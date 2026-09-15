package viewer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultMaxFiles          = 10_000
	DefaultMaxExtractedBytes = int64(2 << 30)
	DefaultMaxFileBytes      = int64(512 << 20)
)

// ExtractionLimits bound archive processing before any local viewer starts.
type ExtractionLimits struct {
	MaxFiles          int
	MaxExtractedBytes int64
	MaxFileBytes      int64
}

// File describes a verified regular file from a support bundle.
type File struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ExtractedBundle is a verified bundle in an owner-only temporary directory.
type ExtractedBundle struct {
	Root  string
	Files []File
}

// Extract validates, bounds, extracts, and verifies a support bundle.
func Extract(bundlePath string, limits ExtractionLimits) (*ExtractedBundle, error) {
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "qodo-support-viewer-*")
	if err != nil {
		return nil, fmt.Errorf("create viewer directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("secure viewer directory: %w", err)
	}

	extracted, err := extractArchive(bundlePath, root, limits)
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	if err := verifyChecksums(root, extracted); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	files := make([]File, 0, len(extracted))
	for path, extractedFile := range extracted {
		files = append(files, File{Path: path, Size: extractedFile.size})
	}
	sort.Slice(files, func(left int, right int) bool {
		return files[left].Path < files[right].Path
	})
	return &ExtractedBundle{Root: root, Files: files}, nil
}

// Close removes all temporary viewer data.
func (bundle *ExtractedBundle) Close() error {
	if bundle == nil || bundle.Root == "" {
		return nil
	}
	root := bundle.Root
	bundle.Root = ""
	return os.RemoveAll(root)
}

// Resolve returns the verified local path for a bundle member.
func (bundle *ExtractedBundle) Resolve(path string) (string, bool) {
	cleaned, err := safeArchivePath(path)
	if err != nil {
		return "", false
	}
	for _, file := range bundle.Files {
		if file.Path == cleaned {
			return filepath.Join(bundle.Root, filepath.FromSlash(cleaned)), true
		}
	}
	return "", false
}

type extractedFile struct {
	size   int64
	digest string
}

func extractArchive(
	bundlePath string,
	root string,
	limits ExtractionLimits,
) (map[string]extractedFile, error) {
	archiveFile, err := os.Open(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer archiveFile.Close()
	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return nil, fmt.Errorf("open bundle gzip stream: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	extracted := make(map[string]extractedFile)
	var totalBytes int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle archive: %w", err)
		}
		path, err := safeArchivePath(header.Name)
		if err != nil {
			return nil, err
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return nil, fmt.Errorf("create viewer directory %q: %w", path, err)
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("unsupported archive member type for %q", path)
		}
		if _, exists := extracted[path]; exists {
			return nil, fmt.Errorf("duplicate archive member: %q", path)
		}
		if len(extracted) >= limits.MaxFiles {
			return nil, fmt.Errorf("bundle exceeds %d files", limits.MaxFiles)
		}
		if header.Size < 0 || header.Size > limits.MaxFileBytes {
			return nil, fmt.Errorf(
				"bundle member %q exceeds %d bytes",
				path,
				limits.MaxFileBytes,
			)
		}
		if totalBytes > limits.MaxExtractedBytes-header.Size {
			return nil, fmt.Errorf(
				"bundle exceeds %d extracted bytes",
				limits.MaxExtractedBytes,
			)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, fmt.Errorf("create viewer directory for %q: %w", path, err)
		}
		targetFile, err := os.OpenFile(
			target,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		if err != nil {
			return nil, fmt.Errorf("create viewer file %q: %w", path, err)
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(
			io.MultiWriter(targetFile, hasher),
			io.LimitReader(tarReader, header.Size),
		)
		closeErr := targetFile.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("extract bundle member %q: %w", path, copyErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close bundle member %q: %w", path, closeErr)
		}
		if written != header.Size {
			return nil, fmt.Errorf(
				"bundle member %q declared %d bytes but contained %d",
				path,
				header.Size,
				written,
			)
		}
		totalBytes += written
		extracted[path] = extractedFile{
			size:   written,
			digest: hex.EncodeToString(hasher.Sum(nil)),
		}
	}
	return extracted, nil
}

func verifyChecksums(root string, extracted map[string]extractedFile) error {
	checksumFile, exists := extracted["checksums.sha256"]
	if !exists {
		return errors.New("bundle does not contain checksums.sha256")
	}
	if checksumFile.size > 4<<20 {
		return errors.New("checksums.sha256 exceeds 4 MiB")
	}
	path := filepath.Join(root, "checksums.sha256")
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open checksums.sha256: %w", err)
	}
	defer file.Close()

	expected := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid checksum line: %q", line)
		}
		digest := strings.ToLower(parts[0])
		if len(digest) != sha256.Size*2 {
			return fmt.Errorf("invalid checksum digest for %q", parts[1])
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("invalid checksum digest for %q: %w", parts[1], err)
		}
		memberPath, err := safeArchivePath(parts[1])
		if err != nil {
			return fmt.Errorf("invalid checksum member: %w", err)
		}
		if memberPath == "checksums.sha256" {
			return errors.New("checksums.sha256 must not checksum itself")
		}
		if _, duplicate := expected[memberPath]; duplicate {
			return fmt.Errorf("duplicate checksum for %q", memberPath)
		}
		expected[memberPath] = digest
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read checksums.sha256: %w", err)
	}

	for memberPath, extractedFile := range extracted {
		if memberPath == "checksums.sha256" {
			continue
		}
		expectedDigest, exists := expected[memberPath]
		if !exists {
			return fmt.Errorf("missing checksum for %q", memberPath)
		}
		if extractedFile.digest != expectedDigest {
			return fmt.Errorf("checksum mismatch for %q", memberPath)
		}
	}
	for memberPath := range expected {
		if _, exists := extracted[memberPath]; !exists {
			return fmt.Errorf("checksum references missing member %q", memberPath)
		}
	}
	return nil
}

func validateLimits(limits ExtractionLimits) error {
	switch {
	case limits.MaxFiles <= 0:
		return errors.New("maximum file count must be positive")
	case limits.MaxExtractedBytes <= 0:
		return errors.New("maximum extracted bytes must be positive")
	case limits.MaxFileBytes <= 0:
		return errors.New("maximum file bytes must be positive")
	default:
		return nil
	}
}

func safeArchivePath(path string) (string, error) {
	if path == "" || strings.Contains(path, "\\") || strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("unsafe archive path: %q", path)
	}
	if strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("unsafe archive path: %q", path)
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("unsafe archive path: %q", path)
	}
	if volume := filepath.VolumeName(filepath.FromSlash(path)); volume != "" {
		return "", fmt.Errorf("unsafe archive path: %q", path)
	}
	return cleaned, nil
}

func parsePositiveInt(value string, fallback int, maximum int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if parsed > maximum {
		return maximum
	}
	return parsed
}
