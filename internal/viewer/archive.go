package viewer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultMaxFiles          = 10_000
	DefaultMaxArchiveBytes   = int64(4 << 30)
	MaxSupportedArchiveBytes = int64(math.MaxInt64 - 2)
	DefaultMaxExtractedBytes = int64(2 << 30)
	DefaultMaxFileBytes      = int64(512 << 20)
	maxChecksumsBytes        = int64(4 << 20)
	maxManifestBytes         = int64(4 << 20)
	maxArchivePathBytes      = 4 << 10
	maxArchivePathDepth      = 64
	tarOverheadPerMember     = int64(8 << 10)
)

// ExtractionLimits bound archive processing before any local viewer starts.
type ExtractionLimits struct {
	MaxFiles          int
	MaxArchiveBytes   int64
	MaxExtractedBytes int64
	MaxFileBytes      int64
}

// File describes a checksum-consistent regular file from a support bundle.
type File struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ExtractedBundle contains a structurally valid, checksum-consistent bundle.
type ExtractedBundle struct {
	Root      string
	Files     []File
	removeAll func(string) error
}

// Extract validates, bounds, extracts, and checks a bundle for internal consistency.
// Checksums detect corruption but do not authenticate who created the bundle.
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
	if err := checkChecksumConsistency(root, extracted); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	if err := validateManifest(root, extracted); err != nil {
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
	return &ExtractedBundle{Root: root, Files: files, removeAll: os.RemoveAll}, nil
}

// Close removes all temporary viewer data.
func (bundle *ExtractedBundle) Close() error {
	if bundle == nil || bundle.Root == "" {
		return nil
	}
	root := bundle.Root
	removeAll := bundle.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	if err := removeAll(root); err != nil {
		return err
	}
	bundle.Root = ""
	return nil
}

// Resolve returns the checksum-consistent local path for a bundle member.
func (bundle *ExtractedBundle) Resolve(path string) (string, bool) {
	if bundle == nil || bundle.Root == "" {
		return "", false
	}
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
	archiveFile, archiveSize, err := openRegularArchive(bundlePath)
	if err != nil {
		return nil, err
	}
	defer archiveFile.Close()
	if archiveSize > limits.MaxArchiveBytes {
		return nil, fmt.Errorf(
			"bundle archive exceeds %d compressed bytes",
			limits.MaxArchiveBytes,
		)
	}
	compressedArchive := &io.LimitedReader{
		R: archiveFile,
		N: limits.MaxArchiveBytes + 1,
	}
	bufferedArchive := bufio.NewReader(compressedArchive)
	gzipReader, err := gzip.NewReader(bufferedArchive)
	if err != nil {
		return nil, fmt.Errorf("open bundle gzip stream: %w", err)
	}
	defer gzipReader.Close()
	gzipReader.Multistream(false)
	maximumTarBytes, err := maximumTarStreamBytes(limits)
	if err != nil {
		return nil, err
	}
	limitedArchive := &io.LimitedReader{R: gzipReader, N: maximumTarBytes + 1}
	tarReader := tar.NewReader(limitedArchive)

	extracted := make(map[string]extractedFile)
	seenMembers := make(map[string]struct{})
	createdNodes := make(map[string]struct{})
	var totalBytes int64
	memberCount := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if limitedArchive.N <= 0 {
				return nil, fmt.Errorf(
					"bundle archive exceeds %d decompressed bytes",
					maximumTarBytes,
				)
			}
			return nil, fmt.Errorf("read bundle archive: %w", err)
		}
		memberCount++
		if memberCount > limits.MaxFiles {
			return nil, fmt.Errorf(
				"bundle exceeds %d archive members",
				limits.MaxFiles,
			)
		}
		path, err := safeArchivePath(header.Name)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenMembers[path]; duplicate {
			return nil, fmt.Errorf("duplicate archive member: %q", path)
		}
		seenMembers[path] = struct{}{}
		target := filepath.Join(root, filepath.FromSlash(path))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := createArchiveDirectories(
				root,
				path,
				createdNodes,
				limits.MaxFiles,
			); err != nil {
				return nil, err
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("unsupported archive member type for %q", path)
		}
		if path == "checksums.sha256" && header.Size > maxChecksumsBytes {
			return nil, errors.New("checksums.sha256 exceeds 4 MiB")
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
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(path)))
		if parent != "." {
			if err := createArchiveDirectories(
				root,
				parent,
				createdNodes,
				limits.MaxFiles,
			); err != nil {
				return nil, err
			}
		}
		if err := reserveArchiveNode(path, createdNodes, limits.MaxFiles); err != nil {
			return nil, err
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
	if _, err := io.Copy(io.Discard, limitedArchive); err != nil {
		return nil, fmt.Errorf("finish bundle gzip stream: %w", err)
	}
	if limitedArchive.N <= 0 {
		return nil, fmt.Errorf(
			"bundle archive exceeds %d decompressed bytes",
			maximumTarBytes,
		)
	}
	if _, err := bufferedArchive.ReadByte(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("check bundle gzip trailer: %w", err)
		}
		return nil, errors.New("bundle contains data after the gzip stream")
	}
	if compressedArchive.N <= 0 {
		return nil, fmt.Errorf(
			"bundle archive exceeds %d compressed bytes",
			limits.MaxArchiveBytes,
		)
	}
	return extracted, nil
}

func createArchiveDirectories(
	root string,
	path string,
	createdNodes map[string]struct{},
	maximumNodes int,
) error {
	parts := strings.Split(path, "/")
	current := ""
	for _, part := range parts {
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		if _, exists := createdNodes[current]; exists {
			continue
		}
		if err := reserveArchiveNode(current, createdNodes, maximumNodes); err != nil {
			return err
		}
		target := filepath.Join(root, filepath.FromSlash(current))
		if err := os.Mkdir(target, 0o700); err != nil {
			return fmt.Errorf("create viewer directory %q: %w", current, err)
		}
	}
	return nil
}

func reserveArchiveNode(
	path string,
	createdNodes map[string]struct{},
	maximumNodes int,
) error {
	if _, exists := createdNodes[path]; exists {
		return fmt.Errorf("archive member conflicts with existing path: %q", path)
	}
	if len(createdNodes) >= maximumNodes {
		return fmt.Errorf("bundle exceeds %d filesystem nodes", maximumNodes)
	}
	createdNodes[path] = struct{}{}
	return nil
}

func maximumTarStreamBytes(limits ExtractionLimits) (int64, error) {
	if int64(limits.MaxFiles) > (int64(^uint64(0)>>1)-limits.MaxExtractedBytes)/
		tarOverheadPerMember {
		return 0, errors.New("archive limits are too large")
	}
	return limits.MaxExtractedBytes + int64(limits.MaxFiles)*tarOverheadPerMember, nil
}

func checkChecksumConsistency(root string, extracted map[string]extractedFile) error {
	checksumFile, exists := extracted["checksums.sha256"]
	if !exists {
		return errors.New("bundle does not contain checksums.sha256")
	}
	if checksumFile.size > maxChecksumsBytes {
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

func validateManifest(root string, extracted map[string]extractedFile) error {
	manifestFile, exists := extracted["manifest.json"]
	if !exists {
		return errors.New("bundle does not contain manifest.json")
	}
	if manifestFile.size > maxManifestBytes {
		return fmt.Errorf("manifest.json exceeds %d bytes", maxManifestBytes)
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read manifest.json: %w", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest.json: %w", err)
	}
	if manifest == nil {
		return errors.New("manifest.json must contain a JSON object")
	}
	return nil
}

func validateLimits(limits ExtractionLimits) error {
	switch {
	case limits.MaxFiles <= 0:
		return errors.New("maximum file count must be positive")
	case limits.MaxArchiveBytes <= 0:
		return errors.New("maximum archive bytes must be positive")
	case limits.MaxArchiveBytes > MaxSupportedArchiveBytes:
		return errors.New("maximum archive bytes is too large")
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
	if len(path) > maxArchivePathBytes {
		return "", fmt.Errorf(
			"archive path exceeds %d bytes: %q",
			maxArchivePathBytes,
			path,
		)
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
	if depth := len(strings.Split(cleaned, "/")); depth > maxArchivePathDepth {
		return "", fmt.Errorf(
			"archive path exceeds %d components: %q",
			maxArchivePathDepth,
			path,
		)
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
