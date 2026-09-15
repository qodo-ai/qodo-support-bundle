package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	directoryMode = 0o700
	fileMode      = 0o600
)

// Manifest describes the collector and sanitized sources in a bundle.
type Manifest struct {
	SchemaVersion    string         `json:"schema_version"`
	CollectorVersion string         `json:"collector_version"`
	GeneratedAt      time.Time      `json:"generated_at"`
	Collection       map[string]any `json:"collection"`
	Files            int            `json:"files"`
}

// Builder stages sanitized data and creates a checksummed tar.gz archive.
type Builder struct {
	outputPath string
	stagingDir string
	closed     bool
	fileCount  int
}

// New creates a bundle staging directory beside the output archive.
func New(outputPath string) (*Builder, error) {
	if outputPath == "" {
		return nil, errors.New("output path is required")
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}
	if _, err := os.Lstat(absoluteOutput); err == nil {
		return nil, fmt.Errorf("output already exists: %s", absoluteOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect output path: %w", err)
	}

	outputDirectory := filepath.Dir(absoluteOutput)
	if err := os.MkdirAll(outputDirectory, directoryMode); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	stagingDirectory, err := os.MkdirTemp(outputDirectory, ".qodo-support-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	if err := os.Chmod(stagingDirectory, directoryMode); err != nil {
		_ = os.RemoveAll(stagingDirectory)
		return nil, fmt.Errorf("secure staging directory: %w", err)
	}
	return &Builder{
		outputPath: absoluteOutput,
		stagingDir: stagingDirectory,
	}, nil
}

// Add writes one sanitized file into the staged bundle.
func (builder *Builder) Add(path string, data []byte) error {
	if builder.closed {
		return errors.New("bundle is closed")
	}
	cleanPath, err := safeRelativePath(path)
	if err != nil {
		return err
	}
	target := filepath.Join(builder.stagingDir, cleanPath)
	if err := os.MkdirAll(filepath.Dir(target), directoryMode); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	if err := os.WriteFile(target, data, fileMode); err != nil {
		return fmt.Errorf("write bundle file %q: %w", cleanPath, err)
	}
	builder.fileCount++
	return nil
}

// Finalize writes the manifest, checksums, and output archive.
func (builder *Builder) Finalize(manifest Manifest) (string, error) {
	if builder.closed {
		return "", errors.New("bundle is closed")
	}
	manifest.SchemaVersion = "1"
	manifest.Files = builder.fileCount + 2
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if err := builder.Add("manifest.json", manifestData); err != nil {
		return "", err
	}

	checksums, err := builder.createChecksums()
	if err != nil {
		return "", err
	}
	if err := builder.Add("checksums.sha256", checksums); err != nil {
		return "", err
	}

	if err := builder.createArchive(manifest.GeneratedAt); err != nil {
		return "", err
	}
	builder.closed = true
	if err := os.RemoveAll(builder.stagingDir); err != nil {
		return "", fmt.Errorf("remove staging directory: %w", err)
	}
	return builder.outputPath, nil
}

// Close removes staged data when collection fails.
func (builder *Builder) Close() error {
	if builder.closed {
		return nil
	}
	builder.closed = true
	return os.RemoveAll(builder.stagingDir)
}

func (builder *Builder) createChecksums() ([]byte, error) {
	paths, err := stagedFiles(builder.stagingDir)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	for _, path := range paths {
		if path == "checksums.sha256" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(builder.stagingDir, filepath.FromSlash(path)))
		if err != nil {
			return nil, fmt.Errorf("read %q for checksum: %w", path, err)
		}
		sum := sha256.Sum256(data)
		output.WriteString(hex.EncodeToString(sum[:]))
		output.WriteString("  ")
		output.WriteString(path)
		output.WriteByte('\n')
	}
	return []byte(output.String()), nil
}

func (builder *Builder) createArchive(generatedAt time.Time) error {
	outputDirectory := filepath.Dir(builder.outputPath)
	temporaryFile, err := os.CreateTemp(outputDirectory, ".qodo-support-bundle-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	cleanup := func() {
		_ = temporaryFile.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporaryFile.Chmod(fileMode); err != nil {
		cleanup()
		return fmt.Errorf("secure archive: %w", err)
	}

	gzipWriter := gzip.NewWriter(temporaryFile)
	gzipWriter.Header.ModTime = generatedAt.UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)

	paths, err := stagedFiles(builder.stagingDir)
	if err != nil {
		cleanup()
		return err
	}
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(builder.stagingDir, filepath.FromSlash(path)))
		if err != nil {
			cleanup()
			return fmt.Errorf("read staged file %q: %w", path, err)
		}
		header := &tar.Header{
			Name:     path,
			Mode:     fileMode,
			Size:     int64(len(data)),
			ModTime:  generatedAt.UTC(),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			cleanup()
			return fmt.Errorf("write archive header %q: %w", path, err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			cleanup()
			return fmt.Errorf("write archive file %q: %w", path, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tar stream: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close gzip stream: %w", err)
	}
	if err := temporaryFile.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync archive: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close archive: %w", err)
	}
	if err := os.Rename(temporaryPath, builder.outputPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish archive: %w", err)
	}
	return nil
}

func stagedFiles(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains unsupported symlink: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list staged files: %w", err)
	}
	sort.Strings(paths)
	return paths, nil
}

func safeRelativePath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) {
		return "", fmt.Errorf("invalid bundle path: %q", path)
	}
	cleaned := filepath.Clean(filepath.FromSlash(path))
	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid bundle path: %q", path)
	}
	return cleaned, nil
}
