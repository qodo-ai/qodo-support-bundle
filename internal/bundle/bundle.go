package bundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// ErrCleanup reports that temporary staged data could not be removed.
var ErrCleanup = errors.New("clean up temporary bundle data")

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
	outputPath           string
	stagingDir           string
	closed               bool
	fileCount            int
	removeAll            func(string) error
	remove               func(string) error
	temporaryArchivePath string
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
		removeAll:  os.RemoveAll,
		remove:     os.Remove,
	}, nil
}

// Add writes one sanitized file into the staged bundle.
func (builder *Builder) Add(path string, data []byte) error {
	return builder.AddStream(path, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
}

// AddStream writes one sanitized stream into the staged bundle.
func (builder *Builder) AddStream(path string, write func(io.Writer) error) error {
	if builder.closed {
		return errors.New("bundle is closed")
	}
	if write == nil {
		return errors.New("bundle stream writer is required")
	}
	cleanPath, err := safeRelativePath(path)
	if err != nil {
		return err
	}
	target := filepath.Join(builder.stagingDir, cleanPath)
	if err := os.MkdirAll(filepath.Dir(target), directoryMode); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("create bundle file %q: %w", cleanPath, err)
	}
	if err := write(file); err != nil {
		_ = file.Close()
		_ = os.Remove(target)
		return fmt.Errorf("write bundle file %q: %w", cleanPath, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(target)
		return fmt.Errorf("close bundle file %q: %w", cleanPath, err)
	}
	builder.fileCount++
	return nil
}

// Finalize writes the manifest, checksums, and output archive.
func (builder *Builder) Finalize(manifest Manifest) (string, error) {
	return builder.FinalizeContext(context.Background(), manifest)
}

// FinalizeContext writes the bundle while honoring cancellation.
func (builder *Builder) FinalizeContext(
	ctx context.Context,
	manifest Manifest,
) (string, error) {
	if builder.closed {
		return "", errors.New("bundle is closed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
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

	if err := builder.AddStream("checksums.sha256", func(writer io.Writer) error {
		return builder.writeChecksums(ctx, writer)
	}); err != nil {
		return "", err
	}

	if err := builder.createArchive(ctx, manifest.GeneratedAt); err != nil {
		if errors.Is(err, ErrCleanup) {
			return builder.outputPath, err
		}
		return "", err
	}
	if err := builder.removeAll(builder.stagingDir); err != nil {
		return builder.outputPath, ErrCleanup
	}
	builder.closed = true
	return builder.outputPath, nil
}

// Close removes staged data when collection fails.
func (builder *Builder) Close() error {
	if builder.closed {
		return nil
	}
	cleanupFailed := false
	if builder.temporaryArchivePath != "" {
		if err := builder.remove(builder.temporaryArchivePath); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			cleanupFailed = true
		} else {
			builder.temporaryArchivePath = ""
		}
	}
	if err := builder.removeAll(builder.stagingDir); err != nil {
		cleanupFailed = true
	}
	if cleanupFailed {
		return ErrCleanup
	}
	builder.closed = true
	return nil
}

func (builder *Builder) writeChecksums(ctx context.Context, writer io.Writer) error {
	paths, err := stagedFiles(builder.stagingDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if path == "checksums.sha256" {
			continue
		}
		file, err := os.Open(filepath.Join(builder.stagingDir, filepath.FromSlash(path)))
		if err != nil {
			return fmt.Errorf("open %q for checksum: %w", path, err)
		}
		hasher := sha256.New()
		_, copyErr := io.Copy(hasher, contextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("read %q for checksum: %w", path, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %q after checksum: %w", path, closeErr)
		}
		if _, err := fmt.Fprintf(
			writer,
			"%s  %s\n",
			hex.EncodeToString(hasher.Sum(nil)),
			path,
		); err != nil {
			return fmt.Errorf("write checksum for %q: %w", path, err)
		}
	}
	return nil
}

func (builder *Builder) createArchive(ctx context.Context, generatedAt time.Time) error {
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
		if err := ctx.Err(); err != nil {
			cleanup()
			return err
		}
		stagedPath := filepath.Join(builder.stagingDir, filepath.FromSlash(path))
		file, err := os.Open(stagedPath)
		if err != nil {
			cleanup()
			return fmt.Errorf("open staged file %q: %w", path, err)
		}
		fileInfo, err := file.Stat()
		if err != nil {
			_ = file.Close()
			cleanup()
			return fmt.Errorf("inspect staged file %q: %w", path, err)
		}
		if !fileInfo.Mode().IsRegular() {
			_ = file.Close()
			cleanup()
			return fmt.Errorf("staged file %q is not regular", path)
		}
		header := &tar.Header{
			Name:     path,
			Mode:     fileMode,
			Size:     fileInfo.Size(),
			ModTime:  generatedAt.UTC(),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = file.Close()
			cleanup()
			return fmt.Errorf("write archive header %q: %w", path, err)
		}
		_, copyErr := io.Copy(tarWriter, contextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil {
			cleanup()
			return fmt.Errorf("write archive file %q: %w", path, copyErr)
		}
		if closeErr != nil {
			cleanup()
			return fmt.Errorf("close staged file %q: %w", path, closeErr)
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
	if err := ctx.Err(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Link(temporaryPath, builder.outputPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish archive: %w", err)
	}
	builder.temporaryArchivePath = temporaryPath
	if err := builder.remove(temporaryPath); err != nil {
		return fmt.Errorf("%w: remove temporary archive: %v", ErrCleanup, err)
	}
	builder.temporaryArchivePath = ""
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
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
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("bundle contains unsupported non-regular file: %s", path)
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
