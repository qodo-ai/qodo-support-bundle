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
	schemaVersion = "4"
)

// ErrCleanup reports that temporary staged data could not be removed.
var ErrCleanup = errors.New("clean up temporary bundle data")

// Manifest describes the collector and sanitized sources in a bundle.
type Manifest struct {
	SchemaVersion    string            `json:"schema_version"`
	CollectorVersion string            `json:"collector_version"`
	GeneratedAt      time.Time         `json:"generated_at"`
	Redaction        map[string]string `json:"redaction"`
	CustomerContext  map[string]string `json:"customer_context,omitempty"`
	Collection       map[string]any    `json:"collection"`
	Artifacts        []ManifestFile    `json:"artifacts"`
	Files            int               `json:"files"`
}

// ManifestFile records the integrity metadata for a collected artifact.
type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ProgressStage values are stable presentation hooks and never contain file paths.
type ProgressStage string

const (
	ProgressManifest   ProgressStage = "archive_manifest"
	ProgressChecksums  ProgressStage = "archive_checksums"
	ProgressPacking    ProgressStage = "archive_packing"
	ProgressFinalizing ProgressStage = "archive_finalizing"
	ProgressComplete   ProgressStage = "archive_complete"
)

// Progress reports archive stages without exposing staged paths or contents.
type Progress struct {
	Stage ProgressStage
}

// Builder stages sanitized data and creates a checksummed tar.gz archive.
type Builder struct {
	outputPath           string
	stagingDir           string
	closed               bool
	fileCount            int
	removeAll            func(string) error
	remove               func(string) error
	closeArchive         func(*os.File) error
	publish              func(oldpath, newpath string) error
	temporaryArchivePath string
	retractPublishedPath string
	hideAbsolutePaths    bool
	progress             func(Progress)
}

// HideAbsolutePaths omits filesystem locations from retract and cleanup errors.
func (builder *Builder) HideAbsolutePaths() {
	builder.hideAbsolutePaths = true
}

// Option configures bundle construction.
type Option func(*Builder)

// OmitAbsolutePaths omits filesystem locations from constructor and cleanup errors.
func OmitAbsolutePaths() Option {
	return func(builder *Builder) {
		builder.hideAbsolutePaths = true
	}
}

// WithProgress reports stable archive-finalization stages.
func WithProgress(progress func(Progress)) Option {
	return func(builder *Builder) {
		builder.progress = progress
	}
}

// New creates a bundle staging directory beside the output archive.
func New(outputPath string, options ...Option) (*Builder, error) {
	builder := &Builder{}
	for _, option := range options {
		option(builder)
	}
	if outputPath == "" {
		return nil, errors.New("output path is required")
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return nil, builder.wrapPath("resolve output path", err)
	}
	if _, err := os.Lstat(absoluteOutput); err == nil {
		return nil, builder.existingOutput(absoluteOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, builder.wrapPath("inspect output path", err)
	}

	outputDirectory := filepath.Dir(absoluteOutput)
	if err := os.MkdirAll(outputDirectory, directoryMode); err != nil {
		return nil, builder.wrapPath("create output directory", err)
	}
	stagingDirectory, err := os.MkdirTemp(outputDirectory, ".qodo-support-bundle-*")
	if err != nil {
		return nil, builder.wrapPath("create staging directory", err)
	}
	if err := os.Chmod(stagingDirectory, directoryMode); err != nil {
		_ = os.RemoveAll(stagingDirectory)
		return nil, builder.wrapPath("secure staging directory", err)
	}
	builder.outputPath = absoluteOutput
	builder.stagingDir = stagingDirectory
	builder.removeAll = os.RemoveAll
	builder.remove = os.Remove
	builder.closeArchive = func(file *os.File) error {
		return file.Close()
	}
	builder.publish = os.Link
	return builder, nil
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
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("bundle file %q already exists", cleanPath)
		}
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
	builder.reportProgress(ProgressManifest)
	manifest.SchemaVersion = schemaVersion
	artifacts, err := builder.manifestFiles(ctx)
	if err != nil {
		return "", err
	}
	manifest.Artifacts = artifacts
	manifest.Files = len(manifest.Artifacts) + 2
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if err := builder.Add("manifest.json", manifestData); err != nil {
		return "", err
	}

	builder.reportProgress(ProgressChecksums)
	if err := builder.AddStream("checksums.sha256", func(writer io.Writer) error {
		return builder.writeChecksums(ctx, writer, manifest.Artifacts)
	}); err != nil {
		return "", err
	}

	builder.reportProgress(ProgressPacking)
	if err := builder.createArchive(ctx, manifest.GeneratedAt); err != nil {
		if errors.Is(err, ErrCleanup) {
			return builder.outputPath, err
		}
		return "", err
	}
	builder.reportProgress(ProgressFinalizing)
	if err := builder.removeAll(builder.stagingDir); err != nil {
		return builder.outputPath, ErrCleanup
	}
	builder.closed = true
	builder.reportProgress(ProgressComplete)
	return builder.outputPath, nil
}

func (builder *Builder) reportProgress(stage ProgressStage) {
	if builder.progress != nil {
		builder.progress(Progress{Stage: stage})
	}
}

func (builder *Builder) manifestFiles(ctx context.Context) ([]ManifestFile, error) {
	paths, err := stagedFiles(builder.stagingDir)
	if err != nil {
		return nil, err
	}
	files := make([]ManifestFile, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		localPath := filepath.Join(builder.stagingDir, filepath.FromSlash(path))
		digest, size, err := checksumFile(ctx, localPath)
		if err != nil {
			return nil, fmt.Errorf("hash %q for manifest: %w", path, err)
		}
		files = append(files, ManifestFile{
			Path:   path,
			Size:   size,
			SHA256: digest,
		})
	}
	return files, nil
}

func checksumFile(ctx context.Context, path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(hasher, contextReader{ctx: ctx, reader: file})
	closeErr := file.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// Close removes staged data when collection fails.
func (builder *Builder) Close() error {
	if builder.closed {
		return nil
	}
	cleanupFailed := false
	if builder.retractPublishedPath != "" {
		if err := builder.remove(builder.retractPublishedPath); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			cleanupFailed = true
		} else {
			builder.retractPublishedPath = ""
		}
	}
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

func (builder *Builder) writeChecksums(
	ctx context.Context,
	writer io.Writer,
	artifacts []ManifestFile,
) error {
	for _, artifact := range artifacts {
		if _, err := fmt.Fprintf(
			writer,
			"%s  %s\n",
			artifact.SHA256,
			artifact.Path,
		); err != nil {
			return fmt.Errorf("write checksum for %q: %w", artifact.Path, err)
		}
	}
	manifestDigest, _, err := checksumFile(
		ctx,
		filepath.Join(builder.stagingDir, "manifest.json"),
	)
	if err != nil {
		return fmt.Errorf("checksum manifest.json: %w", err)
	}
	if _, err := fmt.Fprintf(writer, "%s  manifest.json\n", manifestDigest); err != nil {
		return fmt.Errorf("write checksum for manifest.json: %w", err)
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
	builder.temporaryArchivePath = temporaryPath
	if err := temporaryFile.Chmod(fileMode); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("secure archive: %w", err),
		)
	}

	gzipWriter := gzip.NewWriter(temporaryFile)
	gzipWriter.Header.ModTime = generatedAt.UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)

	paths, err := stagedFiles(builder.stagingDir)
	if err != nil {
		return builder.cleanupFailedArchive(temporaryFile, err)
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return builder.cleanupFailedArchive(temporaryFile, err)
		}
		stagedPath := filepath.Join(builder.stagingDir, filepath.FromSlash(path))
		file, err := os.Open(stagedPath)
		if err != nil {
			return builder.cleanupFailedArchive(
				temporaryFile,
				fmt.Errorf("open staged file %q: %w", path, err),
			)
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return builder.cleanupFailedArchive(
				temporaryFile,
				errors.Join(
					fmt.Errorf("inspect staged file %q: %w", path, err),
					wrapCloseError(path, file.Close()),
				),
			)
		}
		if !fileInfo.Mode().IsRegular() {
			return builder.cleanupFailedArchive(
				temporaryFile,
				errors.Join(
					fmt.Errorf("staged file %q is not regular", path),
					wrapCloseError(path, file.Close()),
				),
			)
		}
		header := &tar.Header{
			Name:     path,
			Mode:     fileMode,
			Size:     fileInfo.Size(),
			ModTime:  generatedAt.UTC(),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return builder.cleanupFailedArchive(
				temporaryFile,
				errors.Join(
					fmt.Errorf("write archive header %q: %w", path, err),
					wrapCloseError(path, file.Close()),
				),
			)
		}
		_, copyErr := io.Copy(tarWriter, contextReader{ctx: ctx, reader: file})
		closeErr := file.Close()
		if copyErr != nil {
			return builder.cleanupFailedArchive(
				temporaryFile,
				errors.Join(
					fmt.Errorf("write archive file %q: %w", path, copyErr),
					wrapCloseError(path, closeErr),
				),
			)
		}
		if closeErr != nil {
			return builder.cleanupFailedArchive(
				temporaryFile,
				fmt.Errorf("close staged file %q: %w", path, closeErr),
			)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("close tar stream: %w", err),
		)
	}
	if err := gzipWriter.Close(); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("close gzip stream: %w", err),
		)
	}
	if err := temporaryFile.Sync(); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("sync archive: %w", err),
		)
	}
	if err := builder.closeArchive(temporaryFile); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("close archive: %w", err),
		)
	}
	if err := ctx.Err(); err != nil {
		return builder.cleanupFailedArchive(temporaryFile, err)
	}
	if err := builder.publish(temporaryPath, builder.outputPath); err != nil {
		return builder.cleanupFailedArchive(
			temporaryFile,
			fmt.Errorf("publish archive: %w", err),
		)
	}
	if err := ctx.Err(); err != nil {
		return builder.retractPublishedArchive(err)
	}
	if err := builder.remove(temporaryPath); err != nil {
		if builder.hideAbsolutePaths {
			cause := pathFreeCause(err)
			if cause == "" {
				return fmt.Errorf("%w: remove temporary archive", ErrCleanup)
			}
			return fmt.Errorf("%w: remove temporary archive: %s", ErrCleanup, cause)
		}
		return fmt.Errorf(
			"%w: remove temporary archive %q: %v",
			ErrCleanup,
			temporaryPath,
			err,
		)
	}
	builder.temporaryArchivePath = ""
	return nil
}

func (builder *Builder) cleanupFailedArchive(file *os.File, cause error) error {
	closeErr := builder.closeArchive(file)
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	temporaryPath := builder.temporaryArchivePath
	removeErr := builder.remove(temporaryPath)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		builder.temporaryArchivePath = ""
		removeErr = nil
	}
	return errors.Join(
		cause,
		wrapArchiveCloseError(closeErr),
		wrapArchiveRemoveError(temporaryPath, removeErr, builder.hideAbsolutePaths),
	)
}

func (builder *Builder) retractPublishedArchive(cause error) error {
	outputPath := builder.outputPath
	outputErr := builder.remove(outputPath)
	if outputErr == nil || errors.Is(outputErr, os.ErrNotExist) {
		builder.retractPublishedPath = ""
		outputErr = nil
	} else {
		builder.retractPublishedPath = outputPath
	}
	temporaryPath := builder.temporaryArchivePath
	var temporaryErr error
	if temporaryPath != "" {
		temporaryErr = builder.remove(temporaryPath)
		if temporaryErr == nil || errors.Is(temporaryErr, os.ErrNotExist) {
			builder.temporaryArchivePath = ""
			temporaryErr = nil
		}
	}
	return errors.Join(
		cause,
		wrapPublishedArchiveRemoveError(outputPath, outputErr, builder.hideAbsolutePaths),
		wrapArchiveRemoveError(temporaryPath, temporaryErr, builder.hideAbsolutePaths),
	)
}

func wrapCloseError(path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close staged file %q during cleanup: %w", path, err)
}

func wrapArchiveCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close temporary archive during cleanup: %w", err)
}

func wrapPublishedArchiveRemoveError(path string, err error, hidePath bool) error {
	if err == nil {
		return nil
	}
	if hidePath {
		cause := pathFreeCause(err)
		if cause == "" {
			return errors.New("remove published archive during cleanup")
		}
		return fmt.Errorf("remove published archive during cleanup: %s", cause)
	}
	return fmt.Errorf("remove published archive %q during cleanup: %w", path, err)
}

func wrapArchiveRemoveError(path string, err error, hidePath bool) error {
	if err == nil {
		return nil
	}
	if hidePath {
		cause := pathFreeCause(err)
		if cause == "" {
			return errors.New("remove temporary archive during cleanup")
		}
		return fmt.Errorf("remove temporary archive during cleanup: %s", cause)
	}
	return fmt.Errorf("remove temporary archive %q during cleanup: %w", path, err)
}

func (builder *Builder) wrapPath(operation string, err error) error {
	if err == nil {
		return errors.New(operation)
	}
	if !builder.hideAbsolutePaths {
		return fmt.Errorf("%s: %w", operation, err)
	}
	cause := pathFreeCause(err)
	if cause == "" {
		return errors.New(operation)
	}
	return fmt.Errorf("%s: %s", operation, cause)
}

func (builder *Builder) existingOutput(path string) error {
	if builder.hideAbsolutePaths {
		return errors.New("output already exists")
	}
	return fmt.Errorf("output already exists: %s", path)
}

func pathFreeCause(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		parts := make([]string, 0, 2)
		if pathErr.Op != "" && !strings.ContainsAny(pathErr.Op, `/\`) {
			parts = append(parts, pathErr.Op)
		}
		if pathErr.Err != nil {
			inner := pathErr.Err.Error()
			if inner != "" && !strings.ContainsAny(inner, `/\`) {
				parts = append(parts, inner)
			}
		}
		return strings.Join(parts, ": ")
	}
	message := err.Error()
	if message == "" || strings.ContainsAny(message, `/\`) {
		return ""
	}
	return message
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
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, `\`) {
		return "", fmt.Errorf("invalid bundle path: %q", path)
	}
	cleaned := filepath.Clean(filepath.FromSlash(path))
	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) ||
		filepath.ToSlash(cleaned) != path ||
		strings.Contains(strings.SplitN(path, "/", 2)[0], ":") {
		return "", fmt.Errorf("invalid bundle path: %q", path)
	}
	return cleaned, nil
}
