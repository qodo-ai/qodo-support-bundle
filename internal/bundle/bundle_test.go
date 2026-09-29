package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFinalizeCreatesRestrictedChecksummedArchive(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.Add("kubernetes/pods.jsonl", []byte("{\"kind\":\"Pod\"}\n")); err != nil {
		t.Fatal(err)
	}

	result, err := builder.FinalizeContext(context.Background(), Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC),
		Collection:       map[string]any{"status": "complete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != outputPath {
		t.Fatalf("unexpected output path: %s", result)
	}
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != fileMode {
		t.Fatalf("archive mode is %o, expected %o", fileInfo.Mode().Perm(), fileMode)
	}

	files := readArchive(t, outputPath)
	for _, path := range []string{
		"kubernetes/pods.jsonl",
		"manifest.json",
		"checksums.sha256",
	} {
		if _, exists := files[path]; !exists {
			t.Fatalf("archive does not contain %q", path)
		}
	}
	checksums := string(files["checksums.sha256"])
	if !strings.Contains(checksums, "  kubernetes/pods.jsonl\n") ||
		!strings.Contains(checksums, "  manifest.json\n") {
		t.Fatalf("unexpected checksums:\n%s", checksums)
	}
	var manifest Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != schemaVersion ||
		len(manifest.Artifacts) != 1 ||
		manifest.Artifacts[0].Path != "kubernetes/pods.jsonl" ||
		manifest.Artifacts[0].Size != int64(len("{\"kind\":\"Pod\"}\n")) ||
		len(manifest.Artifacts[0].SHA256) != 64 {
		t.Fatalf("unexpected manifest artifacts: %+v", manifest.Artifacts)
	}
}

func TestAddRejectsDuplicateArtifactPathWithoutOverwriting(t *testing.T) {
	t.Parallel()
	builder, err := New(filepath.Join(t.TempDir(), "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	if err := builder.Add("kubernetes/workloads.jsonl", []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	err = builder.Add("kubernetes/workloads.jsonl", []byte("second\n"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate Add returned %v", err)
	}
	staged, readErr := os.ReadFile(
		filepath.Join(builder.stagingDir, "kubernetes", "workloads.jsonl"),
	)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(staged) != "first\n" || builder.fileCount != 1 {
		t.Fatalf("duplicate path overwrote staged data: data=%q files=%d", staged, builder.fileCount)
	}
}

func TestFinalizeContextRetractsArchiveCanceledAfterPublish(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builder.publish = func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		cancel()
		return nil
	}

	_, err = builder.FinalizeContext(ctx, Manifest{GeneratedAt: time.Now()})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation after publish, got %v", err)
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled finalization left published archive: %v", statErr)
	}
}

func TestFinalizeContextRetainsCleanupWhenPublishedArchiveRemovalFails(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builder.publish = func(oldpath, newpath string) error {
		linkErr := os.Link(oldpath, newpath)
		cancel()
		return linkErr
	}
	builder.remove = func(path string) error {
		if path == outputPath {
			return errors.New("injected published archive cleanup failure")
		}
		return os.Remove(path)
	}

	archivePath, err := builder.FinalizeContext(ctx, Manifest{GeneratedAt: time.Now()})

	if archivePath != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected finalize result: path=%q err=%v", archivePath, err)
	}
	if _, statErr := os.Stat(outputPath); statErr != nil {
		t.Fatalf("published archive should remain when retract fails: %v", statErr)
	}
	if builder.retractPublishedPath == "" {
		t.Fatal("retryable published-archive cleanup state was not retained")
	}
	builder.remove = os.Remove
	if err := builder.Close(); err != nil {
		t.Fatalf("retry cleanup failed: %v", err)
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("retry did not remove published archive: %v", statErr)
	}
}

func TestNewOmittingAbsolutePathsHidesExistingOutput(t *testing.T) {
	t.Parallel()
	const username = "review-new-canary"
	outputPath := filepath.Join(t.TempDir(), "Users", username, "qodo-support-bundles", "bundle.tar.gz")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("exists"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := New(outputPath, OmitAbsolutePaths())
	if err == nil {
		t.Fatal("expected existing output error")
	}
	logged := err.Error()
	if strings.Contains(logged, username) || strings.Contains(logged, outputPath) {
		t.Fatalf("constructor leaked default output path: %s", logged)
	}
	if !strings.Contains(logged, "output already exists") {
		t.Fatalf("missing constructor operation: %s", logged)
	}

	_, explicitErr := New(outputPath)
	if explicitErr == nil || !strings.Contains(explicitErr.Error(), outputPath) {
		t.Fatalf("explicit constructor should retain path: %v", explicitErr)
	}
}

func TestRetractDefaultArchiveErrorsOmitAbsolutePath(t *testing.T) {
	t.Parallel()
	const username = "review-retract-canary"
	outputPath := filepath.Join(t.TempDir(), "Users", username, "qodo-support-bundles", "bundle.tar.gz")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		t.Fatal(err)
	}
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	builder.HideAbsolutePaths()
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builder.publish = func(oldpath, newpath string) error {
		linkErr := os.Link(oldpath, newpath)
		cancel()
		return linkErr
	}
	builder.remove = func(path string) error {
		if path == outputPath {
			return &os.PathError{Op: "remove", Path: path, Err: errors.New("permission denied")}
		}
		return os.Remove(path)
	}

	_, err = builder.FinalizeContext(ctx, Manifest{GeneratedAt: time.Now()})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	logged := err.Error()
	if strings.Contains(logged, username) || strings.Contains(logged, outputPath) {
		t.Fatalf("default retract error leaked output path: %s", logged)
	}
	if !strings.Contains(logged, "remove published archive") ||
		!strings.Contains(logged, "remove") ||
		!strings.Contains(logged, "permission denied") {
		t.Fatalf("missing path-free retract cause: %s", logged)
	}
	builder.remove = os.Remove
	_ = builder.Close()
}

func TestFinalizeContextDoesNotPublishAfterCancellation(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = builder.FinalizeContext(ctx, Manifest{GeneratedAt: time.Now()})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled finalization published output: %v", statErr)
	}
}

func TestFinalizeReportsAndRetriesTemporaryArchiveCleanup(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	builder.remove = func(string) error {
		return errors.New("injected temporary archive cleanup failure")
	}

	archivePath, err := builder.FinalizeContext(
		context.Background(),
		Manifest{GeneratedAt: time.Now()},
	)

	if !errors.Is(err, ErrCleanup) || archivePath != outputPath {
		t.Fatalf("unexpected finalize result: path=%q err=%v", archivePath, err)
	}
	if builder.temporaryArchivePath == "" {
		t.Fatal("temporary archive path was not retained for retry")
	}
	builder.remove = os.Remove
	if err := builder.Close(); err != nil {
		t.Fatalf("retry cleanup failed: %v", err)
	}
}

func TestCreateArchiveFailureReportsCleanupErrorsAndRetainsPath(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Add("data.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("injected archive close failure")
	removeFailure := errors.New("injected archive remove failure")
	builder.closeArchive = func(file *os.File) error {
		_ = file.Close()
		return closeFailure
	}
	builder.remove = func(string) error {
		return removeFailure
	}

	archivePath, err := builder.FinalizeContext(
		context.Background(),
		Manifest{GeneratedAt: time.Now()},
	)

	if archivePath != "" ||
		!errors.Is(err, closeFailure) ||
		!errors.Is(err, removeFailure) ||
		errors.Is(err, ErrCleanup) {
		t.Fatalf("unexpected finalize result: path=%q err=%v", archivePath, err)
	}
	if builder.temporaryArchivePath == "" ||
		!strings.Contains(err.Error(), builder.temporaryArchivePath) {
		t.Fatalf("temporary archive path was not retained and reported: %v", err)
	}
	builder.closeArchive = func(file *os.File) error { return file.Close() }
	builder.remove = os.Remove
	if err := builder.Close(); err != nil {
		t.Fatalf("retry cleanup failed: %v", err)
	}
}

func TestAddRejectsUnsafeAndAliasedArchivePaths(t *testing.T) {
	t.Parallel()
	builder, err := New(filepath.Join(t.TempDir(), "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	for _, path := range []string{
		"../outside",
		`..\outside`,
		"kubernetes/../outside",
		"kubernetes//workloads.jsonl",
		"C:/outside",
		"/absolute",
	} {
		if err := builder.Add(path, []byte("data")); err == nil {
			t.Errorf("expected unsafe path %q to be rejected", path)
		}
	}
}

func TestArchiveOutputIsDeterministic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	generatedAt := time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC)
	build := func(name string) []byte {
		builder, err := New(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		defer builder.Close()
		if err := builder.Add("z.jsonl", []byte("z\n")); err != nil {
			t.Fatal(err)
		}
		if err := builder.Add("a.jsonl", []byte("a\n")); err != nil {
			t.Fatal(err)
		}
		path, err := builder.FinalizeContext(context.Background(), Manifest{
			CollectorVersion: "test",
			GeneratedAt:      generatedAt,
			Collection:       map[string]any{"status": "complete"},
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	first := build("first.tar.gz")
	second := build("second.tar.gz")

	if !bytes.Equal(first, second) {
		t.Fatal("archives with identical content and timestamps differ")
	}
}

func TestAddStreamWritesIncrementallyAndRemovesFailedFile(t *testing.T) {
	t.Parallel()
	builder, err := New(filepath.Join(t.TempDir(), "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	if err := builder.AddStream("streamed.jsonl", func(writer io.Writer) error {
		if _, err := writer.Write([]byte("first\n")); err != nil {
			return err
		}
		_, err := writer.Write([]byte("second\n"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectedError := errors.New("stream failed")
	if err := builder.AddStream("failed.jsonl", func(writer io.Writer) error {
		if _, err := writer.Write([]byte("partial\n")); err != nil {
			return err
		}
		return expectedError
	}); !errors.Is(err, expectedError) {
		t.Fatalf("expected stream error, got %v", err)
	}

	archivePath, err := builder.FinalizeContext(context.Background(), Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	files := readArchive(t, archivePath)
	if string(files["streamed.jsonl"]) != "first\nsecond\n" {
		t.Fatalf("unexpected streamed content: %q", files["streamed.jsonl"])
	}
	if _, exists := files["failed.jsonl"]; exists {
		t.Fatal("archive contains partial failed stream")
	}
}

func TestFinalizeDoesNotOverwriteConcurrentOutput(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	first, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Add("source.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := second.Add("source.txt", []byte("second")); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC),
	}
	if _, err := first.FinalizeContext(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := second.FinalizeContext(context.Background(), manifest); err == nil {
		t.Fatal("expected concurrent output publication to fail")
	}
	current, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) {
		t.Fatal("existing output was overwritten")
	}
}

func TestFinalizeCleanupFailureCanBeRetriedByClose(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := New(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	originalRemoveAll := builder.removeAll
	removeAttempts := 0
	builder.removeAll = func(path string) error {
		removeAttempts++
		if removeAttempts == 1 {
			return errors.New("injected cleanup failure")
		}
		return originalRemoveAll(path)
	}

	archivePath, err := builder.FinalizeContext(context.Background(), Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("expected cleanup error, got %v", err)
	}
	if archivePath != outputPath {
		t.Fatalf("unexpected published archive path: %q", archivePath)
	}
	if builder.closed {
		t.Fatal("builder was closed before staging cleanup succeeded")
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("published archive is unavailable: %v", err)
	}

	if err := builder.Close(); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	if !builder.closed {
		t.Fatal("builder is not closed after successful cleanup retry")
	}
	if removeAttempts != 2 {
		t.Fatalf("unexpected cleanup attempts: %d", removeAttempts)
	}
	if _, err := os.Stat(builder.stagingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory still exists: %v", err)
	}
}

func readArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = data
		if header.Mode != fileMode {
			t.Fatalf("%s mode is %o, expected %o", header.Name, header.Mode, fileMode)
		}
	}
	return files
}
