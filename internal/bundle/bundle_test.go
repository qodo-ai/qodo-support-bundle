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
	if manifest.SchemaVersion != "3" ||
		len(manifest.Artifacts) != 1 ||
		manifest.Artifacts[0].Path != "kubernetes/pods.jsonl" ||
		manifest.Artifacts[0].Size != int64(len("{\"kind\":\"Pod\"}\n")) ||
		len(manifest.Artifacts[0].SHA256) != 64 {
		t.Fatalf("unexpected manifest artifacts: %+v", manifest.Artifacts)
	}
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

func TestAddRejectsArchiveTraversal(t *testing.T) {
	t.Parallel()
	builder, err := New(filepath.Join(t.TempDir(), "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()

	if err := builder.Add("../outside", []byte("data")); err == nil {
		t.Fatal("expected traversal path to be rejected")
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
