package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	if err := builder.Add("browser/network.jsonl", []byte("{\"status\":200}\n")); err != nil {
		t.Fatal(err)
	}

	result, err := builder.Finalize(Manifest{
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
		"browser/network.jsonl",
		"manifest.json",
		"checksums.sha256",
	} {
		if _, exists := files[path]; !exists {
			t.Fatalf("archive does not contain %q", path)
		}
	}
	checksums := string(files["checksums.sha256"])
	if !strings.Contains(checksums, "  browser/network.jsonl\n") ||
		!strings.Contains(checksums, "  manifest.json\n") {
		t.Fatalf("unexpected checksums:\n%s", checksums)
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
		path, err := builder.Finalize(Manifest{
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

	archivePath, err := builder.Finalize(Manifest{
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
	if _, err := first.Finalize(manifest); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := second.Finalize(manifest); err == nil {
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

	archivePath, err := builder.Finalize(Manifest{
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
