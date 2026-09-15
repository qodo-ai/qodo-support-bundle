package viewer

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/bundle"
)

func TestExtractVerifiesAndCleansBundle(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := bundle.New(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.Add(
		"browser/network.jsonl",
		[]byte(`{"request":{"url":"https://example.com"},"response":{"status":200}}`+"\n"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Finalize(bundle.Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC),
		Collection:       map[string]any{"status": "complete"},
	}); err != nil {
		t.Fatal(err)
	}

	extracted, err := Extract(archivePath, defaultTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := extracted.Root
	path, exists := extracted.Resolve("browser/network.jsonl")
	if !exists {
		t.Fatal("browser data was not extracted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected extracted mode: %o", info.Mode().Perm())
	}
	if err := extracted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("temporary directory still exists: %v", err)
	}
}

func TestExtractRejectsTraversalMember(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "traversal.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{
		"../outside": "unsafe",
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("expected traversal error, got %v", err)
	}
}

func TestExtractRejectsChecksumMismatch(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "mismatch.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{
		"data.jsonl":       "{}\n",
		"checksums.sha256": strings.Repeat("0", 64) + "  data.jsonl\n",
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestExtractEnforcesTotalSizeLimit(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "large.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{
		"data.jsonl": "12345",
	})
	limits := defaultTestLimits()
	limits.MaxExtractedBytes = 4

	_, err := Extract(archivePath, limits)

	if err == nil || !strings.Contains(err.Error(), "extracted bytes") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestExtractCountsDirectoryHeadersAgainstMemberLimit(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "directories.tar.gz")
	writeTestArchiveEntries(t, archivePath, []testArchiveEntry{
		{name: "one", typeFlag: tar.TypeDir},
		{name: "two", typeFlag: tar.TypeDir},
		{name: "three", typeFlag: tar.TypeDir},
	})
	limits := defaultTestLimits()
	limits.MaxFiles = 2

	_, err := Extract(archivePath, limits)

	if err == nil || !strings.Contains(err.Error(), "archive members") {
		t.Fatalf("expected archive member limit error, got %v", err)
	}
}

func TestExtractCountsImplicitDirectoriesAgainstNodeLimit(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "implicit-directories.tar.gz")
	writeTestArchiveEntries(t, archivePath, []testArchiveEntry{
		{name: "one/two/data.jsonl", content: "{}\n", typeFlag: tar.TypeReg},
	})
	limits := defaultTestLimits()
	limits.MaxFiles = 2

	_, err := Extract(archivePath, limits)

	if err == nil || !strings.Contains(err.Error(), "filesystem nodes") {
		t.Fatalf("expected filesystem node limit error, got %v", err)
	}
}

func TestExtractRejectsDuplicateDirectoryHeaders(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "duplicate-directories.tar.gz")
	writeTestArchiveEntries(t, archivePath, []testArchiveEntry{
		{name: "duplicate", typeFlag: tar.TypeDir},
		{name: "duplicate", typeFlag: tar.TypeDir},
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "duplicate archive member") {
		t.Fatalf("expected duplicate member error, got %v", err)
	}
}

func TestExtractRejectsExcessivePathDepth(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "deep-path.tar.gz")
	path := strings.Repeat("directory/", maxArchivePathDepth) + "data.jsonl"
	writeTestArchiveEntries(t, archivePath, []testArchiveEntry{
		{name: path, content: "{}\n", typeFlag: tar.TypeReg},
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "components") {
		t.Fatalf("expected path depth error, got %v", err)
	}
}

func TestExtractRejectsExcessivePathLength(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "long-path.tar.gz")
	path := strings.Repeat("a", maxArchivePathBytes+1)
	writeTestArchiveEntries(t, archivePath, []testArchiveEntry{
		{name: path, content: "{}\n", typeFlag: tar.TypeReg},
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("expected path length error, got %v", err)
	}
}

func defaultTestLimits() ExtractionLimits {
	return ExtractionLimits{
		MaxFiles:          100,
		MaxExtractedBytes: 1 << 20,
		MaxFileBytes:      1 << 20,
	}
}

func writeTestArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()
	entries := make([]testArchiveEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, testArchiveEntry{
			name:     name,
			content:  content,
			typeFlag: tar.TypeReg,
		})
	}
	writeTestArchiveEntries(t, path, entries)
}

type testArchiveEntry struct {
	name     string
	content  string
	typeFlag byte
}

func writeTestArchiveEntries(t *testing.T, path string, entries []testArchiveEntry) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o600,
			Size:     int64(len(entry.content)),
			Typeflag: entry.typeFlag,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
