package viewer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	if _, err := builder.FinalizeContext(context.Background(), bundle.Manifest{
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
	if path, exists := extracted.Resolve("browser/network.jsonl"); exists || path != "" {
		t.Fatalf("closed bundle resolved a path: %q", path)
	}
}

func TestExtractRejectsMissingManifest(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "missing-manifest.tar.gz")
	writeConsistentTestArchive(t, archivePath, map[string]string{
		"browser/network.jsonl": "{}\n",
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "does not contain manifest.json") {
		t.Fatalf("expected missing manifest error, got %v", err)
	}
}

func TestExtractedBundleCloseRetriesCleanupFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	attempts := 0
	extracted := &ExtractedBundle{
		Root: root,
		removeAll: func(path string) error {
			attempts++
			if attempts == 1 {
				return errors.New("injected cleanup failure")
			}
			return os.RemoveAll(path)
		},
	}

	if err := extracted.Close(); err == nil {
		t.Fatal("expected initial cleanup failure")
	}
	if extracted.Root != root {
		t.Fatal("cleanup failure discarded the retry path")
	}
	if err := extracted.Close(); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if extracted.Root != "" {
		t.Fatal("successful cleanup retained the root path")
	}
}

func TestExtractRejectsInvalidManifest(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "invalid-manifest.tar.gz")
	writeConsistentTestArchive(t, archivePath, map[string]string{
		"manifest.json": "not-json",
	})

	_, err := Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "parse manifest.json") {
		t.Fatalf("expected invalid manifest error, got %v", err)
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

func TestExtractEnforcesCompressedArchiveLimit(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "compressed-limit.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{"data.jsonl": "{}\n"})
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultTestLimits()
	limits.MaxArchiveBytes = info.Size() - 1

	_, err = Extract(archivePath, limits)

	if err == nil || !strings.Contains(err.Error(), "compressed bytes") {
		t.Fatalf("expected compressed archive limit error, got %v", err)
	}
}

func TestExtractRejectsOversizedChecksumBeforeWritingIt(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "large-checksums.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{
		"checksums.sha256": strings.Repeat("x", int(maxChecksumsBytes)+1),
	})
	root := t.TempDir()
	limits := defaultTestLimits()
	limits.MaxArchiveBytes = 8 << 20
	limits.MaxExtractedBytes = 8 << 20
	limits.MaxFileBytes = 8 << 20

	_, err := extractArchive(archivePath, root, limits)

	if err == nil || !strings.Contains(err.Error(), "checksums.sha256 exceeds 4 MiB") {
		t.Fatalf("expected checksum size error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "checksums.sha256")); !os.IsNotExist(statErr) {
		t.Fatalf("oversized checksum file was created: %v", statErr)
	}
}

func TestExtractRejectsCorruptGzipTrailer(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "corrupt-trailer.tar.gz")
	writeTestArchive(t, archivePath, map[string]string{"data.jsonl": "{}\n"})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Extract(archivePath, defaultTestLimits())

	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("expected corrupt gzip trailer error, got %v", err)
	}
}

func TestExtractRejectsDataAfterGzipStream(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		append func(*testing.T, string)
	}{
		{
			name: "raw data",
			append: func(t *testing.T, path string) {
				t.Helper()
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("appended"); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "gzip member",
			append: func(t *testing.T, path string) {
				t.Helper()
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				writer := gzip.NewWriter(file)
				if _, err := writer.Write([]byte("appended")); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			archivePath := filepath.Join(t.TempDir(), "appended.tar.gz")
			writeTestArchive(t, archivePath, map[string]string{"data.jsonl": "{}\n"})
			testCase.append(t, archivePath)

			_, err := Extract(archivePath, defaultTestLimits())

			if err == nil || !strings.Contains(err.Error(), "after the gzip stream") {
				t.Fatalf("expected appended data error, got %v", err)
			}
		})
	}
}

func defaultTestLimits() ExtractionLimits {
	return ExtractionLimits{
		MaxFiles:          100,
		MaxArchiveBytes:   2 << 20,
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

func writeConsistentTestArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()
	checksums := strings.Builder{}
	for name, content := range files {
		digest := sha256.Sum256([]byte(content))
		_, _ = fmt.Fprintf(&checksums, "%x  %s\n", digest, name)
	}
	files["checksums.sha256"] = checksums.String()
	writeTestArchive(t, path, files)
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
