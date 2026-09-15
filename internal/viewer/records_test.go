package viewer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRecordsFiltersBrowserErrorsAndAuthentication(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `
{"@timestamp":"2026-09-15T07:00:00Z","request":{"method":"GET","url":"https://example.com/health"},"response":{"status":200},"source":{"type":"browser_har"}}
{"@timestamp":"2026-09-15T07:00:01Z","request":{"method":"GET","url":"https://example.com/auth/v1/oidc/userinfo"},"response":{"status":403},"source":{"type":"browser_har"}}
`,
	})

	errorsResponse, err := readRecords(
		bundle,
		"browser/network.jsonl",
		"",
		"errors",
		0,
		100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(errorsResponse.Records) != 1 {
		t.Fatalf("unexpected error records: %+v", errorsResponse.Records)
	}
	if errorsResponse.Records[0].Severity != "warning" {
		t.Fatalf("unexpected severity: %+v", errorsResponse.Records[0])
	}

	authResponse, err := readRecords(
		bundle,
		"browser/network.jsonl",
		"",
		"auth",
		0,
		100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(authResponse.Records) != 1 {
		t.Fatalf("unexpected auth records: %+v", authResponse.Records)
	}
}

func TestReadRecordsNormalizesTimestampedStructuredLog(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/platform/main.log": `
2026-09-15T07:00:00Z {"severity":"ERROR","message":"Token exchange failed","request_id":"req-1"}
`,
	})

	response, err := readRecords(
		bundle,
		"kubernetes/logs/platform/main.log",
		"req-1",
		"errors",
		0,
		100,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(response.Records) != 1 {
		t.Fatalf("unexpected records: %+v", response.Records)
	}
	record := response.Records[0]
	if record.Timestamp != "2026-09-15T07:00:00Z" ||
		record.Severity != "error" ||
		record.Summary != "Token exchange failed" {
		t.Fatalf("unexpected normalized record: %+v", record)
	}
}

func TestReadRecordsPaginatesMatches(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"kubernetes/logs/platform/main.log": "one\ntwo\nthree\n",
	})

	first, err := readRecords(
		bundle,
		"kubernetes/logs/platform/main.log",
		"",
		"all",
		0,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 2 || !first.HasMore || first.NextOffset != 2 {
		t.Fatalf("unexpected first page: %+v", first)
	}

	second, err := readRecords(
		bundle,
		"kubernetes/logs/platform/main.log",
		"",
		"all",
		first.NextOffset,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Records) != 1 || second.HasMore {
		t.Fatalf("unexpected second page: %+v", second)
	}
}

func testExtractedBundle(t *testing.T, files map[string]string) *ExtractedBundle {
	t.Helper()
	root := t.TempDir()
	bundle := &ExtractedBundle{Root: root}
	for path, content := range files {
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		bundle.Files = append(bundle.Files, File{Path: path, Size: int64(len(content))})
	}
	return bundle
}
