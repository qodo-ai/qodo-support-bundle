package har

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

func TestImportSanitizesHARAndOmitsBodies(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	input := `{
	  "log": {
	    "version": "1.2",
	    "entries": [{
	      "startedDateTime": "2026-09-15T06:00:00Z",
	      "time": 42,
	      "request": {
	        "method": "GET",
	        "url": "https://example.com/callback?code=oauth-code&request_id=req-1",
	        "httpVersion": "HTTP/2",
	        "headers": [
	          {"name": "Authorization", "value": "Bearer raw-token"},
	          {"name": "Accept", "value": "application/json"}
	        ],
	        "queryString": [
	          {"name": "code", "value": "oauth-code"},
	          {"name": "request_id", "value": "req-1"}
	        ],
	        "postData": {"text": "password=body-password"},
	        "bodySize": 12
	      },
	      "response": {
	        "status": 200,
	        "statusText": "OK",
	        "httpVersion": "HTTP/2",
	        "headers": [{"name": "Set-Cookie", "value": "session=raw-cookie"}],
	        "content": {
	          "size": 100,
	          "mimeType": "application/json",
	          "text": "{\"email\":\"user@example.com\"}"
	        },
	        "bodySize": 100
	      },
	      "timings": {"wait": 40, "receive": 2}
	    }]
	  }
	}`
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	stats, err := Import(harPath, &output, 1<<20, 100, redact.New())
	if err != nil {
		t.Fatal(err)
	}

	if stats.EntriesWritten != 1 || stats.Truncated {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	result := output.String()
	for _, forbidden := range []string{
		"raw-token",
		"raw-cookie",
		"oauth-code",
		"body-password",
		"user@example.com",
	} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("output contains sensitive value %q: %s", forbidden, result)
		}
	}
	for _, expected := range []string{
		`"authorization":"[REDACTED]"`,
		`"set-cookie":"[REDACTED]"`,
		`"request_id":"req-1"`,
		`"status":200`,
	} {
		if !strings.Contains(result, expected) {
			t.Fatalf("output does not contain %q: %s", expected, result)
		}
	}
}

func TestImportEnforcesInputLimit(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	if err := os.WriteFile(harPath, []byte(`{"log":{"entries":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Import(harPath, &bytes.Buffer{}, 4, 100, redact.New())

	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("expected input limit error, got %v", err)
	}
}

func TestImportCapsEntries(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	input := `{"log":{"entries":[
	  {"request":{"method":"GET","url":"https://example.com/1"},"response":{"status":200}},
	  {"request":{"method":"GET","url":"https://example.com/2"},"response":{"status":200}}
	]}}`
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	stats, err := Import(harPath, &output, 1<<20, 1, redact.New())
	if err != nil {
		t.Fatal(err)
	}

	if stats.EntriesWritten != 1 || !stats.Truncated {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
