package har

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

type notifyingWriter struct {
	bytes.Buffer
	once  sync.Once
	wrote chan struct{}
}

func (writer *notifyingWriter) Write(data []byte) (int, error) {
	written, err := writer.Buffer.Write(data)
	writer.once.Do(func() {
		close(writer.wrote)
	})
	return written, err
}

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

func TestImportClassifiesSensitiveNamesBeforeTruncation(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	headerName := strings.Repeat("h", maxFieldLength) + "authorization"
	queryName := strings.Repeat("q", maxFieldLength) + "client_assertion"
	input := fmt.Sprintf(
		`{"log":{"entries":[{"request":{"headers":[{"name":%q,"value":"raw-header-secret"}],"queryString":[{"name":%q,"value":"raw-query-secret"}]},"response":{}}]}}`,
		headerName,
		queryName,
	)
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if _, err := Import(harPath, &output, 1<<20, 100, redact.New()); err != nil {
		t.Fatal(err)
	}
	result := output.String()
	if strings.Contains(result, "raw-header-secret") ||
		strings.Contains(result, "raw-query-secret") {
		t.Fatalf("output contains a sensitive value: %s", result)
	}
	if strings.Count(result, redact.Replacement) != 2 {
		t.Fatalf("unexpected redaction output: %s", result)
	}
}

func TestImportRejectsNonRegularInput(t *testing.T) {
	t.Parallel()

	_, err := Import(t.TempDir(), &bytes.Buffer{}, 1<<20, 100, redact.New())

	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file error, got %v", err)
	}
}

func TestImportRejectsTrailingData(t *testing.T) {
	t.Parallel()
	for _, trailing := range []string{`{"second":true}`, `garbage`} {
		trailing := trailing
		t.Run(trailing, func(t *testing.T) {
			t.Parallel()
			harPath := filepath.Join(t.TempDir(), "capture.har")
			input := `{"log":{"entries":[]}}` + trailing
			if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := Import(harPath, &bytes.Buffer{}, 1<<20, 100, redact.New())

			if err == nil || !strings.Contains(err.Error(), "trailing") {
				t.Fatalf("expected trailing-data error, got %v", err)
			}
		})
	}
}

func TestImportValidatesEntriesBeyondOutputLimit(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	input := `{"log":{"entries":[
	  {"request":{"method":"GET"},"response":{"status":200}},
	  {"request":{"method":"GET"},"response":
	]}}`
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Import(harPath, &bytes.Buffer{}, 1<<20, 1, redact.New())

	if err == nil {
		t.Fatal("expected malformed skipped entry to be rejected")
	}
}

func TestImportArchiveStreamsEntriesBeforeReadingCompleteInput(t *testing.T) {
	t.Parallel()
	reader, writer := io.Pipe()
	output := &notifyingWriter{wrote: make(chan struct{})}
	inputErr := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte(
			`{"log":{"entries":[{"request":{"method":"GET"},"response":{"status":200}},`,
		))
		if err == nil {
			select {
			case <-output.wrote:
			case <-time.After(5 * time.Second):
				err = errors.New("first entry was not written before the remaining input was requested")
			}
		}
		if err == nil {
			_, err = writer.Write([]byte(
				`{"request":{"method":"POST"},"response":{"status":201}}]}}`,
			))
		}
		_ = writer.CloseWithError(err)
		inputErr <- err
	}()

	type importResult struct {
		stats Stats
		err   error
	}
	result := make(chan importResult, 1)
	go func() {
		decoder := json.NewDecoder(reader)
		encoder := json.NewEncoder(output)
		stats, err := importArchive(decoder, encoder, 100, redact.New())
		if err == nil {
			err = requireEOF(decoder)
		}
		result <- importResult{stats: stats, err: err}
	}()

	select {
	case imported := <-result:
		if imported.err != nil {
			t.Fatal(imported.err)
		}
		if err := <-inputErr; err != nil {
			t.Fatal(err)
		}
		if imported.stats.EntriesWritten != 2 {
			t.Fatalf("unexpected stats: %+v", imported.stats)
		}
	case <-time.After(10 * time.Second):
		_ = reader.Close()
		t.Fatal("HAR import did not stream entries")
	}
}
