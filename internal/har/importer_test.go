package har

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

func TestImportContextHonorsCancellationBeforeOpening(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ImportContext(
		ctx,
		filepath.Join(t.TempDir(), "missing.har"),
		io.Discard,
		1<<20,
		100,
		redact.New(),
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
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
	        "url": "https://example.com/callback?code=oauth-code&code_verifier=url-verifier&request_id=req-1",
	        "httpVersion": "HTTP/2",
	        "headers": [
	          {"name": "Authorization", "value": "Bearer raw-token"},
	          {"name": "Accept", "value": "application/json"}
	        ],
	        "queryString": [
	          {"name": "code", "value": "oauth-code"},
	          {"name": "code_verifier", "value": "query-verifier"},
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
		"url-verifier",
		"query-verifier",
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
		`"request_id":["req-1"]`,
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

func TestImportRejectsUnrepresentableInputLimit(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	if err := os.WriteFile(harPath, []byte(`{"log":{"entries":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Import(harPath, &bytes.Buffer{}, math.MaxInt64, 100, redact.New())

	if err == nil || !strings.Contains(err.Error(), "maximum HAR input bytes") {
		t.Fatalf("expected invalid input-limit error, got %v", err)
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

func TestImportRejectsNullEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		maxEntries int
	}{
		{name: "within output limit", maxEntries: 100},
		{name: "beyond output limit", maxEntries: 0},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harPath := filepath.Join(t.TempDir(), "capture.har")
			if err := os.WriteFile(
				harPath,
				[]byte(`{"log":{"entries":[null]}}`),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			_, err := Import(harPath, &output, 1<<20, test.maxEntries, redact.New())

			if err == nil || !strings.Contains(err.Error(), "null elements") {
				t.Fatalf("expected null-entry error, got %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("null entry produced output: %s", output.String())
			}
		})
	}
}

func TestImportWhitelistsStandardNumericTimings(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	input := `{"log":{"entries":[{
		"timings":{"blocked":1,"dns":2,"connect":3,"send":4,"wait":5,"receive":6,"ssl":7,"email@example.com":8,"comment":"user@example.com"}
	}]}}`
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if _, err := Import(harPath, &output, 1<<20, 100, redact.New()); err != nil {
		t.Fatal(err)
	}

	result := output.String()
	for _, expected := range []string{
		`"blocked":1`,
		`"dns":2`,
		`"connect":3`,
		`"send":4`,
		`"wait":5`,
		`"receive":6`,
		`"ssl":7`,
	} {
		if !strings.Contains(result, expected) {
			t.Fatalf("standard timing %q missing: %s", expected, result)
		}
	}
	for _, forbidden := range []string{"email@example.com", `"comment"`} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("unsafe timing key or value %q present: %s", forbidden, result)
		}
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

func TestImportPreservesRepeatedQueryParameters(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	input := `{"log":{"entries":[{"request":{"queryString":[` +
		`{"name":"scope","value":"read"},{"name":"scope","value":"write"}` +
		`]},"response":{}}]}}`
	if err := os.WriteFile(harPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if _, err := Import(harPath, &output, 1<<20, 100, redact.New()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"scope":["read","write"]`) {
		t.Fatalf("repeated query values were not preserved: %s", output.String())
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

func TestImportRequiresUnambiguousLogAndEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{name: "missing log", input: `{}`},
		{name: "null log", input: `{"log":null}`},
		{name: "duplicate log", input: `{"log":{"entries":[]},"log":{"entries":[]}}`},
		{name: "missing entries", input: `{"log":{"version":"1.2"}}`},
		{name: "null entries", input: `{"log":{"entries":null}}`},
		{
			name:  "duplicate entries",
			input: `{"log":{"entries":[],"entries":[]}}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harPath := filepath.Join(t.TempDir(), "capture.har")
			if err := os.WriteFile(harPath, []byte(test.input), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := Import(harPath, &bytes.Buffer{}, 1<<20, 100, redact.New())

			if err == nil {
				t.Fatalf("expected invalid HAR structure %q to be rejected", test.name)
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
