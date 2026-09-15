package viewer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	archivebundle "github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/bundle"
)

func TestHandlerServesManifestWithSecurityHeaders(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{"collection":{"status":"complete"}}`,
	})
	handler := newHandler(bundle, "/session-token", "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/session-token/api/manifest",
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body)
	}
	if response.Header().Get("Content-Security-Policy") == "" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers are missing: %+v", response.Header())
	}
	var manifest map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerRejectsWrongHostAndNonLoopbackClient(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{}`,
	})
	handler := newHandler(bundle, "/session-token", "127.0.0.1:4321")

	wrongHost := viewerRequest(
		http.MethodGet,
		"http://attacker.invalid/session-token/api/manifest",
	)
	wrongHost.Host = "attacker.invalid"
	wrongHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongHostResponse, wrongHost)
	if wrongHostResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong host returned %d", wrongHostResponse.Code)
	}

	remoteRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/session-token/api/manifest",
	)
	remoteRequest.RemoteAddr = "192.0.2.10:1234"
	remoteResponse := httptest.NewRecorder()
	handler.ServeHTTP(remoteResponse, remoteRequest)
	if remoteResponse.Code != http.StatusForbidden {
		t.Fatalf("remote client returned %d", remoteResponse.Code)
	}
}

func TestHandlerFiltersRecords(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `
{"request":{"method":"GET","url":"https://example.com/health"},"response":{"status":200}}
{"request":{"method":"GET","url":"https://example.com/auth/v1/oidc/userinfo"},"response":{"status":403}}
`,
	})
	handler := newHandler(bundle, "/session-token", "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/session-token/api/records?"+
			"path=browser%2Fnetwork.jsonl&filter=errors",
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), `"status":403`) ||
		strings.Contains(response.Body.String(), `"status":200`) {
		t.Fatalf("unexpected filtered response: %s", response.Body)
	}
}

func TestHandlerServesTimelineAndRecordDetails(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"browser/network.jsonl": `{"@timestamp":"2026-09-15T07:02:00Z","request":{"method":"GET","url":"https://example.com/auth/v1/oidc/userinfo"},"response":{"status":403}}` + "\n",
	})
	handler := newHandler(bundle, "/session-token", "127.0.0.1:4321")

	timelineRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/session-token/api/timeline?filter=auth",
	)
	timelineResponse := httptest.NewRecorder()
	handler.ServeHTTP(timelineResponse, timelineRequest)
	if timelineResponse.Code != http.StatusOK {
		t.Fatalf(
			"unexpected timeline response: %d %s",
			timelineResponse.Code,
			timelineResponse.Body,
		)
	}
	if !strings.Contains(timelineResponse.Body.String(), `"lane":"Browser"`) ||
		strings.Contains(timelineResponse.Body.String(), `"details"`) {
		t.Fatalf("unexpected timeline: %s", timelineResponse.Body)
	}

	recordRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/session-token/api/record?"+
			"path=browser%2Fnetwork.jsonl&line=1",
	)
	recordResponse := httptest.NewRecorder()
	handler.ServeHTTP(recordResponse, recordRequest)
	if recordResponse.Code != http.StatusOK {
		t.Fatalf(
			"unexpected record response: %d %s",
			recordResponse.Code,
			recordResponse.Body,
		)
	}
	if !strings.Contains(recordResponse.Body.String(), `"details"`) {
		t.Fatalf("record details are missing: %s", recordResponse.Body)
	}
}

func TestHandlerRejectsMutationMethods(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{}`,
	})
	handler := newHandler(bundle, "/session-token", "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodPost,
		"http://127.0.0.1:4321/session-token/api/manifest",
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected response: %d", response.Code)
	}
}

func TestRandomTokenIsUnpredictableLength(t *testing.T) {
	t.Parallel()
	first, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 || first == second {
		t.Fatalf("unexpected session tokens: %q %q", first, second)
	}
}

func TestServeStartsAndStopsLocalViewer(t *testing.T) {
	t.Parallel()
	archivePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	builder, err := archivebundle.New(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.Add("browser/network.jsonl", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Finalize(archivebundle.Manifest{
		CollectorVersion: "test",
		GeneratedAt:      time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC),
		Collection:       map[string]any{"status": "complete"},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := newReadyWriter()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- Serve(ctx, Config{
			BundlePath:    archivePath,
			ListenAddress: "127.0.0.1:0",
			Output:        output,
			ErrorOutput:   output,
		})
	}()
	select {
	case <-output.ready:
	case <-time.After(3 * time.Second):
		t.Fatalf("viewer did not start: %s", output.String())
	}

	fields := strings.Fields(output.String())
	if len(fields) < 4 {
		t.Fatalf("viewer URL is missing: %s", output.String())
	}
	viewerURL := fields[3]
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(viewerURL + "api/manifest")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}

	cancel()
	select {
	case err := <-serveErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("viewer did not stop")
	}
}

func viewerRequest(method string, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Host = "127.0.0.1:4321"
	request.RemoteAddr = "127.0.0.1:1234"
	return request
}

type readyWriter struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
	ready  chan struct{}
	once   sync.Once
}

func newReadyWriter() *readyWriter {
	return &readyWriter{ready: make(chan struct{})}
}

func (writer *readyWriter) Write(data []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	written, err := writer.buffer.Write(data)
	if strings.Contains(writer.buffer.String(), "Support bundle viewer:") {
		writer.once.Do(func() {
			close(writer.ready)
		})
	}
	return written, err
}

func (writer *readyWriter) String() string {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return writer.buffer.String()
}
