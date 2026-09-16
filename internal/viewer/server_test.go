package viewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	archivebundle "github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/bundle"
)

const testViewerToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestHandlerServesManifestWithSecurityHeaders(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{"collection":{"status":"complete"}}`,
	})
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/manifest",
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

func TestHandlerRequiresTokenOnlyForAPIs(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{}`,
	})
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")

	indexRequest := viewerRequest(http.MethodGet, "http://127.0.0.1:4321/")
	indexRequest.Header.Del("Authorization")
	indexResponse := httptest.NewRecorder()
	handler.ServeHTTP(indexResponse, indexRequest)
	if indexResponse.Code != http.StatusOK {
		t.Fatalf("public index returned %d", indexResponse.Code)
	}

	apiRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/manifest",
	)
	apiRequest.Header.Del("Authorization")
	apiResponse := httptest.NewRecorder()
	handler.ServeHTTP(apiResponse, apiRequest)
	if apiResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API returned %d", apiResponse.Code)
	}

	apiRequest.Header.Set("Authorization", "Bearer wrong-token")
	wrongTokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongTokenResponse, apiRequest)
	if wrongTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token API returned %d", wrongTokenResponse.Code)
	}
}

func TestHandlerRejectsWrongHostAndNonLoopbackClient(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{
		"manifest.json": `{}`,
	})
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")

	wrongHost := viewerRequest(
		http.MethodGet,
		"http://attacker.invalid/api/manifest",
	)
	wrongHost.Host = "attacker.invalid"
	wrongHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongHostResponse, wrongHost)
	if wrongHostResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong host returned %d", wrongHostResponse.Code)
	}

	remoteRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/manifest",
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
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/records?"+
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
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")

	timelineRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/timeline?filter=auth",
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
		"http://127.0.0.1:4321/api/record?"+
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
	handler := newClaimedHandler(t, bundle, "127.0.0.1:4321")
	request := viewerRequest(
		http.MethodPost,
		"http://127.0.0.1:4321/api/manifest",
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected response: %d", response.Code)
	}
}

func TestHandlerOnlyAcceptsServerIssuedSession(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{"manifest.json": `{}`})
	handler := newHandler(bundle, "127.0.0.1:4321", testViewerToken, nil)
	const claimCount = 16
	statuses := make(chan int, claimCount)
	var waitGroup sync.WaitGroup
	for index := 0; index < claimCount; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request := viewerRequest(
				http.MethodPost,
				"http://127.0.0.1:4321/api/session",
			)
			request.Header.Del("Authorization")
			request.Header.Set(sessionClaimHeader, strings.Repeat("a", 64))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	waitGroup.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusForbidden {
			t.Fatalf("unexpected claim status: %d", status)
		}
	}
	request := viewerRequest(http.MethodPost, "http://127.0.0.1:4321/api/session")
	request.Header.Del("Authorization")
	request.Header.Set(sessionClaimHeader, testViewerToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("server-issued claim returned %d", response.Code)
	}
}

func TestHandlerBootstrapsSessionThroughFormWithoutURLCredential(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{"manifest.json": `{}`})
	handler := newHandler(bundle, "127.0.0.1:4321", testViewerToken, nil)
	request := httptest.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:4321/api/session/bootstrap",
		strings.NewReader("session="+testViewerToken),
	)
	request.Host = "127.0.0.1:4321"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/" {
		t.Fatalf("unexpected bootstrap response: %d %s", response.Code, response.Body)
	}
	result := response.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName ||
		!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %#v", cookies)
	}
	manifestRequest := viewerRequest(
		http.MethodGet,
		"http://127.0.0.1:4321/api/manifest",
	)
	manifestRequest.Header.Del("Authorization")
	manifestRequest.AddCookie(cookies[0])
	manifestResponse := httptest.NewRecorder()
	handler.ServeHTTP(manifestResponse, manifestRequest)
	if manifestResponse.Code != http.StatusOK {
		t.Fatalf(
			"cookie-authenticated manifest failed: %d %s",
			manifestResponse.Code,
			manifestResponse.Body,
		)
	}
}

func TestHandlerRequiresCustomHeaderToClaimSession(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{"manifest.json": `{}`})
	handler := newHandler(bundle, "127.0.0.1:4321", testViewerToken, nil)
	request := viewerRequest(http.MethodPost, "http://127.0.0.1:4321/api/session")
	request.Header.Del("Authorization")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("claim without custom header returned %d", response.Code)
	}
}

func TestHandlerDoesNotAllowCrossOriginSessionPreflight(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{"manifest.json": `{}`})
	handler := newHandler(bundle, "127.0.0.1:4321", testViewerToken, nil)
	request := viewerRequest(http.MethodOptions, "http://127.0.0.1:4321/api/session")
	request.Header.Del("Authorization")
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", sessionClaimHeader)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected preflight response: %d", response.Code)
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cross-origin request was allowed: %+v", response.Header())
	}
}

func TestHandlerRetriesClaimAfterLauncherCleanupFailure(t *testing.T) {
	t.Parallel()
	bundle := testExtractedBundle(t, map[string]string{"manifest.json": `{}`})
	cleanupCalls := 0
	handler := newHandler(
		bundle,
		"127.0.0.1:4321",
		testViewerToken,
		func() error {
			cleanupCalls++
			if cleanupCalls == 1 {
				return errors.New("temporary cleanup failure")
			}
			return nil
		},
	)
	request := viewerRequest(http.MethodPost, "http://127.0.0.1:4321/api/session")
	request.Header.Del("Authorization")
	request.Header.Set(sessionClaimHeader, testViewerToken)

	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, request)
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, request)

	if firstResponse.Code != http.StatusInternalServerError ||
		secondResponse.Code != http.StatusNoContent ||
		cleanupCalls != 2 {
		t.Fatalf(
			"unexpected retry result: first=%d second=%d cleanup=%d",
			firstResponse.Code,
			secondResponse.Code,
			cleanupCalls,
		)
	}
}

func TestCreateLauncherProtectsSecretAndUsesBrowserCompatibleCSP(t *testing.T) {
	t.Parallel()
	launcher, err := createLauncher("http://127.0.0.1:4321/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := launcher.Remove(); err != nil {
			t.Error(err)
		}
	})
	info, err := os.Stat(launcher.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected launcher permissions: %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(launcher.path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `name="session" value="`+launcher.token+`"`) ||
		!strings.Contains(content, `action="http://127.0.0.1:4321/api/session/bootstrap"`) ||
		!strings.Contains(content, `.submit()`) ||
		!strings.Contains(content, `script-src 'nonce-`) {
		t.Fatalf("launcher is missing protected handoff: %s", content)
	}
	if strings.Contains(content, "window.name") || strings.Contains(content, "#"+launcher.token) {
		t.Fatalf("launcher puts the credential in browser navigation state: %s", content)
	}
}

func TestBrowserOpenerUsesAbsoluteSystemPath(t *testing.T) {
	t.Parallel()

	command, err := newBrowserCommand("/tmp/viewer-launcher.html")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(command.Path) {
		t.Fatalf("browser opener path is not absolute: %q", command.Path)
	}
}

func TestServeStartsAndStopsLocalViewer(t *testing.T) {
	t.Parallel()
	archivePath := createTestViewerArchive(t)

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
	if strings.Contains(output.String(), "token") ||
		strings.Contains(output.String(), testViewerToken) {
		t.Fatalf("viewer output contains an access token: %s", output.String())
	}
	client := &http.Client{Timeout: 2 * time.Second}
	launcherPath := outputValue(t, output.String(), "Open launcher file: ")
	launcherData, err := os.ReadFile(launcherPath)
	if err != nil {
		t.Fatal(err)
	}
	token := launcherToken(t, string(launcherData))
	claimRequest, err := http.NewRequest(
		http.MethodPost,
		viewerURL+"api/session",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	claimRequest.Header.Set(sessionClaimHeader, token)
	claimResponse, err := client.Do(claimRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if claimResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected claim status: %d", claimResponse.StatusCode)
	}
	if _, err := os.Stat(launcherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("launcher still exists after claim: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, viewerURL+"api/manifest", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
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

func TestServeRemovesUnclaimedLauncherAtShutdown(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	archivePath := createTestViewerArchive(t)
	output := newReadyWriter()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- Serve(ctx, Config{
			BundlePath:    archivePath,
			ListenAddress: "127.0.0.1:0",
			Output:        output,
		})
	}()
	select {
	case <-output.ready:
	case <-time.After(3 * time.Second):
		t.Fatalf("viewer did not start: %s", output.String())
	}
	launcherPath := outputValue(t, output.String(), "Open launcher file: ")

	cancel()
	select {
	case err := <-serveErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("viewer did not stop")
	}
	if _, err := os.Stat(launcherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("launcher still exists after shutdown: %v", err)
	}
}

func TestServeFailsWhenInstructionsCannotBeWritten(t *testing.T) {
	t.Parallel()
	archivePath := createTestViewerArchive(t)

	err := Serve(context.Background(), Config{
		BundlePath:    archivePath,
		ListenAddress: "127.0.0.1:0",
		Output:        failingWriter{},
	})

	if err == nil || !strings.Contains(err.Error(), "write viewer instructions") {
		t.Fatalf("expected output error, got %v", err)
	}
}

func createTestViewerArchive(t *testing.T) string {
	t.Helper()
	archivePath := t.TempDir() + "/bundle.tar.gz"
	builder, err := archivebundle.New(archivePath)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := builder.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func outputValue(t *testing.T, output string, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("output does not contain %q: %s", prefix, output)
	return ""
}

func launcherToken(t *testing.T, content string) string {
	t.Helper()
	const prefix = `name="session" value="`
	start := strings.Index(content, prefix)
	if start < 0 {
		t.Fatalf("launcher token is missing: %s", content)
	}
	start += len(prefix)
	end := strings.Index(content[start:], `"`)
	if end < 0 {
		t.Fatalf("launcher token is unterminated: %s", content)
	}
	return content[start : start+end]
}

func newClaimedHandler(
	t *testing.T,
	bundle *ExtractedBundle,
	expectedHost string,
) http.Handler {
	t.Helper()
	handler := newHandler(bundle, expectedHost, testViewerToken, nil)
	request := viewerRequest(http.MethodPost, "http://"+expectedHost+"/api/session")
	request.Header.Del("Authorization")
	request.Header.Set(sessionClaimHeader, testViewerToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("could not claim test viewer session: %d %s", response.Code, response.Body)
	}
	return handler
}

func viewerRequest(method string, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Host = "127.0.0.1:4321"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer "+testViewerToken)
	return request
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
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
