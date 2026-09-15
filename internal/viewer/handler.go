package viewer

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

//go:embed web/index.html web/app.js web/request_sequence.mjs web/session.mjs web/styles.css
var webAssets embed.FS

const sessionClaimHeader = "X-Qodo-Viewer-Session"

type handler struct {
	bundle              *ExtractedBundle
	expectedHost        string
	expectedClaimDigest [sha256.Size]byte
	claimCleanup        func() error
	sessionMutex        sync.RWMutex
	sessionToken        string
	mux                 *http.ServeMux
}

func newHandler(
	bundle *ExtractedBundle,
	expectedHost string,
	expectedClaim string,
	claimCleanup func() error,
) http.Handler {
	application := &handler{
		bundle:              bundle,
		expectedHost:        expectedHost,
		expectedClaimDigest: sha256.Sum256([]byte(expectedClaim)),
		claimCleanup:        claimCleanup,
		mux:                 http.NewServeMux(),
	}
	application.mux.HandleFunc("/api/session", application.handleSession)
	application.mux.HandleFunc("/api/manifest", application.handleManifest)
	application.mux.HandleFunc("/api/files", application.handleFiles)
	application.mux.HandleFunc("/api/timeline", application.handleTimeline)
	application.mux.HandleFunc("/api/record", application.handleRecord)
	application.mux.HandleFunc("/api/records", application.handleRecords)
	application.mux.HandleFunc("/app.js", application.handleJavaScript)
	application.mux.HandleFunc(
		"/request_sequence.mjs",
		application.handleRequestSequence,
	)
	application.mux.HandleFunc("/session.mjs", application.handleSessionJavaScript)
	application.mux.HandleFunc("/styles.css", application.handleStyles)
	application.mux.HandleFunc("/", application.handleIndex)
	return application
}

func (application *handler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	setSecurityHeaders(writer.Header())
	if !requestFromLoopback(request) || request.Host != application.expectedHost {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") &&
		request.URL.Path != "/api/session" &&
		!application.authorized(request) {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	application.mux.ServeHTTP(writer, request)
}

func (application *handler) authorized(request *http.Request) bool {
	const bearerPrefix = "Bearer "
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, bearerPrefix) {
		return false
	}
	providedToken := strings.TrimPrefix(authorization, bearerPrefix)
	providedDigest := sha256.Sum256([]byte(providedToken))
	application.sessionMutex.RLock()
	expectedToken := application.sessionToken
	application.sessionMutex.RUnlock()
	if expectedToken == "" {
		return false
	}
	expectedDigest := sha256.Sum256([]byte(expectedToken))
	return subtle.ConstantTimeCompare(
		providedDigest[:],
		expectedDigest[:],
	) == 1
}

func (application *handler) handleSession(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := request.Header.Get(sessionClaimHeader)
	decodedToken, err := hex.DecodeString(token)
	if err != nil || len(decodedToken) != 32 {
		http.Error(writer, "A valid session claim header is required", http.StatusBadRequest)
		return
	}
	providedDigest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(
		providedDigest[:],
		application.expectedClaimDigest[:],
	) != 1 {
		http.Error(writer, "Invalid viewer session claim", http.StatusForbidden)
		return
	}
	application.sessionMutex.Lock()
	defer application.sessionMutex.Unlock()
	if application.sessionToken != "" {
		// Retrying the server-issued claim is safe and handles a lost success response.
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if application.claimCleanup != nil {
		if err := application.claimCleanup(); err != nil {
			http.Error(writer, "Could not retire viewer launcher", http.StatusInternalServerError)
			return
		}
	}
	application.sessionToken = token
	writer.WriteHeader(http.StatusNoContent)
}

func (application *handler) handleIndex(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	serveEmbeddedFile(writer, "web/index.html", "text/html; charset=utf-8")
}

func (application *handler) handleJavaScript(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(writer, "web/app.js", "text/javascript; charset=utf-8")
}

func (application *handler) handleStyles(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(writer, "web/styles.css", "text/css; charset=utf-8")
}

func (application *handler) handleRequestSequence(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(
		writer,
		"web/request_sequence.mjs",
		"text/javascript; charset=utf-8",
	)
}

func (application *handler) handleSessionJavaScript(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(
		writer,
		"web/session.mjs",
		"text/javascript; charset=utf-8",
	)
}

func (application *handler) handleManifest(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	path, exists := application.bundle.Resolve("manifest.json")
	if !exists {
		http.Error(writer, "Manifest is missing", http.StatusUnprocessableEntity)
		return
	}
	data, err := readFileBounded(path, 4<<20)
	if err != nil {
		http.Error(writer, "Could not read manifest", http.StatusInternalServerError)
		return
	}
	var manifest any
	if err := json.Unmarshal(data, &manifest); err != nil {
		http.Error(writer, "Manifest is invalid", http.StatusUnprocessableEntity)
		return
	}
	writeJSON(writer, manifest)
}

func (application *handler) handleFiles(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	type fileResponse struct {
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		Category string `json:"category"`
	}
	files := make([]fileResponse, 0, len(application.bundle.Files))
	for _, file := range application.bundle.Files {
		if file.Path == "checksums.sha256" || file.Path == "manifest.json" {
			continue
		}
		files = append(files, fileResponse{
			Path:     file.Path,
			Size:     file.Size,
			Category: categoryForPath(file.Path),
		})
	}
	writeJSON(writer, map[string]any{"files": files})
}

func (application *handler) handleRecords(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	query := request.URL.Query()
	path := query.Get("path")
	if path == "" {
		http.Error(writer, "path is required", http.StatusBadRequest)
		return
	}
	limit := parsePositiveInt(query.Get("limit"), 200, maxRecordLimit)
	offset := parsePositiveInt(query.Get("offset"), 0, 10_000_000)
	if query.Get("offset") == "0" {
		offset = 0
	}
	response, err := readRecords(
		application.bundle,
		path,
		query.Get("query"),
		query.Get("filter"),
		offset,
		limit,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unknown bundle file") {
			http.Error(writer, "Unknown bundle file", http.StatusNotFound)
			return
		}
		http.Error(writer, "Could not read bundle records", http.StatusUnprocessableEntity)
		return
	}
	writeJSON(writer, response)
}

func (application *handler) handleTimeline(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	query := request.URL.Query()
	limit := parsePositiveInt(
		query.Get("limit"),
		defaultTimelineLimit,
		maxTimelineLimit,
	)
	response, err := readTimeline(
		request.Context(),
		application.bundle,
		query.Get("query"),
		query.Get("filter"),
		limit,
	)
	if err != nil {
		http.Error(writer, "Could not build timeline", http.StatusUnprocessableEntity)
		return
	}
	writeJSON(writer, response)
}

func (application *handler) handleRecord(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	query := request.URL.Query()
	path := query.Get("path")
	line := parsePositiveInt(query.Get("line"), 0, 10_000_000)
	if path == "" || line == 0 {
		http.Error(writer, "path and positive line are required", http.StatusBadRequest)
		return
	}
	record, err := readRecordAtLine(application.bundle, path, line)
	if err != nil {
		http.Error(writer, "Record was not found", http.StatusNotFound)
		return
	}
	writeJSON(writer, record)
}

func setSecurityHeaders(headers http.Header) {
	headers.Set("Cache-Control", "no-store")
	headers.Set(
		"Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; "+
			"connect-src 'self'; img-src 'self' data:; base-uri 'none'; "+
			"frame-ancestors 'none'; form-action 'none'",
	)
	headers.Set("Cross-Origin-Resource-Policy", "same-origin")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
}

func requestFromLoopback(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func serveEmbeddedFile(writer http.ResponseWriter, path string, contentType string) {
	data, err := webAssets.ReadFile(path)
	if err != nil {
		http.Error(writer, "Viewer asset is unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", contentType)
	_, _ = writer.Write(data)
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return
	}
}

func methodNotAllowed(writer http.ResponseWriter) {
	writer.Header().Set("Allow", http.MethodGet)
	http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
}

func readFileBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}

func categoryForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "browser/"):
		return "Browser"
	case strings.HasPrefix(path, "kubernetes/logs/"):
		return "Backend logs"
	case path == "kubernetes/events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/events/"):
		return "Kubernetes events"
	case path == "kubernetes/pods.jsonl" ||
		strings.HasPrefix(path, "kubernetes/pods/"):
		return "Kubernetes pods"
	default:
		return "Diagnostics"
	}
}
