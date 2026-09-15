package viewer

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//go:embed web/*
var webAssets embed.FS

// Config controls the local support-bundle viewer.
type Config struct {
	BundlePath    string
	ListenAddress string
	OpenBrowser   bool
	Output        io.Writer
	ErrorOutput   io.Writer
	Limits        ExtractionLimits
}

// Serve verifies a bundle and exposes its contents through a loopback-only UI.
func Serve(ctx context.Context, config Config) error {
	if config.BundlePath == "" {
		return errors.New("bundle path is required")
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:0"
	}
	if config.Output == nil {
		config.Output = io.Discard
	}
	if config.ErrorOutput == nil {
		config.ErrorOutput = io.Discard
	}
	if config.Limits == (ExtractionLimits{}) {
		config.Limits = ExtractionLimits{
			MaxFiles:          DefaultMaxFiles,
			MaxExtractedBytes: DefaultMaxExtractedBytes,
			MaxFileBytes:      DefaultMaxFileBytes,
		}
	}

	bundle, err := Extract(config.BundlePath, config.Limits)
	if err != nil {
		return err
	}
	defer bundle.Close()

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("start viewer listener: %w", err)
	}
	defer listener.Close()
	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !tcpAddress.IP.IsLoopback() {
		return fmt.Errorf(
			"viewer must bind to a loopback address, got %s",
			listener.Addr(),
		)
	}

	token, err := randomToken()
	if err != nil {
		return err
	}
	expectedHost := listener.Addr().String()
	basePath := "/" + token
	handler := newHandler(bundle, basePath, expectedHost)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()

	viewerURL := "http://" + expectedHost + basePath + "/"
	_, _ = fmt.Fprintf(config.Output, "Support bundle viewer: %s\n", viewerURL)
	_, _ = fmt.Fprintln(config.Output, "Press Ctrl+C to stop.")
	if config.OpenBrowser {
		if err := launchBrowser(viewerURL); err != nil {
			_, _ = fmt.Fprintf(
				config.ErrorOutput,
				"Could not open a browser automatically: %v\n",
				err,
			)
		}
	}

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("stop viewer: %w", err)
		}
		return nil
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("run viewer: %w", err)
	}
}

type handler struct {
	bundle       *ExtractedBundle
	basePath     string
	expectedHost string
	mux          *http.ServeMux
}

func newHandler(
	bundle *ExtractedBundle,
	basePath string,
	expectedHost string,
) http.Handler {
	application := &handler{
		bundle:       bundle,
		basePath:     basePath,
		expectedHost: expectedHost,
		mux:          http.NewServeMux(),
	}
	application.mux.HandleFunc(basePath+"/api/manifest", application.handleManifest)
	application.mux.HandleFunc(basePath+"/api/files", application.handleFiles)
	application.mux.HandleFunc(basePath+"/api/timeline", application.handleTimeline)
	application.mux.HandleFunc(basePath+"/api/record", application.handleRecord)
	application.mux.HandleFunc(basePath+"/api/records", application.handleRecords)
	application.mux.HandleFunc(basePath+"/app.js", application.handleJavaScript)
	application.mux.HandleFunc(basePath+"/styles.css", application.handleStyles)
	application.mux.HandleFunc(basePath+"/", application.handleIndex)
	application.mux.HandleFunc("/", http.NotFound)
	return application
}

func (application *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	if !requestFromLoopback(request) || request.Host != application.expectedHost {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	application.mux.ServeHTTP(writer, request)
}

func (application *handler) handleIndex(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	if request.URL.Path != application.basePath+"/" {
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

func randomToken() (string, error) {
	data := make([]byte, 24)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("create viewer session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func launchBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() {
		_ = command.Wait()
	}()
	return nil
}
