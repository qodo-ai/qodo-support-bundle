package viewer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Config controls the local support-bundle viewer.
type Config struct {
	BundlePath    string
	ListenAddress string
	OpenBrowser   bool
	Output        io.Writer
	ErrorOutput   io.Writer
	Limits        ExtractionLimits
}

// Serve checks a bundle for internal consistency and exposes it through a loopback-only UI.
func Serve(ctx context.Context, config Config) (returnErr error) {
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
	config.Limits = defaultExtractionLimits(config.Limits)

	bundle, err := Extract(config.BundlePath, config.Limits)
	if err != nil {
		return err
	}
	defer func() {
		if err := bundle.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean up viewer data: %w", err))
		}
	}()

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

	expectedHost := listener.Addr().String()
	viewerURL := "http://" + expectedHost + "/"
	launcher, err := createLauncher(viewerURL)
	if err != nil {
		return err
	}
	defer launcher.Remove()
	handler := newHandler(bundle, expectedHost, launcher.token, launcher.Remove)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	instructions := fmt.Sprintf(
		"Support bundle viewer: %s\nPress Ctrl+C to stop.\n",
		viewerURL,
	)
	if !config.OpenBrowser {
		instructions = fmt.Sprintf(
			"Support bundle viewer: %s\nOpen launcher file: %s\nPress Ctrl+C to stop.\n",
			viewerURL,
			launcher.path,
		)
	}
	if _, err := fmt.Fprint(config.Output, instructions); err != nil {
		return fmt.Errorf("write viewer instructions: %w", err)
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	if config.OpenBrowser {
		if err := launchBrowser(launcher.path, config.ErrorOutput); err != nil {
			reportBrowserFailure(config.ErrorOutput, launcher.path, err)
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

func defaultExtractionLimits(limits ExtractionLimits) ExtractionLimits {
	if limits.MaxFiles == 0 {
		limits.MaxFiles = DefaultMaxFiles
	}
	if limits.MaxArchiveBytes == 0 {
		limits.MaxArchiveBytes = DefaultMaxArchiveBytes
	}
	if limits.MaxExtractedBytes == 0 {
		limits.MaxExtractedBytes = DefaultMaxExtractedBytes
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = DefaultMaxFileBytes
	}
	return limits
}

type launcherFile struct {
	path  string
	token string
}

func createLauncher(viewerURL string) (*launcherFile, error) {
	token, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate viewer session secret: %w", err)
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate launcher CSP nonce: %w", err)
	}
	escapedURL := html.EscapeString(viewerURL)
	escapedAction := html.EscapeString(viewerURL + "api/session/bootstrap")
	content := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-%s'; base-uri 'none'; form-action %s">
<title>Opening Qodo Support Bundle Viewer</title>
</head>
<body>
<form id="launcher" method="post" action="%s">
<input type="hidden" name="session" value="%s">
</form>
<script nonce="%s">document.getElementById("launcher").submit();</script>
</body>
</html>
`, nonce, escapedURL, escapedAction, token, nonce)
	file, err := os.CreateTemp("", "qodo-support-viewer-*.html")
	if err != nil {
		return nil, fmt.Errorf("create viewer launcher: %w", err)
	}
	path := file.Name()
	removeOnError := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	// The launcher is the only on-disk credential carrier; OS permissions isolate it
	// from other local users. Same-user process isolation is outside this threat model.
	if err := file.Chmod(0o600); err != nil {
		removeOnError()
		return nil, fmt.Errorf("protect viewer launcher: %w", err)
	}
	if _, err := io.WriteString(file, content); err != nil {
		removeOnError()
		return nil, fmt.Errorf("write viewer launcher: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close viewer launcher: %w", err)
	}
	return &launcherFile{path: path, token: token}, nil
}

func (launcher *launcherFile) Remove() error {
	err := os.Remove(launcher.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func randomHex(byteCount int) (string, error) {
	data := make([]byte, byteCount)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func launchBrowser(path string, errorOutput io.Writer) error {
	command, err := newBrowserCommand(path)
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() {
		if err := command.Wait(); err != nil {
			reportBrowserFailure(errorOutput, path, err)
		}
	}()
	return nil
}

func newBrowserCommand(path string) (*exec.Cmd, error) {
	var binary string
	var arguments []string
	switch runtime.GOOS {
	case "darwin":
		binary = "/usr/bin/open"
		arguments = []string{path}
	case "windows":
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			return nil, errors.New("SystemRoot is not configured")
		}
		binary = filepath.Join(systemRoot, "System32", "rundll32.exe")
		arguments = []string{"url.dll,FileProtocolHandler", path}
	default:
		binary = "/usr/bin/xdg-open"
		arguments = []string{path}
	}
	return exec.Command(binary, arguments...), nil
}

func reportBrowserFailure(output io.Writer, launcherPath string, err error) {
	if _, writeErr := fmt.Fprintf(
		output,
		"Could not open a browser automatically: %v\nOpen launcher file: %s\n",
		err,
		launcherPath,
	); writeErr != nil {
		return
	}
}
