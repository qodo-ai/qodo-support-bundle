package viewer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
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
	handler := newHandler(bundle, expectedHost, token)
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

	viewerURL := "http://" + expectedHost + "/"
	_, _ = fmt.Fprintf(config.Output, "Support bundle viewer: %s\n", viewerURL)
	_, _ = fmt.Fprintf(config.Output, "Viewer access token: %s\n", token)
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
