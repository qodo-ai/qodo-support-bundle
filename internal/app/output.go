package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

var (
	homeDirectory      = os.UserHomeDir
	currentTime        = time.Now
	randomOutputSuffix = func() (string, error) {
		value := make([]byte, 6)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		return hex.EncodeToString(value), nil
	}
)

func defaultOutputPath() (string, error) {
	return defaultOutputPathAt(currentTime().UTC())
}

func defaultOutputPathAt(capturedAt time.Time) (string, error) {
	home, err := homeDirectory()
	if err != nil {
		return "", defaultOutputError(defaultOutputResolveHome, err)
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("%s: %s", defaultOutputResolveHome, defaultOutputAbsoluteHome)
	}
	directory := filepath.Join(home, defaultOutputDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", defaultOutputError(defaultOutputCreateDirectory, err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", defaultOutputError(defaultOutputInspectDirectory, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New(defaultOutputMustBeDirectory)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", defaultOutputError(defaultOutputSecureDirectory, err)
	}
	timestamp := capturedAt.UTC().Format("20060102T150405Z")
	suffix, err := randomOutputSuffix()
	if err != nil {
		return "", defaultOutputError(defaultOutputGenerateFilename, err)
	}
	return filepath.Join(
		directory,
		"qodo-support-bundle-"+timestamp+"-"+suffix+".tar.gz",
	), nil
}

func defaultOutputError(operation string, err error) error {
	if cause := pathFreeCause(err); cause != "" {
		return fmt.Errorf("%s: %s", operation, cause)
	}
	return errors.New(operation)
}

func pathFreeCause(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		parts := make([]string, 0, 2)
		if pathErr.Op != "" && !strings.ContainsAny(pathErr.Op, `/\`) {
			parts = append(parts, pathErr.Op)
		}
		if pathErr.Err != nil {
			inner := pathErr.Err.Error()
			if inner != "" && !strings.ContainsAny(inner, `/\`) {
				parts = append(parts, inner)
			}
		}
		return strings.Join(parts, ": ")
	}
	message := err.Error()
	if message == "" || strings.ContainsAny(message, `/\`) {
		return ""
	}
	return message
}

func resolveKubectl(binary string) (string, error) {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("locate kubectl binary: %w", err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve kubectl binary path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve kubectl binary symlinks: %w", err)
	}
	fileInfo, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect kubectl binary: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", errors.New("kubectl binary must be a regular file")
	}
	return canonical, nil
}

func closeBundle(closer io.Closer, stderr io.Writer, exitCode *int) {
	if err := closer.Close(); err != nil {
		_, _ = fmt.Fprintln(stderr, "Failed to clean up temporary bundle data.")
		*exitCode = 1
	}
}

func terminalText(redactor *redact.Redactor, value string) string {
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, redactor.Text(value))
}
