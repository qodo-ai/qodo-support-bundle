//go:build unix

package har

import (
	"bytes"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

func TestImportRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	if err := syscall.Mkfifo(harPath, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Import(harPath, &bytes.Buffer{}, 1<<20, 100, redact.New())

	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file error, got %v", err)
	}
}

func TestOpenHARFileDoesNotBlockOnFIFO(t *testing.T) {
	t.Parallel()
	harPath := filepath.Join(t.TempDir(), "capture.har")
	if err := syscall.Mkfifo(harPath, 0o600); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		file, err := openHARFile(harPath)
		if err == nil {
			err = file.Close()
		}
		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("nonblocking FIFO open failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO open blocked")
	}
}
