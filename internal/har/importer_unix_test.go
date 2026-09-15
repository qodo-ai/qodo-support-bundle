//go:build unix

package har

import (
	"bytes"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

func TestImportRejectsFIFOWithoutOpeningIt(t *testing.T) {
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
