//go:build !windows

package viewer

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenRegularArchiveRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	fifoPath := filepath.Join(directory, "bundle.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "bundle-link.tar.gz")
	if err := os.Symlink(fifoPath, symlinkPath); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{fifoPath, symlinkPath} {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			result := make(chan error, 1)
			go func() {
				file, _, err := openRegularArchive(path)
				if file != nil {
					_ = file.Close()
				}
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "regular file") {
					t.Fatalf("expected regular-file error, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("opening FIFO blocked")
			}
		})
	}
}
