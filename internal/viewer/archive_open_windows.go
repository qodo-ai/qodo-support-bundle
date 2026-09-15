//go:build windows

package viewer

import (
	"fmt"
	"os"
)

func openRegularArchive(path string) (*os.File, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open bundle: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("inspect bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, 0, fmt.Errorf("bundle must be a regular file, got %s", info.Mode().Type())
	}
	return file, info.Size(), nil
}
