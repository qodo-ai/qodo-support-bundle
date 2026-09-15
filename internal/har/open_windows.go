//go:build windows

package har

import "os"

func openHARFile(path string) (*os.File, error) {
	return os.Open(path)
}
