//go:build unix

package har

import (
	"os"
	"syscall"
)

func openHARFile(path string) (*os.File, error) {
	fileDescriptor, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileDescriptor), path), nil
}
