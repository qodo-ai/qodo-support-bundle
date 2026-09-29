//go:build unix

package main

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestInterruptSignals(t *testing.T) {
	t.Parallel()

	expected := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
	if signals := interruptSignals(); !reflect.DeepEqual(signals, expected) {
		t.Fatalf("unexpected interrupt signals: %v", signals)
	}
}
