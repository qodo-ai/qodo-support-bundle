package kubernetes

import (
	"context"
	"strings"
	"testing"
)

func TestExecRunnerRejectsRelativeBinaryPath(t *testing.T) {
	t.Parallel()

	_, err := (ExecRunner{Binary: "kubectl"}).Run(context.Background(), 1024, "version")
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("unexpected error: %v", err)
	}
}
