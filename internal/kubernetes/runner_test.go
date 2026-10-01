package kubernetes

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

func TestExecRunnerReportsStderrTruncationSeparately(t *testing.T) {
	t.Setenv("QODO_RUNNER_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	result, runErr := (ExecRunner{Binary: binary}).Run(
		context.Background(),
		1024,
		"-test.run=^TestExecRunnerHelperProcess$",
		"--",
		"stderr-forbidden-suffix",
	)
	if runErr == nil {
		t.Fatal("expected helper command failure")
	}
	if !result.StderrTruncated {
		t.Fatalf("stderr truncation was not reported: %+v", result)
	}
	if result.Truncated {
		t.Fatalf("stderr truncation changed stdout truncation: %+v", result)
	}
	if len(result.Stderr) > 64<<10 {
		t.Fatalf("stderr exceeded bound: %d", len(result.Stderr))
	}
	if strings.Contains(strings.ToLower(string(result.Stderr)), "forbidden") {
		t.Fatalf("test did not reproduce a truncated permission suffix: %q", result.Stderr)
	}
}

func TestExecRunnerKeepsStdoutTruncationIndependent(t *testing.T) {
	t.Setenv("QODO_RUNNER_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	result, runErr := (ExecRunner{Binary: binary}).Run(
		context.Background(),
		32,
		"-test.run=^TestExecRunnerHelperProcess$",
		"--",
		"stdout",
	)
	if runErr != nil {
		t.Fatalf("stdout limit should retain existing non-error behavior: %v", runErr)
	}
	if !result.Truncated || result.StderrTruncated {
		t.Fatalf("unexpected independent truncation state: %+v", result)
	}
	if len(result.Stdout) > 32 {
		t.Fatalf("stdout exceeded bound: %d", len(result.Stdout))
	}
}

func TestExecRunnerHelperProcess(t *testing.T) {
	if os.Getenv("QODO_RUNNER_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "stderr-forbidden-suffix":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), (64<<10)+1024))
		_, _ = fmt.Fprintln(os.Stderr, "Error from server (Forbidden)")
		os.Exit(1)
	case "stdout":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 4096))
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
