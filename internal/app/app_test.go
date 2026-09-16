package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/har"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/kubernetes"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

type failingCloser struct {
	calls int
	err   error
}

func (closer *failingCloser) Close() error {
	closer.calls++
	return closer.err
}

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(context.Background(), []string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("unexpected exit code: %d; stderr=%s", exitCode, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("version output is empty")
	}
}

func TestCollectRequiresHAR(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"collect", "--namespace", "qodo"},
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("unexpected exit code: %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--har is required") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestCollectAcceptsPositionalHARAndDefaultsToApplicationScope(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	missingHAR := t.TempDir() + "/missing.har"

	exitCode := Run(
		context.Background(),
		[]string{
			"collect",
			"--output", t.TempDir() + "/bundle.tar.gz",
			missingHAR,
		},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 1 ||
		!strings.Contains(stderr.String(), "Scope: all application namespaces") ||
		!strings.Contains(stderr.String(), filepath.Base(missingHAR)) {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestCollectRejectsDuplicateHARArguments(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"collect", "--har", "first.har", "second.har"},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 2 ||
		!strings.Contains(stderr.String(), "either positionally or with --har") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestServeRequiresBundlePath(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"serve", "--no-open"},
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("unexpected exit code: %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "requires exactly one bundle path") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestServeRejectsNonPositiveArchiveLimit(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"serve", "--max-archive-bytes", "0", "bundle.tar.gz"},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 2 ||
		!strings.Contains(stderr.String(), "max-archive-bytes must be positive") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestServeRejectsArchiveLimitThatCannotBeIncrementedSafely(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{
			"serve",
			"--max-archive-bytes",
			"9223372036854775806",
			"bundle.tar.gz",
		},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 2 ||
		!strings.Contains(stderr.String(), "max-archive-bytes is too large") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestParseNamespacesUsesExplicitDeploymentScope(t *testing.T) {
	t.Parallel()

	namespaces, err := parseNamespaces(
		"qodo",
		"qodo-platform, zitadel, qodo-platform, platform-client",
	)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{"qodo-platform", "zitadel", "platform-client"}
	if !reflect.DeepEqual(namespaces, expected) {
		t.Fatalf("unexpected namespaces: %+v", namespaces)
	}
}

func TestCollectRejectsAmbiguousAllNamespaceScope(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{
			"collect",
			"--all-namespaces",
			"--namespaces", "qodo,zitadel",
			"--har", "capture.har",
		},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 2 ||
		!strings.Contains(stderr.String(), "cannot be combined") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestCollectRequiresAllNamespacesForSystemExclusion(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{
			"collect",
			"--exclude-system-namespaces",
			"--har", "capture.har",
		},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 2 ||
		!strings.Contains(stderr.String(), "requires --all-namespaces") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestCollectAcceptsFalseSystemExclusionWithExplicitNamespace(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	missingHAR := filepath.Join(t.TempDir(), "missing.har")

	exitCode := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--exclude-system-namespaces=false",
			"--output", filepath.Join(t.TempDir(), "bundle.tar.gz"),
			missingHAR,
		},
		&bytes.Buffer{},
		&stderr,
	)

	if exitCode != 1 ||
		strings.Contains(stderr.String(), "requires --all-namespaces") {
		t.Fatalf("unexpected result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestCollectRejectsUnsafeResourceLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		arguments []string
		message   string
	}{
		{
			name:      "per log bytes",
			arguments: []string{"--max-log-bytes", fmt.Sprint(maxLogLimit + 1)},
			message:   "--max-log-bytes must not exceed",
		},
		{
			name:      "total log bytes",
			arguments: []string{"--max-total-log-bytes", fmt.Sprint(maxTotalLogLimit + 1)},
			message:   "--max-total-log-bytes must not exceed",
		},
		{
			name:      "raw log scan bytes",
			arguments: []string{"--max-log-scan-bytes", fmt.Sprint(maxLogScanLimit + 1)},
			message:   "--max-log-scan-bytes must not exceed",
		},
		{
			name:      "workers",
			arguments: []string{"--log-workers", fmt.Sprint(maxLogWorkers + 1)},
			message:   "--log-workers must not exceed",
		},
		{
			name:      "command timeout",
			arguments: []string{"--command-timeout", (maxCommandTimeout + time.Second).String()},
			message:   "--command-timeout must not exceed",
		},
		{
			name:      "HAR bytes",
			arguments: []string{"--max-har-bytes", fmt.Sprint(int64(^uint64(0) >> 1))},
			message:   "--max-har-bytes must not exceed",
		},
		{
			name:      "HAR entries",
			arguments: []string{"--max-har-entries", fmt.Sprint(maxHAREntryLimit + 1)},
			message:   "--max-har-entries must not exceed",
		},
		{
			name: "per log exceeds total",
			arguments: []string{
				"--max-log-bytes", "1024",
				"--max-total-log-bytes", "512",
			},
			message: "--max-log-bytes must not exceed --max-total-log-bytes",
		},
		{
			name: "scan bytes below retained bytes",
			arguments: []string{
				"--max-log-bytes", "1024",
				"--max-log-scan-bytes", "512",
			},
			message: "--max-log-scan-bytes must not be less than --max-log-bytes",
		},
		{
			name: "concurrent scan memory",
			arguments: []string{
				"--max-log-scan-bytes", fmt.Sprint(64 << 20),
				"--log-workers", "8",
			},
			message: "--max-log-scan-bytes times --log-workers must not exceed",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			arguments := append(
				[]string{"collect", "--namespace", "qodo", "--har", "capture.har"},
				test.arguments...,
			)
			var stderr bytes.Buffer

			exitCode := Run(
				context.Background(),
				arguments,
				&bytes.Buffer{},
				&stderr,
			)

			if exitCode != 2 || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf(
					"unexpected result: exit=%d stderr=%q",
					exitCode,
					stderr.String(),
				)
			}
		})
	}
}

func TestCloseBundleReportsSanitizedFailureAndSetsFailureExit(t *testing.T) {
	t.Parallel()
	closer := &failingCloser{err: errors.New("remove /sensitive/staging/path")}
	var stderr bytes.Buffer
	exitCode := 3

	closeBundle(closer, &stderr, &exitCode)

	if closer.calls != 1 {
		t.Fatalf("unexpected close calls: %d", closer.calls)
	}
	if exitCode != 1 {
		t.Fatalf("unexpected exit code: %d", exitCode)
	}
	if stderr.String() != "Failed to clean up temporary bundle data.\n" {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestResolveKubectlReturnsCanonicalAbsolutePath(t *testing.T) {
	t.Parallel()
	binaryPath := filepath.Join(t.TempDir(), "kubectl")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveKubectl(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := filepath.EvalSymlinks(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected || !filepath.IsAbs(resolved) {
		t.Fatalf("unexpected resolved path: got %q want %q", resolved, expected)
	}
}

func TestTerminalTextRemovesControlCharacters(t *testing.T) {
	t.Parallel()

	output := terminalText(redact.New(), "capture.har\r\n\x1b[2Jforged")

	if output != "capture.har   [2Jforged" {
		t.Fatalf("unexpected terminal-safe text: %q", output)
	}
}

func TestBuildSummaryExplainsHARTruncation(t *testing.T) {
	t.Parallel()

	summary := buildSummary(
		time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC),
		collectionStatusPartial,
		har.Stats{
			EntriesWritten:          10,
			Truncated:               true,
			CorrelationIDsTruncated: true,
		},
		kubernetes.Report{},
		nil,
	)

	if !strings.Contains(summary, "HAR entry truncation: true") {
		t.Fatalf("summary does not explain partial HAR import: %s", summary)
	}
	if !strings.Contains(summary, "Correlation ID truncation: true") {
		t.Fatalf("summary does not explain correlation truncation: %s", summary)
	}
}
