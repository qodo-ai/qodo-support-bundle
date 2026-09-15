package app

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

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
		!strings.Contains(stderr.String(), missingHAR) {
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
