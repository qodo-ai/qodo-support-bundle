package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

type failingCloser struct {
	calls int
	err   error
}

func (closer *failingCloser) Close() error {
	closer.calls++
	return closer.err
}

func TestRunOnlyExposesSupportedCommands(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit=%d stderr=%s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("version output is empty")
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"serve", "bundle.tar.gz"}, &stdout, &stderr); code != 2 {
		t.Fatalf("serve exit=%d", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "serve"`) {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestCollectRejectsPositionalAndUnsupportedInput(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		{"collect", "capture.json"},
		{"collect", "--input", "capture.json"},
	} {
		var stderr bytes.Buffer
		code := Run(context.Background(), arguments, &bytes.Buffer{}, &stderr)
		if code != 2 {
			t.Fatalf("%v exit=%d stderr=%s", arguments, code, stderr.String())
		}
	}
}

func TestCollectRequiresNoInputFile(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"collect", "--namespace", "qodo", "--since", "0"},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 2 || !strings.Contains(stderr.String(), "--since must be positive") {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(strings.ToLower(stderr.String()), "input file") {
		t.Fatalf("obsolete input validation remains: %s", stderr.String())
	}
}

func TestCollectRejectsNamespaceAndNamespacesTogether(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--namespaces", "qodo,zitadel",
		},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 2 ||
		!strings.Contains(
			stderr.String(),
			"--namespace and --namespaces cannot be combined",
		) {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
}

func TestCollectRejectsUnsafeMetadataLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		message string
	}{
		{name: "zero", value: "0", message: "must be positive"},
		{
			name:    "above maximum",
			value:   fmt.Sprint(maxMetadataLimit + 1),
			message: "must not exceed",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := Run(
				context.Background(),
				[]string{
					"collect",
					"--namespace", "qodo",
					"--max-metadata-bytes", test.value,
				},
				&bytes.Buffer{},
				&stderr,
			)
			if code != 2 ||
				!strings.Contains(stderr.String(), test.message) {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestProbeFlagCouplingAndNamespaceInference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		enabled    bool
		visited    map[string]bool
		namespaces []string
		all        bool
		namespace  string
		pod        string
		container  string
		wantNS     string
		wantError  string
	}{
		{
			name:       "single namespace inferred",
			enabled:    true,
			visited:    map[string]bool{},
			namespaces: []string{"qodo"},
			pod:        "platform-0",
			container:  "platform",
			wantNS:     "qodo",
		},
		{
			name:       "multiple namespaces require target namespace",
			enabled:    true,
			namespaces: []string{"qodo", "zitadel"},
			pod:        "platform-0",
			container:  "platform",
			wantError:  "--platform-namespace",
		},
		{
			name:      "all namespaces require target namespace",
			enabled:   true,
			all:       true,
			pod:       "platform-0",
			container: "platform",
			wantError: "--platform-namespace",
		},
		{
			name:      "target rejected without check",
			visited:   map[string]bool{"platform-pod": true},
			pod:       "platform-0",
			wantError: "require --check-zitadel",
		},
		{
			name:       "target must be in explicit scope",
			enabled:    true,
			namespaces: []string{"qodo"},
			namespace:  "other",
			pod:        "platform-0",
			container:  "platform",
			wantError:  "included in the collection scope",
		},
		{
			name:       "invalid pod name",
			enabled:    true,
			namespaces: []string{"qodo"},
			namespace:  "qodo",
			pod:        "Platform_0",
			container:  "platform",
			wantError:  "DNS-compatible",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			namespace := test.namespace
			err := validateProbeFlags(
				test.enabled,
				test.visited,
				test.namespaces,
				test.all,
				&namespace,
				test.pod,
				test.container,
				defaultProbeTimeout,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || namespace != test.wantNS {
				t.Fatalf("namespace=%q error=%v", namespace, err)
			}
		})
	}
}

func TestDefaultOutputPathUsesPrivateHomeDirectory(t *testing.T) {
	oldHome := homeDirectory
	oldTime := currentTime
	oldRandomSuffix := randomOutputSuffix
	t.Cleanup(func() {
		homeDirectory = oldHome
		currentTime = oldTime
		randomOutputSuffix = oldRandomSuffix
	})
	home := t.TempDir()
	homeDirectory = func() (string, error) { return home, nil }
	currentTime = func() time.Time {
		return time.Date(2026, 9, 27, 10, 11, 12, 0, time.FixedZone("test", 3*60*60))
	}
	randomOutputSuffix = func() (string, error) { return "a1b2c3d4e5f6", nil }

	path, err := defaultOutputPath()
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(
		home,
		"qodo-support-bundles",
		"qodo-support-bundle-20260927T071112Z-a1b2c3d4e5f6.tar.gz",
	)
	if path != expected {
		t.Fatalf("got %q want %q", path, expected)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%o", info.Mode().Perm())
	}
}

func TestDefaultOutputPathAvoidsSameSecondCollisions(t *testing.T) {
	oldHome := homeDirectory
	oldTime := currentTime
	oldRandomSuffix := randomOutputSuffix
	t.Cleanup(func() {
		homeDirectory = oldHome
		currentTime = oldTime
		randomOutputSuffix = oldRandomSuffix
	})
	home := t.TempDir()
	homeDirectory = func() (string, error) { return home, nil }
	currentTime = func() time.Time {
		return time.Date(2026, 9, 27, 7, 11, 12, 0, time.UTC)
	}
	suffixes := []string{"000000000001", "000000000002"}
	randomOutputSuffix = func() (string, error) {
		value := suffixes[0]
		suffixes = suffixes[1:]
		return value, nil
	}

	first, err := defaultOutputPath()
	if err != nil {
		t.Fatal(err)
	}
	second, err := defaultOutputPath()
	if err != nil {
		t.Fatal(err)
	}
	if first == second ||
		!strings.Contains(first, "qodo-support-bundle-20260927T071112Z-") ||
		!strings.Contains(second, "qodo-support-bundle-20260927T071112Z-") {
		t.Fatalf("paths are not collision-resistant: %q %q", first, second)
	}
}

func TestDefaultOutputPathRejectsUnusableHome(t *testing.T) {
	oldHome := homeDirectory
	t.Cleanup(func() { homeDirectory = oldHome })
	homeDirectory = func() (string, error) { return "", errors.New("unavailable") }
	if _, err := defaultOutputPath(); err == nil ||
		!strings.Contains(err.Error(), "resolve home directory") {
		t.Fatalf("unexpected error: %v", err)
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

func TestConnectivityFailureIsSummarizedWithoutChangingStatus(t *testing.T) {
	t.Parallel()
	status := 503
	summary := buildSummary(
		time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC),
		collectionStatusComplete,
		kubernetes.Report{},
		nil,
		true,
		&zitadel.Report{
			SchemaVersion: 1,
			Checks: []zitadel.Check{
				{
					Name:       "discovery",
					Status:     zitadel.StatusFailed,
					Reason:     "http_error",
					HTTPStatus: &status,
				},
				{Name: "jwks", Status: zitadel.StatusPassed, HTTPStatus: intPointer(200)},
			},
		},
		"",
	)
	if !strings.Contains(summary, "Collection status: complete") ||
		!strings.Contains(summary, "discovery: failed (http_error)") {
		t.Fatalf("unexpected summary: %s", summary)
	}
}

func TestCollectExitSemanticsForProbeResults(t *testing.T) {
	tests := []struct {
		name           string
		probeOutput    string
		wantExit       int
		wantArtifact   bool
		wantIssueText  string
		extraArguments []string
		metadataLimit  int64
	}{
		{
			name: "diagnostic failure remains complete",
			probeOutput: `{"schema_version":1,"checks":[` +
				`{"name":"configuration","status":"failed",` +
				`"reason":"settings_unavailable"}]}`,
			wantExit:      0,
			wantArtifact:  true,
			metadataLimit: defaultMetadataLimit,
		},
		{
			name:          "invalid report makes bundle partial",
			probeOutput:   `{"schema_version":1,"checks":[]}`,
			wantExit:      3,
			wantIssueText: zitadel.ReasonInvalidResponse,
			metadataLimit: defaultMetadataLimit,
		},
		{
			name: "metadata exhaustion makes bundle partial",
			probeOutput: `{"schema_version":1,"checks":[` +
				`{"name":"configuration","status":"failed",` +
				`"reason":"settings_unavailable"}]}`,
			wantExit:       3,
			wantArtifact:   true,
			wantIssueText:  "aggregate metadata limit reached",
			extraArguments: []string{"--max-metadata-bytes", "1"},
			metadataLimit:  1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			kubectl := fakeKubectl(t, root, test.probeOutput)
			output := filepath.Join(root, "exact-name.tar.gz")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			arguments := []string{
				"collect",
				"--namespace", "qodo",
				"--kubectl", kubectl,
				"--output", output,
				"--check-zitadel",
				"--platform-pod", "platform-0",
				"--platform-container", "platform",
			}
			arguments = append(arguments, test.extraArguments...)
			code := Run(context.Background(), arguments, &stdout, &stderr)
			if code != test.wantExit {
				t.Fatalf(
					"exit=%d stdout=%q stderr=%q",
					code,
					stdout.String(),
					stderr.String(),
				)
			}
			files := readArchive(t, output)
			_, hasArtifact := files["connectivity/zitadel.json"]
			if hasArtifact != test.wantArtifact {
				t.Fatalf("artifact=%v files=%v", hasArtifact, files)
			}
			if test.wantIssueText != "" &&
				!strings.Contains(
					string(files["collection-issues.jsonl"]),
					test.wantIssueText,
				) {
				t.Fatalf("issues=%s", files["collection-issues.jsonl"])
			}
			manifest := string(files["manifest.json"])
			expectedLimit := fmt.Sprintf(
				`"max_metadata_bytes": %d`,
				test.metadataLimit,
			)
			expectedReportLimit := fmt.Sprintf(
				`"metadata_limit_bytes": %d`,
				test.metadataLimit,
			)
			if !strings.Contains(manifest, expectedLimit) ||
				!strings.Contains(manifest, expectedReportLimit) {
				t.Fatalf("manifest omitted metadata limit: %s", manifest)
			}
			expectedStatus := collectionStatusComplete
			if test.wantExit == 3 {
				expectedStatus = collectionStatusPartial
			}
			if !strings.Contains(
				manifest,
				fmt.Sprintf(`"status": %q`, expectedStatus),
			) {
				t.Fatalf("manifest has wrong collection status: %s", manifest)
			}
			if !strings.Contains(string(files["summary.md"]), "Metadata bytes:") {
				t.Fatalf("summary omitted metadata budget: %s", files["summary.md"])
			}
			if !strings.Contains(stdout.String(), output) {
				t.Fatalf("--output was not used exactly: %s", stdout.String())
			}
		})
	}
}

func TestCloseBundleReportsFailureAndSetsFailureExit(t *testing.T) {
	t.Parallel()
	closer := &failingCloser{err: errors.New("remove /sensitive/staging/path")}
	var stderr bytes.Buffer
	exitCode := 3
	closeBundle(closer, &stderr, &exitCode)
	if closer.calls != 1 || exitCode != 1 {
		t.Fatalf("calls=%d exit=%d", closer.calls, exitCode)
	}
	if stderr.String() != "Failed to clean up temporary bundle data.\n" {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestTerminalTextRemovesControlCharacters(t *testing.T) {
	t.Parallel()
	output := terminalText(redact.New(), "value\r\n\x1b[2Jforged")
	if output != "value   [2Jforged" {
		t.Fatalf("unexpected terminal-safe text: %q", output)
	}
}

func intPointer(value int) *int {
	return &value
}

func fakeKubectl(t *testing.T, directory string, probeOutput string) string {
	t.Helper()
	path := filepath.Join(directory, "kubectl")
	script := `#!/bin/sh
case " $* " in
  *" get pods "*)
    printf '%s\n' '{"items":[{"metadata":{"name":"platform-0","namespace":"qodo"},"spec":{"containers":[{"name":"platform"}]},"status":{"phase":"Running","containerStatuses":[{"name":"platform","ready":true,"state":{"running":{}}}]}}]}'
    ;;
  *" get events "*)
    printf '%s\n' '{"items":[]}'
    ;;
  *" logs "*)
    printf '%s\n' '2026-09-27T08:00:00Z ready'
    ;;
  *" get pod "*)
    printf '%s\n' '{"status":{"phase":"Running","containerStatuses":[{"name":"platform","state":{"running":{}}}]}}'
    ;;
  *" exec "*)
    printf '%s\n' '` + strings.ReplaceAll(probeOutput, `'`, `'\''`) + `'
    ;;
  *)
    exit 9
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func readArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = data
	}
	return files
}
