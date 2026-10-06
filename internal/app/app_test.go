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

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/phoenix"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

type failingCloser struct {
	calls int
	err   error
}

type unusedTelemetryForwarder struct{}

func (*unusedTelemetryForwarder) Forward(
	context.Context,
	telemetry.Target,
) (*telemetry.Tunnel, error) {
	return nil, errors.New("unexpected forwarder call")
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

func TestHelpUsesQodoScoutBrandWithoutRenamingExecutable(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	if code := Run(
		context.Background(),
		[]string{"help"},
		&stdout,
		&bytes.Buffer{},
	); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	for _, expected := range []string{
		"Qodo Scout",
		"qodo-support-bundle collect",
		"Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted.",
		"Review the archive before sharing",
		"saved locally",
		"does not upload",
		"--no-progress",
		"--mascot (deprecated; no-op)",
		"--interactive",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q:\n%s", expected, stdout.String())
		}
	}
	for _, legacy := range []string{
		"Qodo Scout never modifies",
		"Collected text is redacted before packaging",
	} {
		if strings.Contains(stdout.String(), legacy) {
			t.Fatalf("help retained verbose security copy %q:\n%s", legacy, stdout.String())
		}
	}
}

func TestCollectionStagesUseApprovedReadOnlyCaptions(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
	})
	redactor := redact.New()

	writeCollectionEvent(renderer, collection.Event{Kind: collection.EventKubernetesStarted})
	writeCollectionProgress(renderer, redactor, kubernetes.Progress{Stage: "discover_namespaces"})
	writeCollectionProgress(renderer, redactor, kubernetes.Progress{
		Stage: "logs_progress", Current: 18, Total: 35,
	})
	writeCollectionEvent(renderer, collection.Event{Kind: collection.EventWorkloadStarted, Total: 1})
	writeCollectionEvent(renderer, collection.Event{Kind: collection.EventPrometheusStarted})
	writeCollectionEvent(renderer, collection.Event{Kind: collection.EventPhoenixStarted})
	writeCollectionEvent(renderer, collection.Event{Kind: collection.EventZitadelStarted})
	writeBundleProgress(renderer, bundle.Progress{Stage: bundle.ProgressPacking})

	for _, expected := range []string{
		"Read-only Kubernetes data",
		"Namespaces",
		"Container logs | 18/35 sources",
		"Workload and service context",
		"Prometheus metrics",
		"Phoenix traces",
		"Zitadel connectivity",
		"Redaction and archive",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("progress missing %q:\n%s", expected, output.String())
		}
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

func TestCollectOmitsUsernameFromResolvedKubectlLog(t *testing.T) {
	root := t.TempDir()
	username := "review-user-canary"
	kubectl := fakeKubectl(t, filepath.Join(root, "Users", username, "bin"), "")
	if !strings.Contains(kubectl, username) {
		t.Fatalf("resolved kubectl path does not include username: %s", kubectl)
	}
	output := filepath.Join(root, "bundle.tar.gz")
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
		},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	logged := stderr.String()
	if !strings.Contains(logged, "[done] kubectl ready") {
		t.Fatalf("missing redacted preflight status: %s", logged)
	}
	if strings.Contains(logged, username) || strings.Contains(logged, kubectl) {
		t.Fatalf("stderr leaked identifying kubectl path: %s", logged)
	}
}

func TestCollectKeepsStdoutStableAndReportsQodoScoutStages(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
		},
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	wantStdout := fmt.Sprintf(
		"Support bundle created: %s\n"+
			"Kubernetes scope: 1/1 namespaces, 1 pods, 1 containers (0 init, 0 ephemeral)\n",
		output,
	)
	if stdout.String() != wantStdout {
		t.Fatalf("stdout changed:\ngot  %q\nwant %q", stdout.String(), wantStdout)
	}
	for _, expected := range []string{
		"[active] Qodo Scout collection",
		"  [active] kubectl ready",
		"  [done] kubectl ready",
		"  [active] Read-only Kubernetes data",
		"  [done] Read-only Kubernetes data | 1/1 namespace",
		"  [active] Workload and service context | 0/1 namespace",
		"  [done] Workload and service context | 1/1 namespace",
		"  [active] Redaction and archive | preparing summary",
		"  [active] Redaction and archive | creating manifest",
		"  [active] Redaction and archive | writing checksums",
		"  [active] Redaction and archive | packing",
		"  [active] Redaction and archive | finalizing",
		"  [done] Redaction and archive",
		"Qodo Scout\n",
		"Bundle created",
		"1 namespace | 1 pod | 1 log source |",
		"[ok] Read-only Kubernetes data",
		"[ok] Workload and service context",
		"[ok] Archive prepared with redaction |",
		"Bundle saved: " + output,
		"[!] Review before sharing",
	} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("stderr missing %q:\n%s", expected, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), kubectl) {
		t.Fatalf("stderr leaked resolved kubectl path: %s", stderr.String())
	}
}

func TestCollectNoProgressPreservesWarningsAndStdout(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--no-progress",
			"--kubectl", kubectl,
			"--output", output,
		},
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Support bundle created: "+output) {
		t.Fatalf("missing stdout result: %q", stdout.String())
	}
	if !strings.Contains(
		stderr.String(),
		"Scope: all application namespaces; Kubernetes system namespaces are excluded.",
	) {
		t.Fatalf("warning/scope output was suppressed: %q", stderr.String())
	}
	for _, routine := range []string{
		"Qodo Scout",
		"Checking cluster access",
		"Using kubectl",
		"Discovering Kubernetes",
		"Workload context",
		"archive",
	} {
		if strings.Contains(stderr.String(), routine) {
			t.Fatalf("--no-progress emitted %q: %s", routine, stderr.String())
		}
	}
}

func TestCollectDeprecatedMascotFlagIsNoOpForNonTTYOutput(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--mascot",
			"--kubectl", kubectl,
			"--output", output,
		},
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	wantStdout := fmt.Sprintf(
		"Support bundle created: %s\n"+
			"Kubernetes scope: 1/1 namespaces, 1 pods, 1 containers (0 init, 0 ephemeral)\n",
		output,
	)
	if stdout.String() != wantStdout {
		t.Fatalf("deprecated --mascot changed stdout:\ngot  %q\nwant %q", stdout.String(), wantStdout)
	}
	if strings.ContainsAny(stderr.String(), "\r\x1b") {
		t.Fatalf("deprecated --mascot changed non-TTY output: %q", stderr.String())
	}
}

func TestCollectInteractiveRejectsNonTTYWithoutTouchingStdout(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{"collect", "--interactive"},
		&stdout,
		&stderr,
	)

	if code != 2 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("interactive gating changed stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--interactive requires an interactive stdin and stderr") {
		t.Fatalf("missing TTY error: %q", stderr.String())
	}
}

func TestCollectHonorsExplicitExcludeSystemNamespacesFalse(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--exclude-system-namespaces=false",
			"--kubectl", kubectl,
			"--output", output,
		},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	manifest := string(readArchive(t, output)["manifest.json"])
	if !strings.Contains(manifest, `"exclude_system_namespaces": false`) {
		t.Fatalf("explicit false was overwritten: %s", manifest)
	}
	if !strings.Contains(manifest, `"all_namespaces": true`) {
		t.Fatalf("missing default all-namespaces scope: %s", manifest)
	}
}

func TestValidDNSNameRejectsEmptyAndOversizedLabels(t *testing.T) {
	t.Parallel()
	oversized := strings.Repeat("a", 64)
	if validDNSName("platform..0", 253) {
		t.Fatal("consecutive dots were accepted")
	}
	if validDNSName(oversized, 253) {
		t.Fatal("label longer than 63 characters was accepted")
	}
	if !validDNSName("platform-0", 253) {
		t.Fatal("valid single-label pod name was rejected")
	}
	if !validDNSName(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63), 253) {
		t.Fatal("valid 63-character labels were rejected")
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

func TestPrometheusFlagCouplingAndNamespaceInference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		enabled    bool
		visited    map[string]bool
		namespaces []string
		all        bool
		namespace  string
		wantNS     string
		wantError  string
	}{
		{
			name:       "single explicit workload namespace is inferred",
			enabled:    true,
			namespaces: []string{"qodo"},
			wantNS:     "qodo",
		},
		{
			name:       "explicit service namespace is independent of workload scope",
			enabled:    true,
			namespaces: []string{"qodo", "zitadel"},
			namespace:  "monitoring",
			wantNS:     "monitoring",
		},
		{
			name:       "multiple namespaces require service namespace",
			enabled:    true,
			namespaces: []string{"qodo", "zitadel"},
			wantError:  "--prometheus-namespace is required when --collect-prometheus uses multiple or all namespaces",
		},
		{
			name:      "all namespaces require service namespace",
			enabled:   true,
			all:       true,
			wantError: "--prometheus-namespace is required when --collect-prometheus uses multiple or all namespaces",
		},
		{
			name:      "target rejected while disabled",
			visited:   map[string]bool{"prometheus-namespace": true},
			namespace: "monitoring",
			wantError: "--prometheus-namespace requires --collect-prometheus",
		},
		{
			name:       "invalid service namespace is rejected",
			enabled:    true,
			namespaces: []string{"qodo"},
			namespace:  "Monitoring",
			wantError:  "--prometheus-namespace must be a Kubernetes DNS label",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			namespace := test.namespace
			err := validatePrometheusFlags(
				test.enabled,
				test.visited,
				test.namespaces,
				test.all,
				&namespace,
			)
			if test.wantError != "" {
				if err == nil || err.Error() != test.wantError {
					t.Fatalf("error=%v want=%q", err, test.wantError)
				}
				return
			}
			if err != nil || namespace != test.wantNS {
				t.Fatalf("namespace=%q error=%v", namespace, err)
			}
		})
	}
}

func TestPhoenixFlagCouplingTraceValidationAndNamespaceInference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		enabled    bool
		visited    map[string]bool
		namespaces []string
		all        bool
		namespace  string
		traceID    string
		wantNS     string
		wantTrace  string
		wantError  string
	}{
		{
			name:       "general mode infers single explicit namespace",
			enabled:    true,
			namespaces: []string{"qodo"},
			wantNS:     "qodo",
		},
		{
			name:       "exact mode normalizes trace id",
			enabled:    true,
			namespaces: []string{"qodo"},
			traceID:    "ABCDEF0123456789ABCDEF0123456789",
			wantNS:     "qodo",
			wantTrace:  "abcdef0123456789abcdef0123456789",
		},
		{
			name:       "multiple namespaces require Phoenix namespace",
			enabled:    true,
			namespaces: []string{"qodo", "zitadel"},
			wantError:  "--phoenix-namespace is required",
		},
		{
			name:      "all namespaces require Phoenix namespace",
			enabled:   true,
			all:       true,
			wantError: "--phoenix-namespace is required",
		},
		{
			name:      "trace id rejected while disabled",
			visited:   map[string]bool{"trace-id": true},
			traceID:   "abcdef0123456789abcdef0123456789",
			wantError: "--trace-id requires --collect-phoenix",
		},
		{
			name:       "trace id has exact hexadecimal shape",
			enabled:    true,
			namespaces: []string{"qodo"},
			traceID:    "not-a-trace-id",
			wantError:  "--trace-id must be exactly 32 hexadecimal characters",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			namespace := test.namespace
			traceID := test.traceID
			err := validatePhoenixFlags(
				test.enabled,
				test.visited,
				test.namespaces,
				test.all,
				&namespace,
				&traceID,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || namespace != test.wantNS || traceID != test.wantTrace {
				t.Fatalf("namespace=%q trace=%q error=%v", namespace, traceID, err)
			}
		})
	}
}

func TestBuildPhoenixConfigUsesGeneralWindowAndExactTrace(t *testing.T) {
	t.Parallel()
	end := time.Date(2026, 9, 29, 14, 15, 16, 0, time.FixedZone("test", 2*60*60))
	general := buildPhoenixConfig(
		"phoenix",
		"customer",
		"/tmp/customer.kubeconfig",
		end,
		45*time.Minute,
		"",
	)
	want := phoenix.DefaultConfig()
	want.Namespace = "phoenix"
	want.Context = "customer"
	want.Kubeconfig = "/tmp/customer.kubeconfig"
	want.End = end.UTC()
	want.Start = want.End.Add(-45 * time.Minute)
	if !reflect.DeepEqual(general, want) || general.TraceID != "" {
		t.Fatalf("general config=%+v want=%+v", general, want)
	}

	exact := buildPhoenixConfig(
		"phoenix",
		"",
		"",
		end,
		time.Hour,
		"ABCDEF0123456789ABCDEF0123456789",
	)
	if exact.TraceID != "abcdef0123456789abcdef0123456789" ||
		!exact.Start.Equal(end.UTC().Add(-time.Hour)) ||
		!exact.End.Equal(end.UTC()) {
		t.Fatalf("unexpected exact config: %+v", exact)
	}
}

func TestConfigureTelemetryForwardersSharesOnlyCompatibleNamespace(t *testing.T) {
	t.Parallel()
	prometheusConfig := prometheus.DefaultConfig()
	prometheusConfig.Namespace = "telemetry"
	prometheusConfig.Context = "customer"
	prometheusConfig.Kubeconfig = "/tmp/kubeconfig"
	phoenixConfig := phoenix.DefaultConfig()
	phoenixConfig.Namespace = "telemetry"
	phoenixConfig.Context = "customer"
	phoenixConfig.Kubeconfig = "/tmp/kubeconfig"
	var calls []telemetry.ForwardConfig
	factory := func(
		_ string,
		config telemetry.ForwardConfig,
	) (telemetry.Forwarder, error) {
		calls = append(calls, config)
		return &unusedTelemetryForwarder{}, nil
	}
	collectors := collection.Collectors{}
	if err := configureTelemetryForwarders(
		&collectors,
		"/opt/bin/kubectl",
		&prometheusConfig,
		&phoenixConfig,
		factory,
	); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 ||
		collectors.Forwarder == nil ||
		collectors.PrometheusForwarder != nil ||
		collectors.PhoenixForwarder != nil ||
		calls[0].Namespace != "telemetry" {
		t.Fatalf("compatible sources did not share one forwarder: calls=%+v collectors=%+v", calls, collectors)
	}

	calls = nil
	collectors = collection.Collectors{}
	phoenixConfig.Namespace = "phoenix"
	if err := configureTelemetryForwarders(
		&collectors,
		"/opt/bin/kubectl",
		&prometheusConfig,
		&phoenixConfig,
		factory,
	); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 ||
		collectors.Forwarder != nil ||
		collectors.PrometheusForwarder == nil ||
		collectors.PhoenixForwarder == nil ||
		calls[0].Namespace != "telemetry" ||
		calls[1].Namespace != "phoenix" {
		t.Fatalf("different namespaces did not receive isolated forwarders: calls=%+v collectors=%+v", calls, collectors)
	}
}

func TestCollectRejectsInvalidPrometheusFlagCombinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		arguments []string
		message   string
	}{
		{
			name: "target while disabled",
			arguments: []string{
				"collect",
				"--namespace", "qodo",
				"--prometheus-namespace", "monitoring",
			},
			message: "--prometheus-namespace requires --collect-prometheus",
		},
		{
			name: "multiple namespaces without target",
			arguments: []string{
				"collect",
				"--namespaces", "qodo,zitadel",
				"--collect-prometheus",
			},
			message: "--prometheus-namespace is required when --collect-prometheus uses multiple or all namespaces",
		},
		{
			name: "all namespaces without target",
			arguments: []string{
				"collect",
				"--all-namespaces",
				"--collect-prometheus",
			},
			message: "--prometheus-namespace is required when --collect-prometheus uses multiple or all namespaces",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := Run(
				context.Background(),
				test.arguments,
				&bytes.Buffer{},
				&stderr,
			)
			if code != 2 || strings.TrimSpace(stderr.String()) != test.message {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestCollectRejectsInvalidPhoenixFlagCombinationsAndWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		arguments []string
		message   string
	}{
		{
			name: "target while disabled",
			arguments: []string{
				"collect",
				"--namespace", "qodo",
				"--phoenix-namespace", "telemetry",
			},
			message: "--phoenix-namespace requires --collect-phoenix",
		},
		{
			name: "trace while disabled",
			arguments: []string{
				"collect",
				"--namespace", "qodo",
				"--trace-id", "abcdef0123456789abcdef0123456789",
			},
			message: "--trace-id requires --collect-phoenix",
		},
		{
			name: "invalid trace shape",
			arguments: []string{
				"collect",
				"--namespace", "qodo",
				"--collect-phoenix",
				"--trace-id", "abc",
			},
			message: "--trace-id must be exactly 32 hexadecimal characters",
		},
		{
			name: "window exceeds maximum",
			arguments: []string{
				"collect",
				"--namespace", "qodo",
				"--collect-phoenix",
				"--since", "25h",
			},
			message: "--since must not exceed 24h0m0s when --collect-phoenix is enabled",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := Run(
				context.Background(),
				test.arguments,
				&bytes.Buffer{},
				&stderr,
			)
			if code != 2 || strings.TrimSpace(stderr.String()) != test.message {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestBuildPrometheusConfigUsesDefaultsBoundsAndSeparateScope(t *testing.T) {
	t.Parallel()
	end := time.Date(2026, 9, 29, 14, 15, 16, 0, time.FixedZone("test", 2*60*60))
	namespaces := []string{"qodo", "zitadel"}
	got := buildPrometheusConfig(
		"monitoring",
		namespaces,
		false,
		false,
		"customer",
		"/tmp/customer.kubeconfig",
		end,
		45*time.Minute,
	)
	namespaces[0] = "mutated"

	want := prometheus.DefaultConfig()
	want.Namespace = "monitoring"
	want.Namespaces = []string{"qodo", "zitadel"}
	want.Context = "customer"
	want.Kubeconfig = "/tmp/customer.kubeconfig"
	want.End = end.UTC()
	want.Start = want.End.Add(-45 * time.Minute)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config=%+v want=%+v", got, want)
	}
	if got.Namespace == got.Namespaces[0] {
		t.Fatalf("service namespace was conflated with workload scope: %+v", got)
	}

	all := buildPrometheusConfig(
		"monitoring",
		nil,
		true,
		true,
		"",
		"",
		end,
		time.Hour,
	)
	if !all.AllNamespaces ||
		!all.ExcludeSystemNamespaces ||
		len(all.Namespaces) != 0 {
		t.Fatalf("all-namespace scope was broadened incorrectly: %+v", all)
	}
}

func TestBuildPrometheusForwarderUsesResolvedBinaryAndSafeConfig(t *testing.T) {
	t.Parallel()
	config := prometheus.DefaultConfig()
	config.Namespace = "monitoring"
	config.Context = "customer"
	config.Kubeconfig = "/tmp/customer.kubeconfig"
	resolvedKubectl := "/opt/bin/kubectl"
	var gotBinary string
	var gotConfig telemetry.ForwardConfig
	expectedForwarder := &unusedTelemetryForwarder{}

	gotForwarder, err := buildPrometheusForwarder(
		resolvedKubectl,
		config,
		func(
			binary string,
			forwardConfig telemetry.ForwardConfig,
		) (telemetry.Forwarder, error) {
			gotBinary = binary
			gotConfig = forwardConfig
			return expectedForwarder, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantConfig := telemetry.ForwardConfig{
		Namespace:        "monitoring",
		Context:          "customer",
		Kubeconfig:       "/tmp/customer.kubeconfig",
		ReadinessTimeout: prometheus.DefaultReadinessTimeout,
		MaxOutputBytes:   defaultForwardOutputLimit,
	}
	if gotForwarder != expectedForwarder ||
		gotBinary != resolvedKubectl ||
		!reflect.DeepEqual(gotConfig, wantConfig) {
		t.Fatalf(
			"forwarder=%T binary=%q config=%+v",
			gotForwarder,
			gotBinary,
			gotConfig,
		)
	}
}

func TestCollectPrometheusUsesSingleCapturedTimeAndRequestedScope(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	capturedAt := time.Date(
		2026,
		9,
		29,
		14,
		15,
		16,
		0,
		time.FixedZone("test", 2*60*60),
	)
	oldTime := currentTime
	timeCalls := 0
	currentTime = func() time.Time {
		timeCalls++
		return capturedAt
	}
	t.Cleanup(func() { currentTime = oldTime })

	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--collect-prometheus",
			"--prometheus-namespace", "monitoring",
			"--since", "45m",
			"--kubectl", kubectl,
			"--output", output,
		},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 3 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if timeCalls != 1 {
		t.Fatalf("current time sampled %d times", timeCalls)
	}
	manifest := string(readArchive(t, output)["manifest.json"])
	for _, expected := range []string{
		`"enabled": true`,
		`"namespace": "monitoring"`,
		`"namespaces": [`,
		`"qodo"`,
		`"all_namespaces": false`,
		`"configured_start": "2026-09-29T11:30:16Z"`,
		`"configured_end": "2026-09-29T12:15:16Z"`,
	} {
		if !strings.Contains(manifest, expected) {
			t.Fatalf("manifest missing %q: %s", expected, manifest)
		}
	}
	if !strings.Contains(stderr.String(), "[active] Prometheus metrics") ||
		!strings.Contains(stderr.String(), "[failed] Prometheus metrics | unavailable") {
		t.Fatalf("missing Prometheus progress: %s", stderr.String())
	}
}

func TestCollectLeavesPrometheusDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
		},
		&bytes.Buffer{},
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	manifest := string(readArchive(t, output)["manifest.json"])
	if !strings.Contains(manifest, `"prometheus": {`) ||
		!strings.Contains(manifest, `"enabled": false`) {
		t.Fatalf("Prometheus was not disabled in manifest: %s", manifest)
	}
	if !strings.Contains(manifest, `"phoenix": {`) {
		t.Fatalf("Phoenix was not disabled in manifest: %s", manifest)
	}
	if strings.Contains(stderr.String(), "Prometheus telemetry") {
		t.Fatalf("disabled Prometheus emitted progress: %s", stderr.String())
	}
}

func TestTelemetryProgressDoesNotRenderEventReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind collection.EventKind
		want string
	}{
		{collection.EventPrometheusStarted, "  [active] Prometheus metrics\n"},
		{collection.EventPrometheusComplete, "  [done] Prometheus metrics\n"},
		{
			collection.EventPrometheusPartial,
			"  [warning] Prometheus metrics | partial\n",
		},
		{
			collection.EventPrometheusUnavailable,
			"  [failed] Prometheus metrics | unavailable\n",
		},
		{collection.EventPhoenixStarted, "  [active] Phoenix traces\n"},
		{collection.EventPhoenixComplete, "  [done] Phoenix traces\n"},
		{
			collection.EventPhoenixPartial,
			"  [warning] Phoenix traces | partial\n",
		},
		{
			collection.EventPhoenixUnavailable,
			"  [failed] Phoenix traces | unavailable\n",
		},
		{
			collection.EventZitadelUnavailable,
			"  [failed] Zitadel connectivity | unavailable\n",
		},
		{
			collection.EventWorkloadUnavailable,
			"  [failed] Workload and service context | unavailable\n",
		},
	}
	for _, test := range tests {
		var output bytes.Buffer
		renderer := newProgressRenderer(progressRendererOptions{
			Writer:  &output,
			Enabled: true,
		})
		writeCollectionEvent(renderer, collection.Event{
			Kind:   test.kind,
			Reason: "password=private-progress-canary",
		})
		if output.String() != test.want ||
			strings.Contains(output.String(), "private-progress-canary") {
			t.Fatalf("kind=%s output=%q", test.kind, output.String())
		}
	}
}

func TestKubernetesChildStagesFinishWithObservedOutcomes(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
	})
	sanitizer := redact.New()

	writeCollectionProgress(renderer, sanitizer, kubernetes.Progress{
		Stage: "scan_complete", Current: 1, Total: 2,
	})
	writeCollectionProgress(renderer, sanitizer, kubernetes.Progress{
		Stage: "collect_logs", Total: 0,
	})
	writeCollectionProgress(renderer, sanitizer, kubernetes.Progress{
		Stage: "logs_complete", Current: 1, Total: 2,
	})
	renderer.ResolvePending("kubernetes.logs")

	const want = "" +
		"    [warning] Namespace scan | 1/2 namespaces | partial\n" +
		"    [done] Container logs | no sources\n" +
		"    [warning] Container logs | 1/2 sources | partial\n"
	if output.String() != want {
		t.Fatalf("child outcome transcript mismatch:\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestProgressArchivePathMasksHomeDirectory(t *testing.T) {
	oldHome := homeDirectory
	homeDirectory = func() (string, error) { return "/Users/private-account", nil }
	t.Cleanup(func() { homeDirectory = oldHome })

	got := progressArchivePath(
		redact.New(),
		"/Users/private-account/qodo-support-bundles/bundle.tar.gz",
	)
	if got != "~/qodo-support-bundles/bundle.tar.gz" {
		t.Fatalf("home directory was exposed in progress path: %q", got)
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

func TestCollectDefaultOutputErrorsOmitHomePath(t *testing.T) {
	const username = "review-home-canary"
	root := t.TempDir()
	home := filepath.Join(root, "Users", username)
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHome := homeDirectory
	t.Cleanup(func() { homeDirectory = oldHome })
	homeDirectory = func() (string, error) { return home, nil }

	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"collect", "--namespace", "qodo"},
		&bytes.Buffer{},
		&stderr,
	)
	logged := stderr.String()
	if code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, logged)
	}
	if strings.Contains(logged, username) || strings.Contains(logged, home) {
		t.Fatalf("stderr leaked default output home path: %s", logged)
	}
	if !strings.Contains(logged, defaultOutputCreateDirectory) {
		t.Fatalf("missing default-output operation category: %s", logged)
	}
	if !strings.Contains(logged, "mkdir") && !strings.Contains(logged, "not a directory") {
		t.Fatalf("missing path-free filesystem cause: %s", logged)
	}
}

func TestCollectDefaultBundleNewErrorsOmitHomePath(t *testing.T) {
	const username = "review-new-canary"
	root := t.TempDir()
	home := filepath.Join(root, "Users", username)
	if err := os.MkdirAll(filepath.Join(home, "qodo-support-bundles"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldHome := homeDirectory
	oldTime := currentTime
	oldSuffix := randomOutputSuffix
	t.Cleanup(func() {
		homeDirectory = oldHome
		currentTime = oldTime
		randomOutputSuffix = oldSuffix
	})
	homeDirectory = func() (string, error) { return home, nil }
	currentTime = func() time.Time {
		return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	}
	randomOutputSuffix = func() (string, error) { return "aabbccddeeff", nil }
	path, err := defaultOutputPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("already-exists"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"collect", "--namespace", "qodo"},
		&bytes.Buffer{},
		&stderr,
	)
	logged := stderr.String()
	if code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, logged)
	}
	if strings.Contains(logged, username) || strings.Contains(logged, home) || strings.Contains(logged, path) {
		t.Fatalf("stderr leaked default bundle path: %s", logged)
	}
	if !strings.Contains(logged, "output already exists") {
		t.Fatalf("missing path-free constructor category: %s", logged)
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
	summary := collection.BuildSummary(
		time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC),
		collection.CoverageComplete.String(),
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
			expectedStatus := collection.CoverageComplete.String()
			if test.wantExit == 3 {
				expectedStatus = collection.CoveragePartial.String()
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
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case " $* " in
  *" config current-context "*)
    printf '%s\n' 'customer'
    ;;
  *" config view --minify --output=json "*)
    printf '%s\n' '{"users":[{"name":"customer","user":{"token":"REDACTED"}}]}'
    ;;
  *" get namespaces "*)
    printf '%s\n' '{"items":[{"metadata":{"name":"qodo"}},{"metadata":{"name":"kube-system"}}]}'
    ;;
  *" get pods "*)
    printf '%s\n' '{"items":[{"metadata":{"name":"platform-0","namespace":"qodo"},"spec":{"containers":[{"name":"platform"}]},"status":{"phase":"Running","containerStatuses":[{"name":"platform","ready":true,"state":{"running":{}}}]}}]}'
    ;;
  *" get events "*)
    printf '%s\n' '{"items":[]}'
    ;;
  *"/deployments?limit=101"*)
    printf '%s\n' '{"kind":"DeploymentList","items":[]}'
    ;;
  *"/statefulsets?limit=101"*)
    printf '%s\n' '{"kind":"StatefulSetList","items":[]}'
    ;;
  *"/daemonsets?limit=101"*)
    printf '%s\n' '{"kind":"DaemonSetList","items":[]}'
    ;;
  *"/cronjobs?limit=101"*)
    printf '%s\n' '{"kind":"CronJobList","items":[]}'
    ;;
  *"/jobs?limit=101"*)
    printf '%s\n' '{"kind":"JobList","items":[]}'
    ;;
  *"/services?limit=101"*)
    printf '%s\n' '{"kind":"ServiceList","items":[]}'
    ;;
  *"/endpointslices?limit=101"*)
    printf '%s\n' '{"kind":"EndpointSliceList","items":[]}'
    ;;
  *"/horizontalpodautoscalers?limit=101"*)
    printf '%s\n' '{"kind":"HorizontalPodAutoscalerList","items":[]}'
    ;;
  *"/persistentvolumeclaims?limit=101"*)
    printf '%s\n' '{"kind":"PersistentVolumeClaimList","items":[]}'
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
