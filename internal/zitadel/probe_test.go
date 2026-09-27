package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/kubernetes"
)

type runnerCall struct {
	maxBytes  int64
	arguments []string
	deadline  time.Time
}

type fakeRunner struct {
	calls []runnerCall
	run   func(context.Context, int64, []string) (kubernetes.CommandResult, error)
}

func (runner *fakeRunner) Run(
	ctx context.Context,
	maxBytes int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	deadline, _ := ctx.Deadline()
	runner.calls = append(runner.calls, runnerCall{
		maxBytes:  maxBytes,
		arguments: append([]string(nil), arguments...),
		deadline:  deadline,
	})
	return runner.run(ctx, maxBytes, arguments)
}

func TestCollectUsesBoundedArgumentArrayAndValidatesTarget(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(
			_ context.Context,
			_ int64,
			arguments []string,
		) (kubernetes.CommandResult, error) {
			if contains(arguments, "get") {
				return kubernetes.CommandResult{Stdout: []byte(`{
				  "status":{
				    "phase":"Running",
				    "containerStatuses":[
				      {"name":"platform","state":{"running":{"startedAt":"now"}}}
				    ]
				  }
				}`)}, nil
			}
			return kubernetes.CommandResult{Stdout: validReport()}, nil
		},
	}
	outcome := Collect(context.Background(), Config{
		Namespace:    "qodo",
		Pod:          "platform-0",
		Container:    "platform",
		Context:      "customer",
		Kubeconfig:   "/tmp/kube config",
		QueryTimeout: 2 * time.Second,
		ProbeTimeout: 5 * time.Second,
	}, runner)
	if outcome.Reason != "" || outcome.Report == nil {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls=%d", len(runner.calls))
	}
	execCall := runner.calls[1]
	if execCall.maxBytes != MaxOutputBytes {
		t.Fatalf("output limit=%d", execCall.maxBytes)
	}
	expectedPrefix := []string{
		"--kubeconfig", "/tmp/kube config",
		"--context", "customer",
		"exec", "--namespace", "qodo", "pod/platform-0",
		"--container", "platform", "--", "python", "-B", "-c",
	}
	if !reflect.DeepEqual(execCall.arguments[:len(expectedPrefix)], expectedPrefix) {
		t.Fatalf("unexpected argv: %#v", execCall.arguments)
	}
	if execCall.arguments[len(expectedPrefix)] != Source {
		t.Fatal("embedded source was not passed as one argument")
	}
	if strings.Contains(strings.Join(execCall.arguments[:len(expectedPrefix)], " "), " sh ") {
		t.Fatalf("shell appeared in argv: %#v", execCall.arguments)
	}
	if time.Until(execCall.deadline) > 5*time.Second {
		t.Fatalf("probe deadline was not bounded: %s", execCall.deadline)
	}
}

func TestCollectAcceptsLargePodMetadataBeforeBoundedProbeExec(t *testing.T) {
	t.Parallel()
	irrelevant := strings.Repeat("x", int(MaxOutputBytes)+4096)
	podData := []byte(
		`{"metadata":{"annotations":{"irrelevant":"` + irrelevant +
			`"}},"status":{"phase":"Running","containerStatuses":[` +
			`{"name":"platform","state":{"running":{}}}]}}`,
	)
	if int64(len(podData)) <= MaxOutputBytes {
		t.Fatal("test pod did not exceed the probe output cap")
	}
	call := 0
	runner := &fakeRunner{
		run: func(
			_ context.Context,
			_ int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			call++
			if call == 1 {
				return kubernetes.CommandResult{Stdout: podData}, nil
			}
			return kubernetes.CommandResult{Stdout: validReport()}, nil
		},
	}

	outcome := Collect(context.Background(), testConfig(), runner)

	if outcome.Reason != "" || outcome.Report == nil || len(runner.calls) != 2 {
		t.Fatalf("outcome=%+v calls=%d", outcome, len(runner.calls))
	}
	if runner.calls[0].maxBytes != MaxTargetPodBytes {
		t.Fatalf("target query limit=%d", runner.calls[0].maxBytes)
	}
	if runner.calls[1].maxBytes != MaxOutputBytes {
		t.Fatalf("probe output limit=%d", runner.calls[1].maxBytes)
	}
}

func TestCollectRejectsNonRunningTargetsBeforeExec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		pod    string
		reason string
	}{
		{
			name:   "pod pending",
			pod:    `{"status":{"phase":"Pending"}}`,
			reason: ReasonPodNotRunning,
		},
		{
			name: "container waiting",
			pod: `{"status":{"phase":"Running","containerStatuses":[` +
				`{"name":"platform","state":{"waiting":{}}}]}}`,
			reason: ReasonContainerNotRunning,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &fakeRunner{
				run: func(
					_ context.Context,
					_ int64,
					_ []string,
				) (kubernetes.CommandResult, error) {
					return kubernetes.CommandResult{Stdout: []byte(test.pod)}, nil
				},
			}
			outcome := Collect(context.Background(), testConfig(), runner)
			if outcome.Reason != test.reason || len(runner.calls) != 1 {
				t.Fatalf("outcome=%+v calls=%d", outcome, len(runner.calls))
			}
		})
	}
}

func TestCollectCategorizesKubectlFailuresWithoutStderr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		stderr string
		reason string
	}{
		{
			name:   "forbidden",
			stderr: "Error from server (Forbidden): token=private-canary",
			reason: ReasonForbidden,
		},
		{
			name:   "unauthorized",
			stderr: "You must be logged in (Unauthorized): private-canary",
			reason: ReasonUnauthorized,
		},
		{
			name:   "not found",
			stderr: `Error from server (NotFound): pods "private-canary" not found`,
			reason: ReasonNotFound,
		},
		{
			name:   "TLS error",
			stderr: "x509: certificate signed by unknown authority private-canary",
			reason: ReasonTLSError,
		},
		{
			name:   "connection failed",
			stderr: "Unable to connect to the server: connection refused private-canary",
			reason: ReasonConnectionFailed,
		},
		{
			name:   "generic kubectl error",
			stderr: "unexpected private-canary detail",
			reason: ReasonKubectlError,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &fakeRunner{
				run: func(
					_ context.Context,
					_ int64,
					_ []string,
				) (kubernetes.CommandResult, error) {
					return kubernetes.CommandResult{
						Stderr: []byte(test.stderr),
					}, errors.New("private exception canary")
				},
			}
			outcome := Collect(context.Background(), testConfig(), runner)
			if outcome.Reason != test.reason ||
				strings.Contains(outcome.Reason, "canary") {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
	}
}

func TestCollectCategorizesTargetOutputFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result kubernetes.CommandResult
		reason string
	}{
		{
			name:   "output limit",
			result: kubernetes.CommandResult{Truncated: true},
			reason: ReasonPodOutputLimit,
		},
		{
			name:   "malformed JSON",
			result: kubernetes.CommandResult{Stdout: []byte("{")},
			reason: ReasonPodInvalidResponse,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &fakeRunner{
				run: func(
					_ context.Context,
					_ int64,
					_ []string,
				) (kubernetes.CommandResult, error) {
					return test.result, nil
				},
			}
			if outcome := Collect(
				context.Background(),
				testConfig(),
				runner,
			); outcome.Reason != test.reason {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
	}
}

func TestCollectCategorizesExecFailuresWithoutStderr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		stderr string
		reason string
	}{
		{
			name:   "forbidden",
			stderr: "pods/exec is forbidden: private-canary",
			reason: ReasonForbidden,
		},
		{
			name:   "unauthorized",
			stderr: "Unauthorized private-canary",
			reason: ReasonUnauthorized,
		},
		{
			name:   "not found",
			stderr: "Error from server (NotFound): private-canary",
			reason: ReasonNotFound,
		},
		{
			name:   "TLS error",
			stderr: "certificate verify failed private-canary",
			reason: ReasonTLSError,
		},
		{
			name:   "connection failed",
			stderr: "dial tcp: connection refused private-canary",
			reason: ReasonConnectionFailed,
		},
		{
			name:   "generic exec error",
			stderr: "command terminated with exit code 1 private-canary",
			reason: ReasonExecError,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			call := 0
			runner := &fakeRunner{
				run: func(
					_ context.Context,
					_ int64,
					_ []string,
				) (kubernetes.CommandResult, error) {
					call++
					if call == 1 {
						return runningPod(), nil
					}
					return kubernetes.CommandResult{
						Stderr: []byte(test.stderr),
					}, errors.New("private exception canary")
				},
			}
			outcome := Collect(context.Background(), testConfig(), runner)
			if outcome.Reason != test.reason ||
				strings.Contains(outcome.Reason, "canary") {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
	}
}

func TestCollectCategorizesProbeOutputAndSchemaFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result kubernetes.CommandResult
		err    error
		reason string
	}{
		{
			name:   "output limit",
			result: kubernetes.CommandResult{Truncated: true},
			reason: ReasonOutputLimit,
		},
		{
			name:   "malformed",
			result: kubernetes.CommandResult{Stdout: []byte(`{"schema_version":1}`)},
			reason: ReasonInvalidResponse,
		},
		{
			name: "unknown reason",
			result: kubernetes.CommandResult{Stdout: []byte(
				`{"schema_version":1,"issuer":"https://id.example",` +
					`"checks":[{"name":"discovery","status":"failed","reason":"secret"},` +
					`{"name":"jwks","status":"passed","reason":"","http_status":200}]}`,
			)},
			reason: ReasonInvalidResponse,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			call := 0
			runner := &fakeRunner{
				run: func(
					_ context.Context,
					_ int64,
					_ []string,
				) (kubernetes.CommandResult, error) {
					call++
					if call == 1 {
						return runningPod(), nil
					}
					return test.result, test.err
				},
			}
			outcome := Collect(context.Background(), testConfig(), runner)
			if outcome.Reason != test.reason || outcome.Data != nil {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
	}
}

func TestCollectEnforcesProbeTimeout(t *testing.T) {
	t.Parallel()
	call := 0
	runner := &fakeRunner{
		run: func(
			ctx context.Context,
			_ int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			call++
			if call == 1 {
				return runningPod(), nil
			}
			<-ctx.Done()
			return kubernetes.CommandResult{
				Stderr: []byte("private timeout detail"),
			}, ctx.Err()
		},
	}
	config := testConfig()
	config.ProbeTimeout = 20 * time.Millisecond
	started := time.Now()
	outcome := Collect(context.Background(), config, runner)
	if outcome.Reason != ReasonExecTimeout {
		t.Fatalf("outcome=%+v", outcome)
	}
	if time.Since(started) > time.Second {
		t.Fatal("probe timeout was not enforced")
	}
}

func TestCollectRecognizesInternalProbeTimeoutSentinel(t *testing.T) {
	t.Parallel()
	call := 0
	runner := &fakeRunner{
		run: func(
			_ context.Context,
			_ int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			call++
			if call == 1 {
				return runningPod(), nil
			}
			return kubernetes.CommandResult{
				Stdout: []byte(`{"schema_version":1,"reason":"exec_timeout"}`),
				Stderr: []byte("private exception canary"),
			}, errors.New("command exited unexpectedly")
		},
	}

	outcome := Collect(context.Background(), testConfig(), runner)

	if outcome.Reason != ReasonExecTimeout ||
		strings.Contains(outcome.Reason, "canary") {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestValidIssuerRequiresHTTPS(t *testing.T) {
	t.Parallel()
	if validIssuer("http://id.example") {
		t.Fatal("HTTP issuer was accepted")
	}
	if !validIssuer("https://id.example") {
		t.Fatal("HTTPS issuer was rejected")
	}
}

func TestValidDiagnosticFailuresProduceArtifact(t *testing.T) {
	t.Parallel()
	status := 503
	data, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"issuer":         "https://id.example",
		"checks": []any{
			map[string]any{
				"name": "discovery", "status": StatusFailed,
				"reason": "http_error", "http_status": status,
			},
			map[string]any{
				"name": "jwks", "status": StatusPassed,
				"reason": "", "http_status": 200,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := 0
	runner := &fakeRunner{
		run: func(
			_ context.Context,
			_ int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			call++
			if call == 1 {
				return runningPod(), nil
			}
			return kubernetes.CommandResult{Stdout: data}, nil
		},
	}
	outcome := Collect(context.Background(), testConfig(), runner)
	if outcome.Reason != "" ||
		outcome.Report == nil ||
		outcome.Report.FailedChecks() != 1 ||
		!strings.Contains(string(outcome.Data), `"pod": "platform-0"`) {
		t.Fatalf("unexpected outcome: %+v data=%s", outcome, outcome.Data)
	}
}

func testConfig() Config {
	return Config{
		Namespace:    "qodo",
		Pod:          "platform-0",
		Container:    "platform",
		QueryTimeout: time.Second,
		ProbeTimeout: 3 * time.Second,
	}
}

func runningPod() kubernetes.CommandResult {
	return kubernetes.CommandResult{Stdout: []byte(`{
	  "status":{
	    "phase":"Running",
	    "containerStatuses":[
	      {"name":"platform","state":{"running":{}}}
	    ]
	  }
	}`)}
}

func validReport() []byte {
	return []byte(`{
	  "schema_version":1,
	  "issuer":"https://id.example",
	  "checks":[
	    {"name":"discovery","status":"passed","reason":"","http_status":200},
	    {"name":"jwks","status":"passed","reason":"","http_status":200}
	  ]
	}`)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
