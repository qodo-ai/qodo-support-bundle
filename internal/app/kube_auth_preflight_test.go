package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
)

func TestResolveSelectedKubeContextUsesDiscoveryKubeconfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		kubeconfig string
		want       []string
	}{
		{
			name:       "explicit kubeconfig",
			kubeconfig: "/private/custom-kubeconfig",
			want: []string{
				"--kubeconfig", "/private/custom-kubeconfig",
				"config", "current-context",
			},
		},
		{
			name: "default merged KUBECONFIG",
			want: []string{"config", "current-context"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
				Stdout: []byte("customer\n"),
			}}}
			discovery := kubernetesWizardDiscovery{
				Runner:     runner,
				Kubeconfig: test.kubeconfig,
			}

			selected, err := resolveSelectedKubeContext(
				context.Background(),
				discovery,
				"",
			)
			if err != nil || selected != "customer" {
				t.Fatalf("selected=%q err=%v", selected, err)
			}
			if !reflect.DeepEqual(runner.calls, [][]string{test.want}) {
				t.Fatalf("calls=%q want=%q", runner.calls, [][]string{test.want})
			}
		})
	}
}

func TestAuthenticationHelperPreflightRejectsMissingBareHelper(t *testing.T) {
	t.Parallel()
	const (
		contextName = "customer"
		helper      = "company-kube-auth"
	)
	runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
		Stdout: []byte(`{
			"users":[{
				"name":"customer",
				"user":{
					"token":"raw-token-secret",
					"exec":{
						"command":"company-kube-auth",
						"args":["--token","raw-arg-secret"],
						"env":[{"name":"PASSWORD","value":"raw-env-secret"}]
					}
				}
			}]
		}`),
	}}}
	lookup := func(command string) (string, error) {
		if command != helper {
			t.Fatalf("lookup command=%q", command)
		}
		return "", errors.New("not found on PATH")
	}

	err := checkAuthenticationHelper(
		context.Background(),
		runner,
		"/tmp/merged-kubeconfig",
		contextName,
		lookup,
	)

	var unavailable *kubernetes.AuthenticationHelperUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error=%T %v", err, err)
	}
	if unavailable.Command != helper {
		t.Fatalf("helper=%q", unavailable.Command)
	}
	if strings.Contains(err.Error(), "raw-token-secret") ||
		strings.Contains(err.Error(), "raw-arg-secret") ||
		strings.Contains(err.Error(), "raw-env-secret") {
		t.Fatalf("error leaked kubeconfig secrets: %v", err)
	}
	wantCall := []string{
		"--kubeconfig", "/tmp/merged-kubeconfig",
		"--context", contextName,
		"config", "view", "--minify", "--output=json",
	}
	if !reflect.DeepEqual(runner.calls, [][]string{wantCall}) {
		t.Fatalf("kubectl calls=%q want=%q", runner.calls, [][]string{wantCall})
	}
}

func TestAuthenticationHelperPreflightRejectsMissingAbsolutePath(t *testing.T) {
	t.Parallel()
	const helper = "/opt/company/bin/kube-auth"
	runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
		Stdout: []byte(`{"users":[{"user":{"exec":{"command":"` + helper + `"}}}]}`),
	}}}
	lookup := func(command string) (string, error) {
		if command != helper {
			t.Fatalf("lookup command=%q", command)
		}
		return "", os.ErrNotExist
	}

	err := checkAuthenticationHelper(
		context.Background(),
		runner,
		"",
		"customer",
		lookup,
	)

	var unavailable *kubernetes.AuthenticationHelperUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Command != helper {
		t.Fatalf("error=%T %v", err, err)
	}
}

func TestAuthenticationHelperPreflightUsesNativeLookupForWindowsPATHEXT(
	t *testing.T,
) {
	t.Parallel()
	runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
		Stdout: []byte(`{"users":[{"user":{"exec":{"command":"company-kube-auth"}}}]}`),
	}}}
	lookup := func(command string) (string, error) {
		if command != "company-kube-auth" {
			t.Fatalf("lookup command=%q", command)
		}
		return `C:\Tools\company-kube-auth.EXE`, nil
	}

	err := checkAuthenticationHelper(
		context.Background(),
		runner,
		"",
		"customer",
		lookup,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationHelperPreflightAllowsNonExecCredentials(t *testing.T) {
	t.Parallel()
	for _, user := range []string{
		`{"token":"raw-token-secret"}`,
		`{"client-certificate-data":"raw-cert-secret","client-key-data":"raw-key-secret"}`,
	} {
		runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
			Stdout: []byte(`{"users":[{"user":` + user + `}]}`),
		}}}
		lookupCalled := false
		err := checkAuthenticationHelper(
			context.Background(),
			runner,
			"",
			"customer",
			func(string) (string, error) {
				lookupCalled = true
				return "", errors.New("unexpected lookup")
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if lookupCalled {
			t.Fatal("non-exec credentials triggered executable lookup")
		}
	}
}

func TestAuthenticationHelperPreflightRejectsMalformedOutputSafely(t *testing.T) {
	t.Parallel()
	const secret = "raw-token-secret"
	runner := &wizardRunnerStub{results: []kubernetes.CommandResult{{
		Stdout: []byte(`{"users":[{"user":{"token":"` + secret + `"}}]`),
	}}}

	err := checkAuthenticationHelper(
		context.Background(),
		runner,
		"",
		"customer",
		func(string) (string, error) {
			return "", errors.New("unexpected lookup")
		},
	)

	if err == nil || !strings.Contains(err.Error(), "unable to inspect selected kubeconfig context") {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked malformed config: %v", err)
	}
}

func TestAuthenticationHelperGuidanceIsStableAndTerminalSafe(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	writeAuthenticationHelperGuidance(
		&output,
		&kubernetes.AuthenticationHelperUnavailableError{
			Command: "arbitrary-provider-auth-command\x1b[2J",
		},
		"customer\r\nforged",
		"qodo\x1b[31m",
	)

	got := output.String()
	want := `Kubernetes authentication is unavailable

Context: customer  forged

Configure authentication for this context, then verify:

kubectl --context <context> get pods --namespace <namespace>

Rerun Qodo Scout after kubectl succeeds.
`
	if got != want {
		t.Fatalf("guidance:\ngot  %q\nwant %q", got, want)
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\r") {
		t.Fatalf("guidance retained terminal controls: %q", got)
	}
	for _, forbidden := range []string{
		"arbitrary-provider-auth-command",
		"authentication helper",
		"Required command",
		"external authentication command",
		"administrator",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("guidance retained %q: %q", forbidden, got)
		}
	}
}

func TestAuthenticationHelperGuidanceDoesNotMakeShellSyntaxPasteable(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	writeAuthenticationHelperGuidance(
		&output,
		&kubernetes.AuthenticationHelperUnavailableError{
			Command: "company-kube-auth",
		},
		"customer;$(touch injected)",
		"qodo",
	)

	got := output.String()
	if !strings.Contains(got, "Context: customer;$(touch injected)") {
		t.Fatalf("context identity was hidden: %q", got)
	}
	if !strings.Contains(
		got,
		"kubectl --context <context> get pods --namespace qodo",
	) {
		t.Fatalf("unsafe command did not use a placeholder: %q", got)
	}
	if strings.Contains(
		got,
		"kubectl --context customer;$(touch injected)",
	) {
		t.Fatalf("shell syntax remained pasteable: %q", got)
	}
}

func TestRunInteractiveWizardChecksAuthBeforeNamespaceDiscovery(t *testing.T) {
	t.Parallel()
	discovery := &authWizardDiscoveryStub{
		wizardDiscoveryStub: wizardDiscoveryStub{
			contexts:       []string{"customer"},
			currentContext: "customer",
			namespaces:     []string{"qodo"},
		},
		authErr: &kubernetes.AuthenticationHelperUnavailableError{
			Command: "company-kube-auth",
		},
	}
	forms := &wizardFormsStub{}

	_, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{
			AllNamespaces: false,
			Namespaces:    []string{"qodo"},
		},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     forms,
		},
	)

	var unavailable *kubernetes.AuthenticationHelperUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error=%T %v", err, err)
	}
	if len(discovery.namespaceCalls) != 0 {
		t.Fatalf("namespace discovery ran before auth preflight: %v", discovery.namespaceCalls)
	}
}

func TestCollectMissingHelperFailsBeforeAPIAndCreatesNoArchive(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	callLog := filepath.Join(root, "calls.log")
	kubeconfig := filepath.Join(root, "private-canary-kubeconfig")
	kubectl := fakeAuthenticationKubectl(
		t,
		root,
		callLog,
		"customer",
		"qodo-scout-definitely-missing-auth-helper",
	)
	output := filepath.Join(root, "bundle.tar.gz")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--kubeconfig", kubeconfig,
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
		},
		&stdout,
		&stderr,
	)

	if code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing helper created archive: %v", err)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "get namespaces") ||
		strings.Contains(string(calls), "get pods") {
		t.Fatalf("Kubernetes API call ran before auth failure:\n%s", calls)
	}
	if !strings.Contains(
		string(calls),
		"--kubeconfig "+kubeconfig+" config current-context",
	) {
		t.Fatalf("context resolution ignored the explicit kubeconfig:\n%s", calls)
	}
	if !strings.Contains(
		string(calls),
		"--kubeconfig "+kubeconfig+
			" --context customer config view --minify --output=json",
	) {
		t.Fatalf("preflight ignored the explicit kubeconfig:\n%s", calls)
	}
	for _, expected := range []string{
		"Kubernetes authentication is unavailable",
		"Context: customer",
		"Configure authentication for this context, then verify:",
		"kubectl --context customer get pods --namespace qodo",
		"Rerun Qodo Scout after kubectl succeeds.",
	} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("stderr missing %q:\n%s", expected, stderr.String())
		}
	}
	for _, forbidden := range []string{
		"qodo-scout-definitely-missing-auth-helper",
		"Required command",
		"administrator",
		kubeconfig,
	} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("stderr retained %q:\n%s", forbidden, stderr.String())
		}
	}
	for _, secret := range []string{
		"raw-token-secret",
		"raw-arg-secret",
		"raw-env-secret",
	} {
		if strings.Contains(stderr.String(), secret) {
			t.Fatalf("stderr leaked %q:\n%s", secret, stderr.String())
		}
	}
}

func TestCollectCustomKubeconfigTokenAuthenticationProceeds(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kubeconfig := filepath.Join(root, "private-token-kubeconfig")
	kubectl := fakeKubectl(t, filepath.Join(root, "bin"), "")
	output := filepath.Join(root, "bundle.tar.gz")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--kubeconfig", kubeconfig,
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
			"--no-progress",
		},
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("token-auth collection created no archive: %v", err)
	}
	for _, forbidden := range []string{
		kubeconfig,
		"Kubernetes authentication is unavailable",
		"raw-token-secret",
	} {
		if strings.Contains(stderr.String(), forbidden) ||
			strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("output retained %q: stdout=%q stderr=%q",
				forbidden, stdout.String(), stderr.String())
		}
	}
}

func TestCollectInteractiveMissingHelperUsesSameStableGuidance(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	output := filepath.Join(root, "bundle.tar.gz")
	kubeconfig := filepath.Join(root, "private-interactive-kubeconfig")
	discovery := &authWizardDiscoveryStub{
		wizardDiscoveryStub: wizardDiscoveryStub{
			contexts:       []string{"customer"},
			currentContext: "customer",
		},
		authErr: &kubernetes.AuthenticationHelperUnavailableError{
			Command: "company-kube-auth",
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"collect",
			"--interactive",
			"--no-progress",
			"--kubeconfig", kubeconfig,
			"--namespace", "qodo",
			"--output", output,
		},
		&bytes.Buffer{},
		&stdout,
		&stderr,
		interactiveRuntime{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			NewDiscovery: func(_ string, gotKubeconfig string) (interactiveDiscovery, error) {
				if gotKubeconfig != kubeconfig {
					t.Fatalf(
						"interactive kubeconfig=%q want=%q",
						gotKubeconfig,
						kubeconfig,
					)
				}
				return discovery, nil
			},
			Forms: &wizardFormsStub{},
		},
	)

	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interactive missing helper created archive: %v", err)
	}
	if strings.Contains(stderr.String(), kubeconfig) {
		t.Fatalf("interactive guidance leaked kubeconfig path: %q", stderr.String())
	}
	var expected bytes.Buffer
	writeAuthenticationHelperGuidance(
		&expected,
		discovery.authErr.(*kubernetes.AuthenticationHelperUnavailableError),
		"customer",
		"qodo",
	)
	if stderr.String() != expected.String() {
		t.Fatalf(
			"interactive guidance changed:\ngot  %q\nwant %q",
			stderr.String(),
			expected.String(),
		)
	}
}

func TestCollectFallbackClassifiesRealKubectlMissingHelperError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	output := filepath.Join(root, "bundle.tar.gz")
	kubectl := fakeFallbackAuthenticationKubectl(t, root)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{
			"collect",
			"--context", "customer",
			"--namespace", "qodo",
			"--kubectl", kubectl,
			"--output", output,
		},
		&stdout,
		&stderr,
	)

	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fallback missing helper created archive: %v", err)
	}
	if !strings.Contains(
		stderr.String(),
		"kubectl --context customer get pods --namespace qodo",
	) {
		t.Fatalf("fallback guidance missing:\n%s", stderr.String())
	}
	for _, forbidden := range []string{
		"company-kube-auth",
		"Required command",
		"administrator",
	} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("fallback guidance retained %q:\n%s", forbidden, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "raw-stderr-secret") {
		t.Fatalf("fallback leaked complete kubectl stderr:\n%s", stderr.String())
	}
}

type authWizardDiscoveryStub struct {
	wizardDiscoveryStub
	authErr error
}

func (stub *authWizardDiscoveryStub) CheckAuthenticationHelper(
	context.Context,
	string,
) error {
	return stub.authErr
}

func (stub *wizardDiscoveryStub) CheckAuthenticationHelper(
	context.Context,
	string,
) error {
	return nil
}

func fakeAuthenticationKubectl(
	t *testing.T,
	directory string,
	callLog string,
	contextName string,
	helper string,
) string {
	t.Helper()
	path := filepath.Join(directory, "kubectl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> '` + callLog + `'
case " $* " in
  *" config current-context "*)
    printf '%s\n' '` + contextName + `'
    ;;
  *" config view --minify --output=json "*)
    printf '%s\n' '{"users":[{"name":"customer","user":{"token":"raw-token-secret","exec":{"command":"` + helper + `","args":["--token","raw-arg-secret"],"env":[{"name":"PASSWORD","value":"raw-env-secret"}]}}}]}'
    ;;
  *)
    exit 91
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeFallbackAuthenticationKubectl(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "kubectl")
	script := `#!/bin/sh
case " $* " in
  *" config view --minify --output=json "*)
    printf '%s\n' '{"users":[{"name":"customer","user":{"token":"REDACTED"}}]}'
    ;;
  *" get pods "*)
    printf '%s\n' 'Unable to connect to the server: getting credentials: exec: executable company-kube-auth not found' 'raw-stderr-secret' >&2
    exit 1
    ;;
  *)
    exit 92
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
