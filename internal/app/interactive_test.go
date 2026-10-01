package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
)

type wizardDiscoveryStub struct {
	contexts       []string
	currentContext string
	currentErr     error
	namespaces     []string
	namespaceErr   error
	namespaceCalls []string
}

func (stub *wizardDiscoveryStub) Contexts(context.Context) ([]string, error) {
	return append([]string(nil), stub.contexts...), nil
}

func (stub *wizardDiscoveryStub) CurrentContext(context.Context) (string, error) {
	return stub.currentContext, stub.currentErr
}

func (stub *wizardDiscoveryStub) Namespaces(
	_ context.Context,
	kubeContext string,
) ([]string, error) {
	stub.namespaceCalls = append(stub.namespaceCalls, kubeContext)
	return append([]string(nil), stub.namespaces...), stub.namespaceErr
}

type wizardFormsStub struct {
	contexts          []string
	currentContext    string
	discoveryStatuses []string
	names             []string
	choose            func(*interactiveSettings)
	configure         func(*interactiveSettings)
	err               error
	chosen            interactiveSettings
}

func (stub *wizardFormsStub) ChooseContext(
	_ context.Context,
	settings *interactiveSettings,
	catalog interactiveContextCatalog,
	_ io.Reader,
	_ io.Writer,
) error {
	stub.contexts = append([]string(nil), catalog.Names...)
	stub.currentContext = catalog.Current
	stub.chosen = *settings
	stub.chosen.Namespaces = append([]string(nil), settings.Namespaces...)
	if stub.choose != nil {
		stub.choose(settings)
	}
	return stub.err
}

func (stub *wizardFormsStub) DiscoveryStatus(
	kubeContext string,
	_ io.Writer,
) {
	stub.discoveryStatuses = append(stub.discoveryStatuses, kubeContext)
}

func TestCollectInteractiveUsesFlagDefaultsAndCancelCreatesNoArchive(t *testing.T) {
	t.Parallel()
	output := t.TempDir() + "/bundle.tar.gz"
	forms := &wizardFormsStub{err: huh.ErrUserAborted}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"collect",
			"--interactive",
			"--context", "development",
			"--namespace", "qodo",
			"--since", "1h",
			"--collect-prometheus",
			"--prometheus-namespace", "monitoring",
			"--output", output,
		},
		&bytes.Buffer{},
		&stdout,
		&stderr,
		interactiveRuntime{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			NewDiscovery: func(string, string) (interactiveDiscovery, error) {
				return &wizardDiscoveryStub{
					contexts:       []string{"development", "customer"},
					currentContext: "customer",
				}, nil
			},
			Forms: forms,
		},
	)

	if code != 1 || !errors.Is(interactiveFormError(forms.err), errInteractiveCanceled) {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("canceled wizard changed stdout: %q", stdout.String())
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled wizard created archive: %v", err)
	}
	if forms.chosen.Context != "development" ||
		forms.chosen.AllNamespaces ||
		!reflect.DeepEqual(forms.chosen.Namespaces, []string{"qodo"}) ||
		forms.chosen.Since != time.Hour ||
		!forms.chosen.Prometheus ||
		forms.chosen.PrometheusNamespace != "monitoring" ||
		forms.chosen.Output != output {
		t.Fatalf("flag defaults not passed to wizard: %+v", forms.chosen)
	}
	if forms.currentContext != "customer" {
		t.Fatalf("actual current context metadata=%q", forms.currentContext)
	}
}

func TestCollectInteractiveAnswersUseExistingCollectionPathAndStdout(t *testing.T) {
	root := t.TempDir()
	kubectl := fakeKubectl(t, root, "")
	output := root + "/bundle.tar.gz"
	forms := &wizardFormsStub{
		choose: func(settings *interactiveSettings) {
			settings.Context = "customer"
		},
		configure: func(settings *interactiveSettings) {
			settings.AllNamespaces = false
			settings.Namespaces = []string{"qodo"}
			settings.Since = time.Hour
			settings.Prometheus = false
			settings.Output = output
			settings.Confirmed = true
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"collect",
			"--interactive",
			"--kubectl", kubectl,
			"--all-namespaces",
			"--exclude-system-namespaces=true",
			"--collect-prometheus",
			"--prometheus-namespace", "monitoring",
			"--output", output,
		},
		&bytes.Buffer{},
		&stdout,
		&stderr,
		interactiveRuntime{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			NewDiscovery: func(string, string) (interactiveDiscovery, error) {
				return &wizardDiscoveryStub{
					contexts:       []string{"customer"},
					currentContext: "customer",
					namespaces:     []string{"qodo", "monitoring"},
				}, nil
			},
			Forms: forms,
		},
	)

	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	want := fmt.Sprintf(
		"Support bundle created: %s\n"+
			"Kubernetes scope: 1/1 namespaces, 1 pods, 1 containers (0 init, 0 ephemeral)\n",
		output,
	)
	if stdout.String() != want {
		t.Fatalf("stdout changed:\ngot  %q\nwant %q", stdout.String(), want)
	}
}

func (stub *wizardFormsStub) Configure(
	_ context.Context,
	settings *interactiveSettings,
	namespaces []string,
	_ io.Reader,
	_ io.Writer,
) error {
	stub.names = append([]string(nil), namespaces...)
	if stub.configure != nil {
		stub.configure(settings)
	}
	return stub.err
}

func TestRunInteractiveWizardRejectsNonTTYBeforeDiscovery(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{contexts: []string{"customer"}}
	forms := &wizardFormsStub{}

	_, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return false },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     forms,
		},
	)

	if !errors.Is(err, errInteractiveRequiresTTY) {
		t.Fatalf("error=%v", err)
	}
	if len(forms.contexts) != 0 || len(discovery.namespaceCalls) != 0 {
		t.Fatal("non-TTY wizard performed discovery or opened a form")
	}
}

func TestRunInteractiveWizardDiscoversNamespacesAfterContextChoice(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{
		contexts:   []string{"development", "customer"},
		namespaces: []string{"qodo", "monitoring"},
	}
	forms := &wizardFormsStub{
		choose: func(settings *interactiveSettings) {
			settings.Context = "customer"
		},
		configure: func(settings *interactiveSettings) {
			settings.AllNamespaces = false
			settings.Namespaces = []string{"qodo", "monitoring"}
			settings.Since = 6 * time.Hour
			settings.Prometheus = true
			settings.PrometheusNamespace = "monitoring"
			settings.Phoenix = true
			settings.PhoenixNamespace = "qodo"
			settings.TraceID = "0123456789abcdef0123456789abcdef"
			settings.Zitadel = true
			settings.PlatformNamespace = "qodo"
			settings.PlatformPod = "platform-0"
			settings.PlatformContainer = "platform"
			settings.Output = "/tmp/customer-bundle.tar.gz"
			settings.Confirmed = true
		},
	}

	got, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{Context: "development", Since: 30 * time.Minute},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     forms,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(discovery.namespaceCalls, []string{"customer"}) {
		t.Fatalf("namespace discovery contexts=%v", discovery.namespaceCalls)
	}
	if !reflect.DeepEqual(forms.discoveryStatuses, []string{"customer"}) {
		t.Fatalf("discovery statuses=%v", forms.discoveryStatuses)
	}
	if !reflect.DeepEqual(forms.names, []string{"qodo", "monitoring"}) {
		t.Fatalf("form namespaces=%v", forms.names)
	}
	if got.Context != "customer" ||
		!reflect.DeepEqual(got.Namespaces, []string{"qodo", "monitoring"}) ||
		got.Since != 6*time.Hour ||
		!got.Prometheus ||
		!got.Phoenix ||
		!got.Zitadel ||
		!got.Confirmed {
		t.Fatalf("answers were not retained: %+v", got)
	}
}

func TestRunInteractiveWizardDefaultsToCurrentContext(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{
		contexts:       []string{"alphabetical-first", "current"},
		currentContext: "current",
		namespaces:     []string{"qodo"},
	}
	forms := &wizardFormsStub{
		configure: func(settings *interactiveSettings) {
			settings.Confirmed = true
		},
	}

	got, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     forms,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if forms.chosen.Context != "current" || got.Context != "current" {
		t.Fatalf(
			"current context was not the default: chosen=%q got=%q",
			forms.chosen.Context,
			got.Context,
		)
	}
	if forms.currentContext != "current" {
		t.Fatalf("current context metadata=%q", forms.currentContext)
	}
}

func TestRunInteractiveWizardAllowsContextChoiceWithoutCurrentContext(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{
		contexts:     []string{"customer"},
		currentErr:   errors.New("current-context is not set"),
		namespaces:   []string{"qodo"},
		namespaceErr: nil,
	}
	forms := &wizardFormsStub{
		choose: func(settings *interactiveSettings) {
			settings.Context = "customer"
		},
		configure: func(settings *interactiveSettings) {
			settings.Confirmed = true
		},
	}

	got, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     forms,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Context != "customer" {
		t.Fatalf("chosen context=%q", got.Context)
	}
}

func TestRunInteractiveWizardFallsBackToExplicitNamespacesOnListDenial(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{
		contexts:     []string{"customer"},
		namespaceErr: errNamespaceDiscoveryForbidden,
	}
	forms := &wizardFormsStub{
		configure: func(settings *interactiveSettings) {
			settings.Confirmed = true
		},
	}

	got, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{
			Context:       "customer",
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
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forms.names, []string{"qodo"}) ||
		!reflect.DeepEqual(got.Namespaces, []string{"qodo"}) {
		t.Fatalf("fallback namespaces: form=%v result=%v", forms.names, got.Namespaces)
	}
}

func TestRunInteractiveWizardDoesNotHideNamespaceDiscoveryFailures(t *testing.T) {
	t.Parallel()
	discovery := &wizardDiscoveryStub{
		contexts:     []string{"customer"},
		namespaceErr: context.DeadlineExceeded,
	}

	_, err := runInteractiveWizard(
		context.Background(),
		interactiveSettings{
			Context:       "customer",
			AllNamespaces: false,
			Namespaces:    []string{"qodo"},
		},
		&bytes.Buffer{},
		&bytes.Buffer{},
		interactiveWizardDependencies{
			InputTTY:  func(io.Reader) bool { return true },
			OutputTTY: func(io.Writer) bool { return true },
			Discovery: discovery,
			Forms:     &wizardFormsStub{},
		},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
}

func TestRunInteractiveWizardMapsAbortAndDeclinedConfirmationToCancellation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		forms *wizardFormsStub
	}{
		{
			name:  "escape",
			forms: &wizardFormsStub{err: huh.ErrUserAborted},
		},
		{
			name: "declined confirmation",
			forms: &wizardFormsStub{
				configure: func(settings *interactiveSettings) {
					settings.Confirmed = false
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := runInteractiveWizard(
				context.Background(),
				interactiveSettings{Confirmed: true},
				&bytes.Buffer{},
				&bytes.Buffer{},
				interactiveWizardDependencies{
					InputTTY:  func(io.Reader) bool { return true },
					OutputTTY: func(io.Writer) bool { return true },
					Discovery: &wizardDiscoveryStub{
						contexts:       []string{"customer"},
						currentContext: "customer",
						namespaces:     []string{"qodo"},
					},
					Forms: test.forms,
				},
			)
			if !errors.Is(err, errInteractiveCanceled) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestValidateInteractiveDurationAcceptsSafeCustomValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "45m", valid: true},
		{value: "6h", valid: true},
		{value: "0", valid: false},
		{value: "-1m", valid: false},
		{value: "forever", valid: false},
		{value: "31m", valid: true},
	} {
		err := validateInteractiveDuration(test.value)
		if (err == nil) != test.valid {
			t.Fatalf("value=%q error=%v valid=%t", test.value, err, test.valid)
		}
	}
}

func TestOrderedCollectorNamespacesPrioritizesSelectedScope(t *testing.T) {
	t.Parallel()
	got := orderedCollectorNamespaces(
		"selected",
		[]string{"qodo"},
		[]string{"monitoring", "qodo", "other"},
	)
	want := []string{"qodo", "monitoring", "other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered namespaces=%v want=%v", got, want)
	}
}

func TestInteractiveSummarySanitizesOutputPath(t *testing.T) {
	t.Parallel()
	got := interactiveSummary(
		"customer",
		"selected",
		false,
		[]string{"qodo"},
		"30m",
		"",
		nil,
		"/tmp/bundle\x1b[31m.tar.gz\nspoof",
	)
	if strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("summary retained terminal controls: %q", got)
	}
}

func TestAllNamespaceScopeLabelReflectsSystemNamespaceSetting(t *testing.T) {
	t.Parallel()
	if got := allNamespaceScopeLabel(true); got != "All application namespaces" {
		t.Fatalf("excluded-system label=%q", got)
	}
	if got := allNamespaceScopeLabel(false); got != "All namespaces (including system namespaces)" {
		t.Fatalf("system-inclusive label=%q", got)
	}
}

func TestInteractiveSummaryShowsSystemInclusiveScope(t *testing.T) {
	t.Parallel()
	got := interactiveSummary(
		"customer",
		"all",
		false,
		nil,
		"30m",
		"",
		nil,
		"",
	)
	if !strings.Contains(got, "scope all namespaces (including system namespaces)") {
		t.Fatalf("summary understated namespace scope: %q", got)
	}
}

type wizardRunnerStub struct {
	calls   [][]string
	results []kubernetes.CommandResult
	errors  []error
}

func (stub *wizardRunnerStub) Run(
	_ context.Context,
	_ int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	stub.calls = append(stub.calls, append([]string(nil), arguments...))
	result := stub.results[0]
	stub.results = stub.results[1:]
	var err error
	if len(stub.errors) > 0 {
		err = stub.errors[0]
		stub.errors = stub.errors[1:]
	}
	return result, err
}

func TestKubernetesWizardDiscoveryUsesFixedBoundedArguments(t *testing.T) {
	t.Parallel()
	runner := &wizardRunnerStub{results: []kubernetes.CommandResult{
		{Stdout: []byte("development\ncustomer\n")},
		{Stdout: []byte("customer\n")},
		{Stdout: []byte("qodo\nmonitoring\n")},
	}}
	discovery := kubernetesWizardDiscovery{
		Runner:     runner,
		Kubeconfig: "/tmp/customer.kubeconfig",
	}

	contexts, err := discovery.Contexts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := discovery.CurrentContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := discovery.Namespaces(context.Background(), "customer")
	if err != nil {
		t.Fatal(err)
	}
	if current != "customer" ||
		!reflect.DeepEqual(contexts, []string{"development", "customer"}) ||
		!reflect.DeepEqual(namespaces, []string{"qodo", "monitoring"}) {
		t.Fatalf("current=%q contexts=%v namespaces=%v", current, contexts, namespaces)
	}
	want := [][]string{
		{
			"--kubeconfig", "/tmp/customer.kubeconfig",
			"config", "get-contexts", "-o", "name",
		},
		{
			"--kubeconfig", "/tmp/customer.kubeconfig",
			"config", "current-context",
		},
		{
			"--kubeconfig", "/tmp/customer.kubeconfig",
			"--context", "customer",
			"get", "namespaces",
			"-o", `jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`,
		},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("kubectl calls=%q want=%q", runner.calls, want)
	}
}

func TestKubernetesWizardDiscoveryClassifiesCompleteNamespacePermissionDenial(t *testing.T) {
	t.Parallel()
	for _, message := range []string{
		"Error from server (Forbidden): namespaces is forbidden",
		"permission denied while listing namespaces",
	} {
		message := message
		t.Run(message, func(t *testing.T) {
			t.Parallel()
			runner := &wizardRunnerStub{
				results: []kubernetes.CommandResult{{Stderr: []byte(message)}},
				errors:  []error{errors.New("kubectl exited with status 1")},
			}
			discovery := kubernetesWizardDiscovery{Runner: runner}

			_, err := discovery.Namespaces(context.Background(), "customer")
			if !errors.Is(err, errNamespaceDiscoveryForbidden) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestKubernetesWizardDiscoveryRejectsTruncatedPermissionErrors(t *testing.T) {
	t.Parallel()
	for _, stderr := range []string{
		"bounded output without the truncated Forbidden suffix",
		"Error from server (Forbidden): prefix followed by truncated output",
	} {
		stderr := stderr
		t.Run(stderr, func(t *testing.T) {
			t.Parallel()
			runner := &wizardRunnerStub{
				results: []kubernetes.CommandResult{{
					Stderr:          []byte(stderr),
					StderrTruncated: true,
				}},
				errors: []error{errors.New("kubectl exited with status 1")},
			}
			discovery := kubernetesWizardDiscovery{Runner: runner}

			_, err := discovery.Namespaces(context.Background(), "customer")
			if !errors.Is(err, errDiscoveryErrorOutputTruncated) {
				t.Fatalf("error=%v", err)
			}
			if errors.Is(err, errNamespaceDiscoveryForbidden) ||
				strings.Contains(strings.ToLower(err.Error()), "forbidden") {
				t.Fatalf("truncated stderr was classified as a permission denial: %v", err)
			}
		})
	}
}

func TestKubernetesWizardDiscoveryPreservesUnrelatedCommandFailure(t *testing.T) {
	t.Parallel()
	runErr := errors.New("kubectl exited with status 7")
	runner := &wizardRunnerStub{
		results: []kubernetes.CommandResult{{Stderr: []byte("connection refused")}},
		errors:  []error{runErr},
	}
	discovery := kubernetesWizardDiscovery{Runner: runner}

	_, err := discovery.Namespaces(context.Background(), "customer")
	if !errors.Is(err, runErr) {
		t.Fatalf("error=%v", err)
	}
}

func TestKubernetesWizardDiscoveryRejectsTruncatedStdout(t *testing.T) {
	t.Parallel()
	runner := &wizardRunnerStub{
		results: []kubernetes.CommandResult{{
			Stdout:    []byte("qodo\n"),
			Truncated: true,
		}},
	}
	discovery := kubernetesWizardDiscovery{Runner: runner}

	_, err := discovery.Namespaces(context.Background(), "customer")
	if err == nil || !strings.Contains(err.Error(), "output exceeded the safe limit") {
		t.Fatalf("error=%v", err)
	}
}
