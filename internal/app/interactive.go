package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"golang.org/x/term"
)

const interactiveDiscoveryLimit int64 = 1 << 20

var (
	errInteractiveRequiresTTY = errors.New(
		"--interactive requires an interactive stdin and stderr terminal",
	)
	errInteractiveCanceled         = errors.New("interactive setup canceled")
	errNamespaceDiscoveryForbidden = errors.New(
		"namespace discovery is not permitted",
	)
	errDiscoveryErrorOutputTruncated = errors.New(
		"kubectl discovery failed; error output exceeded the safe limit",
	)
	errDiscoveryOutputTruncated = errors.New(
		"kubectl discovery output exceeded the safe limit",
	)
	errDiscoveryRunnerUnavailable = errors.New("kubectl runner is unavailable")
)

type interactiveSettings struct {
	Context                 string
	ContextSummary          string
	AllNamespaces           bool
	ExcludeSystemNamespaces bool
	Namespaces              []string
	Since                   time.Duration
	Prometheus              bool
	PrometheusNamespace     string
	Phoenix                 bool
	PhoenixNamespace        string
	TraceID                 string
	Zitadel                 bool
	PlatformNamespace       string
	PlatformPod             string
	PlatformContainer       string
	Output                  string
	Confirmed               bool
}

type interactiveDiscovery interface {
	Contexts(context.Context) ([]string, error)
	CurrentContext(context.Context) (string, error)
	Namespaces(context.Context, string) ([]string, error)
}

type interactiveContextCatalog struct {
	Names   []string
	Current string
}

type interactiveForms interface {
	ChooseContext(
		context.Context,
		*interactiveSettings,
		interactiveContextCatalog,
		io.Reader,
		io.Writer,
	) error
	DiscoveryStatus(string, io.Writer)
	Configure(
		context.Context,
		*interactiveSettings,
		[]string,
		io.Reader,
		io.Writer,
	) error
}

type interactiveWizardDependencies struct {
	InputTTY  func(io.Reader) bool
	OutputTTY func(io.Writer) bool
	Discovery interactiveDiscovery
	Forms     interactiveForms
	Preflight func(
		context.Context,
		interactiveDiscovery,
		io.Reader,
		io.Writer,
	) (interactiveContextCatalog, error)
	DiscoverNamespaces func(
		context.Context,
		interactiveDiscovery,
		string,
		io.Writer,
		int,
	) ([]string, error)
}

type interactiveRuntime struct {
	InputTTY     func(io.Reader) bool
	OutputTTY    func(io.Writer) bool
	NewDiscovery func(string, string) (interactiveDiscovery, error)
	Forms        interactiveForms
}

func defaultInteractiveRuntime() interactiveRuntime {
	return interactiveRuntime{
		InputTTY:  terminalReader,
		OutputTTY: terminalWriter,
		NewDiscovery: func(
			binary string,
			kubeconfig string,
		) (interactiveDiscovery, error) {
			resolved, err := resolveKubectl(binary)
			if err != nil {
				return nil, err
			}
			return kubernetesWizardDiscovery{
				Runner:     kubernetes.ExecRunner{Binary: resolved},
				Kubeconfig: kubeconfig,
			}, nil
		},
		Forms: newHuhInteractiveForms(),
	}
}

func terminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func runInteractiveWizard(
	ctx context.Context,
	settings interactiveSettings,
	stdin io.Reader,
	stderr io.Writer,
	dependencies interactiveWizardDependencies,
) (interactiveSettings, error) {
	if dependencies.InputTTY == nil ||
		dependencies.OutputTTY == nil ||
		!dependencies.InputTTY(stdin) ||
		!dependencies.OutputTTY(stderr) {
		return settings, errInteractiveRequiresTTY
	}
	if dependencies.Discovery == nil || dependencies.Forms == nil {
		return settings, errors.New("interactive setup is unavailable")
	}
	catalog := interactiveContextCatalog{}
	var err error
	if dependencies.Preflight != nil {
		catalog, err = dependencies.Preflight(
			ctx,
			dependencies.Discovery,
			stdin,
			stderr,
		)
		if err != nil {
			return settings, interactiveFormError(err)
		}
	} else {
		contexts, contextErr := dependencies.Discovery.Contexts(ctx)
		if contextErr != nil {
			return settings, fmt.Errorf("discover Kubernetes contexts: %w", contextErr)
		}
		if len(contexts) == 0 {
			return settings, errors.New("discover Kubernetes contexts: no contexts found")
		}
		catalog.Names = contexts
		discoveredCurrent, currentErr := dependencies.Discovery.CurrentContext(ctx)
		if currentErr == nil && containsString(contexts, terminalLine(discoveredCurrent)) {
			catalog.Current = terminalLine(discoveredCurrent)
		}
	}
	contexts := catalog.Names
	currentContext := catalog.Current
	explicitContext := settings.Context != ""
	if settings.Context == "" {
		settings.Context = currentContext
	}
	if explicitContext && !containsString(contexts, settings.Context) {
		return settings, fmt.Errorf(
			"Kubernetes context %q was not found",
			settings.Context,
		)
	}
	if err := dependencies.Forms.ChooseContext(
		ctx,
		&settings,
		catalog,
		stdin,
		stderr,
	); err != nil {
		return settings, interactiveFormError(err)
	}
	if !containsString(contexts, settings.Context) {
		return settings, errors.New("select a Kubernetes context")
	}
	var namespaces []string
	if dependencies.DiscoverNamespaces != nil {
		explicitNamespaceCount := 0
		if !settings.AllNamespaces {
			explicitNamespaceCount = len(settings.Namespaces)
		}
		namespaces, err = dependencies.DiscoverNamespaces(
			ctx,
			dependencies.Discovery,
			settings.Context,
			stderr,
			explicitNamespaceCount,
		)
	} else {
		dependencies.Forms.DiscoveryStatus(settings.Context, stderr)
		namespaces, err = dependencies.Discovery.Namespaces(ctx, settings.Context)
	}
	if err != nil {
		if !errors.Is(err, errNamespaceDiscoveryForbidden) ||
			settings.AllNamespaces ||
			len(settings.Namespaces) == 0 {
			if errors.Is(err, context.Canceled) {
				return settings, errInteractiveCanceled
			}
			return settings, conciseNamespaceDiscoveryError(err)
		}
		namespaces = append([]string(nil), settings.Namespaces...)
	}
	if err := dependencies.Forms.Configure(
		ctx,
		&settings,
		namespaces,
		stdin,
		stderr,
	); err != nil {
		return settings, interactiveFormError(err)
	}
	if !settings.Confirmed {
		return settings, errInteractiveCanceled
	}
	return settings, nil
}

func interactiveFormError(err error) error {
	if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, context.Canceled) {
		return errInteractiveCanceled
	}
	return err
}

func conciseNamespaceDiscoveryError(err error) error {
	switch {
	case errors.Is(err, errNamespaceDiscoveryForbidden):
		return errors.New(
			"read-only access check failed; verify the selected context and permissions",
		)
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New(
			"namespace discovery timed out; check cluster connectivity",
		)
	case errors.Is(err, errDiscoveryErrorOutputTruncated),
		errors.Is(err, errDiscoveryOutputTruncated):
		return errors.New(
			"namespace discovery failed; kubectl output exceeded the safe limit",
		)
	case errors.Is(err, errDiscoveryRunnerUnavailable):
		return errors.New(
			"namespace discovery failed; kubectl is unavailable",
		)
	default:
		return errors.New(
			"namespace discovery failed; check kubectl and the selected context",
		)
	}
}

func validateInteractiveDuration(value string) error {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return errors.New("enter a duration such as 30m, 1h, or 6h")
	}
	if duration <= 0 {
		return errors.New("duration must be positive")
	}
	return nil
}

type kubernetesWizardDiscovery struct {
	Runner     kubernetes.Runner
	Kubeconfig string
}

func (discovery kubernetesWizardDiscovery) Contexts(
	ctx context.Context,
) ([]string, error) {
	arguments := discovery.baseArguments()
	arguments = append(arguments, "config", "get-contexts", "-o", "name")
	return discovery.run(ctx, arguments)
}

func (discovery kubernetesWizardDiscovery) CurrentContext(
	ctx context.Context,
) (string, error) {
	arguments := discovery.baseArguments()
	arguments = append(arguments, "config", "current-context")
	values, err := discovery.run(ctx, arguments)
	if err != nil {
		return "", err
	}
	if len(values) != 1 {
		return "", errors.New("kubectl did not return one current context")
	}
	return values[0], nil
}

func (discovery kubernetesWizardDiscovery) Namespaces(
	ctx context.Context,
	kubeContext string,
) ([]string, error) {
	arguments := discovery.baseArguments()
	if kubeContext != "" {
		arguments = append(arguments, "--context", kubeContext)
	}
	arguments = append(
		arguments,
		"get",
		"namespaces",
		"-o",
		`jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}`,
	)
	return discovery.run(ctx, arguments)
}

func (discovery kubernetesWizardDiscovery) baseArguments() []string {
	if discovery.Kubeconfig == "" {
		return nil
	}
	return []string{"--kubeconfig", discovery.Kubeconfig}
}

func (discovery kubernetesWizardDiscovery) run(
	ctx context.Context,
	arguments []string,
) ([]string, error) {
	if discovery.Runner == nil {
		return nil, errDiscoveryRunnerUnavailable
	}
	result, err := discovery.Runner.Run(ctx, interactiveDiscoveryLimit, arguments...)
	if err != nil {
		if result.StderrTruncated {
			return nil, errDiscoveryErrorOutputTruncated
		}
		stderr := strings.ToLower(string(result.Stderr))
		if strings.Contains(stderr, "forbidden") ||
			strings.Contains(stderr, "permission denied") {
			return nil, fmt.Errorf("%w: %v", errNamespaceDiscoveryForbidden, err)
		}
		return nil, err
	}
	if result.Truncated {
		return nil, errDiscoveryOutputTruncated
	}
	values := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		value := terminalLine(line)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values, nil
}
