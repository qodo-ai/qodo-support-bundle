package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	defaultLogLimit               int64 = 10 << 20
	maxLogLimit                         = kubernetes.MaximumLogBytes
	defaultTotalLogLimit          int64 = 1 << 30
	maxTotalLogLimit                    = kubernetes.MaximumTotalLogBytes
	defaultMetadataLimit          int64 = 128 << 20
	maxMetadataLimit                    = kubernetes.MaximumMetadataBytes
	defaultLogWorkers                   = 8
	maxLogWorkers                       = kubernetes.MaximumLogWorkers
	maxCustomerContextLength            = 4096
	maxCommandTimeout                   = 30 * time.Minute
	defaultProbeTimeout                 = 15 * time.Second
	defaultOutputDirectory              = "qodo-support-bundles"
	defaultOutputResolveHome            = "resolve home directory"
	defaultOutputCreateDirectory        = "create default output directory"
	defaultOutputInspectDirectory       = "inspect default output directory"
	defaultOutputSecureDirectory        = "secure default output directory"
	defaultOutputGenerateFilename       = "generate output filename"
	defaultOutputMustBeDirectory        = "default output directory must be a real directory"
	defaultOutputAbsoluteHome           = "absolute home path is required"
)

var Version = "dev"

// Run executes the support-bundle CLI and returns its process exit code.
func Run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "collect":
		return runCollect(ctx, arguments[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", arguments[0])
		printUsage(stderr)
		return 2
	}
}

func runCollect(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) (exitCode int) {
	flags := flag.NewFlagSet("collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	namespace := flags.String("namespace", "", "Specific Kubernetes namespace to collect")
	namespaces := flags.String("namespaces", "", "Comma-separated Kubernetes namespaces")
	allNamespaces := flags.Bool("all-namespaces", false, "Collect every namespace")
	excludeSystemNamespaces := flags.Bool(
		"exclude-system-namespaces",
		false,
		"Exclude Kubernetes and managed GKE system namespaces",
	)
	selector := flags.String("selector", "", "Optional Kubernetes label selector")
	kubeContext := flags.String("context", "", "Optional kubeconfig context")
	kubeconfig := flags.String("kubeconfig", "", "Optional kubeconfig path")
	kubectl := flags.String("kubectl", "kubectl", "Path to kubectl-compatible binary")
	output := flags.String("output", "", "Exact output .tar.gz archive path")
	since := flags.Duration("since", 30*time.Minute, "Container log lookback")
	timeout := flags.Duration("command-timeout", 2*time.Minute, "Timeout per kubectl command")
	maxLogBytes := flags.Int64(
		"max-log-bytes",
		defaultLogLimit,
		"Maximum bytes collected from each container log",
	)
	maxTotalLogBytes := flags.Int64(
		"max-total-log-bytes",
		defaultTotalLogLimit,
		"Maximum bytes retained across all container logs",
	)
	maxMetadataBytes := flags.Int64(
		"max-metadata-bytes",
		defaultMetadataLimit,
		"Maximum bytes retained across Kubernetes metadata records",
	)
	logWorkers := flags.Int("log-workers", defaultLogWorkers, "Concurrent log readers")
	activity := flags.String("activity", "", "Customer description of current activity")
	problem := flags.String("problem", "", "Customer description of the failure")
	checkZitadel := flags.Bool(
		"check-zitadel",
		false,
		"Probe Platform-to-Zitadel connectivity in an existing container",
	)
	platformNamespace := flags.String(
		"platform-namespace",
		"",
		"Namespace of the selected Platform pod",
	)
	platformPod := flags.String("platform-pod", "", "Selected Platform pod")
	platformContainer := flags.String(
		"platform-container",
		"",
		"Selected Platform application container",
	)
	probeTimeout := flags.Duration(
		"probe-timeout",
		defaultProbeTimeout,
		"Maximum Zitadel probe execution time",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "collect does not accept positional arguments")
		return 2
	}

	visited := make(map[string]bool)
	flags.Visit(func(current *flag.Flag) { visited[current.Name] = true })
	if visited["namespace"] && visited["namespaces"] {
		_, _ = fmt.Fprintln(
			stderr,
			"--namespace and --namespaces cannot be combined",
		)
		return 2
	}
	explicitNamespaces := visited["namespace"] || visited["namespaces"]
	if *excludeSystemNamespaces && !visited["all-namespaces"] {
		_, _ = fmt.Fprintln(stderr, "--exclude-system-namespaces requires --all-namespaces")
		return 2
	}
	if !explicitNamespaces && !visited["all-namespaces"] {
		*allNamespaces = true
		if !visited["exclude-system-namespaces"] {
			*excludeSystemNamespaces = true
		}
	}
	var selectedNamespaces []string
	var err error
	if *allNamespaces {
		if explicitNamespaces {
			_, _ = fmt.Fprintln(
				stderr,
				"--all-namespaces cannot be combined with --namespace or --namespaces",
			)
			return 2
		}
	} else {
		selectedNamespaces, err = parseNamespaces(*namespace, *namespaces)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if err := validateCollectFlags(
		selectedNamespaces,
		*allNamespaces,
		*since,
		*timeout,
		*maxMetadataBytes,
		*maxLogBytes,
		*maxTotalLogBytes,
		*logWorkers,
		*activity,
		*problem,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := validateProbeFlags(
		*checkZitadel,
		visited,
		selectedNamespaces,
		*allNamespaces,
		platformNamespace,
		*platformPod,
		*platformContainer,
		*probeTimeout,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	usedDefaultOutput := false
	if *output == "" {
		usedDefaultOutput = true
		*output, err = defaultOutputPath()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
	}

	redactor := redact.New()
	if *allNamespaces {
		message := "Warning: collecting all namespaces includes non-Qodo workloads."
		if *excludeSystemNamespaces {
			message = "Scope: all application namespaces; Kubernetes system namespaces are excluded."
		}
		_, _ = fmt.Fprintln(stderr, message)
	}
	var builder *bundle.Builder
	if usedDefaultOutput {
		builder, err = bundle.New(*output, bundle.OmitAbsolutePaths())
	} else {
		builder, err = bundle.New(*output)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			closeBundle(builder, stderr, &exitCode)
		}
	}()

	resolvedKubectl, err := resolveKubectl(*kubectl)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "Using kubectl: resolved executable")
	runner := kubernetes.ExecRunner{Binary: resolvedKubectl}
	kubernetesConfig := kubernetes.Config{
		Namespaces:              selectedNamespaces,
		AllNamespaces:           *allNamespaces,
		ExcludeSystemNamespaces: *excludeSystemNamespaces,
		Selector:                *selector,
		Context:                 *kubeContext,
		Kubeconfig:              *kubeconfig,
		Since:                   *since,
		Timeout:                 *timeout,
		MaxMetadataBytes:        *maxMetadataBytes,
		MaxLogBytes:             *maxLogBytes,
		MaxTotalLogBytes:        *maxTotalLogBytes,
		LogWorkers:              *logWorkers,
		Progress: func(progress kubernetes.Progress) {
			writeCollectionProgress(stderr, redactor, progress)
		},
	}
	var zitadelConfig *zitadel.Config
	if *checkZitadel {
		zitadelConfig = &zitadel.Config{
			Namespace:    *platformNamespace,
			Pod:          *platformPod,
			Container:    *platformContainer,
			Context:      *kubeContext,
			Kubeconfig:   *kubeconfig,
			QueryTimeout: *timeout,
			ProbeTimeout: *probeTimeout,
		}
	}
	result, err := collection.Execute(
		ctx,
		collection.Request{
			CollectorVersion: Version,
			CurrentTime:      currentTime,
			Activity:         *activity,
			Problem:          *problem,
			Kubernetes:       kubernetesConfig,
			Zitadel:          zitadelConfig,
			Progress: func(event collection.Event) {
				writeCollectionEvent(stderr, event)
			},
		},
		runner,
		builder,
		redactor,
		collection.DefaultCollectors(),
	)
	if result.CanceledBeforeBundle {
		_, _ = fmt.Fprintln(stderr, "Collection canceled; no bundle was published.")
		return 1
	}
	if err != nil {
		if errors.Is(err, bundle.ErrCleanup) {
			_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", result.ArchivePath)
			_, _ = fmt.Fprintln(stderr, "Bundle created, but temporary data cleanup failed.")
			return 1
		}
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending = false

	_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", result.ArchivePath)
	_, _ = fmt.Fprintf(
		stdout,
		"Kubernetes scope: %d/%d namespaces, %d pods, %d containers (%d init, %d ephemeral)\n",
		len(result.KubernetesReport.Namespaces),
		result.KubernetesReport.NamespacesRequested,
		result.KubernetesReport.Pods,
		result.KubernetesReport.Containers,
		result.KubernetesReport.InitContainers,
		result.KubernetesReport.EphemeralContainers,
	)
	if result.Status == collection.CoveragePartial.String() {
		_, _ = fmt.Fprintln(
			stderr,
			"Warning: collection was partial; inspect collection-issues.jsonl.",
		)
		return 3
	}
	return 0
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  qodo-support-bundle collect [options]
  qodo-support-bundle version
  qodo-support-bundle help

Collect bounded, redacted Kubernetes metadata, events, and container logs.
The optional --check-zitadel probe runs inside one selected Platform container.`)
}
