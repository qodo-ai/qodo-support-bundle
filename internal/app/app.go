package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	defaultForwardOutputLimit     int64 = 8 << 10
)

var Version = "dev"

// Run executes the support-bundle CLI and returns its process exit code.
func Run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	return run(
		ctx,
		arguments,
		os.Stdin,
		stdout,
		stderr,
		defaultInteractiveRuntime(),
	)
}

func run(
	ctx context.Context,
	arguments []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	interactiveRuntime interactiveRuntime,
) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "collect":
		return runCollect(
			ctx,
			arguments[1:],
			stdin,
			stdout,
			stderr,
			interactiveRuntime,
		)
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
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	interactiveRuntime interactiveRuntime,
) (exitCode int) {
	collectionTime := currentTime().UTC()
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
	interactive := flags.Bool("interactive", false, "Launch the interactive collection setup wizard")
	noProgress := flags.Bool("no-progress", false, "Suppress routine progress output")
	_ = flags.Bool("mascot", false, "Deprecated no-op; interactive progress uses the scanner animation")
	activity := flags.String("activity", "", "Customer description of current activity")
	problem := flags.String("problem", "", "Customer description of the failure")
	checkZitadel := flags.Bool(
		"check-zitadel",
		false,
		"Probe Platform-to-Zitadel connectivity in an existing container",
	)
	collectPrometheus := flags.Bool(
		"collect-prometheus",
		false,
		"Collect bounded Prometheus telemetry",
	)
	prometheusNamespace := flags.String(
		"prometheus-namespace",
		"",
		"Namespace hosting the Prometheus service",
	)
	collectPhoenix := flags.Bool(
		"collect-phoenix",
		false,
		"Collect bounded Phoenix trace telemetry",
	)
	phoenixNamespace := flags.String(
		"phoenix-namespace",
		"",
		"Namespace hosting the Phoenix service",
	)
	traceID := flags.String(
		"trace-id",
		"",
		"Exact 32-hex-character Phoenix trace ID",
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
	if *interactive {
		if interactiveRuntime.InputTTY == nil ||
			interactiveRuntime.OutputTTY == nil ||
			!interactiveRuntime.InputTTY(stdin) ||
			!interactiveRuntime.OutputTTY(stderr) {
			_, _ = fmt.Fprintln(stderr, errInteractiveRequiresTTY)
			return 2
		}
		if interactiveRuntime.NewDiscovery == nil || interactiveRuntime.Forms == nil {
			_, _ = fmt.Fprintln(stderr, "interactive setup is unavailable")
			return 1
		}
		discovery, discoveryErr := interactiveRuntime.NewDiscovery(*kubectl, *kubeconfig)
		if discoveryErr != nil {
			_, _ = fmt.Fprintln(stderr, "kubectl is unavailable; verify --kubectl and kubeconfig settings")
			return 1
		}
		settings, wizardErr := runInteractiveWizard(
			ctx,
			interactiveSettings{
				Context:                 *kubeContext,
				AllNamespaces:           *allNamespaces,
				ExcludeSystemNamespaces: *excludeSystemNamespaces,
				Namespaces:              selectedNamespaces,
				Since:                   *since,
				Prometheus:              *collectPrometheus,
				PrometheusNamespace:     *prometheusNamespace,
				Phoenix:                 *collectPhoenix,
				PhoenixNamespace:        *phoenixNamespace,
				TraceID:                 *traceID,
				Zitadel:                 *checkZitadel,
				PlatformNamespace:       *platformNamespace,
				PlatformPod:             *platformPod,
				PlatformContainer:       *platformContainer,
				Output:                  *output,
				Confirmed:               true,
			},
			stdin,
			stderr,
			interactiveWizardDependencies{
				InputTTY:  interactiveRuntime.InputTTY,
				OutputTTY: interactiveRuntime.OutputTTY,
				Discovery: discovery,
				Forms:     interactiveRuntime.Forms,
				Preflight: func(
					preflightCtx context.Context,
					preflightDiscovery interactiveDiscovery,
					preflightInput io.Reader,
					preflightOutput io.Writer,
				) (interactiveContextCatalog, error) {
					accessible := os.Getenv("ACCESSIBLE") != ""
					noColor := os.Getenv("NO_COLOR") != ""
					visible := !*noProgress
					decorated := wizardEntranceEnabled(
						visible,
						accessible,
						noColor,
						terminalReader(preflightInput),
						terminalWriter(preflightOutput),
						os.Getenv("TERM"),
					)
					return runWizardPreflight(
						preflightCtx,
						preflightDiscovery,
						preflightInput,
						preflightOutput,
						wizardPreflightOptions{
							Interactive: decorated,
							Entrance:    decorated,
							Visible:     visible,
							Unicode:     terminalUnicode(),
							Color: wizardColorEnabled(
								accessible,
								preflightOutput,
							),
							Width: terminalWidth(preflightOutput),
						},
					)
				},
				DiscoverNamespaces: func(
					discoveryCtx context.Context,
					discovery interactiveDiscovery,
					selectedContext string,
					discoveryOutput io.Writer,
				) ([]string, error) {
					return runWizardNamespaceDiscovery(
						discoveryCtx,
						discovery,
						selectedContext,
						discoveryOutput,
						!*noProgress,
					)
				},
			},
		)
		if wizardErr != nil {
			_, _ = fmt.Fprintln(stderr, wizardErr)
			if errors.Is(wizardErr, errInteractiveCanceled) {
				return 1
			}
			return 1
		}
		*kubeContext = settings.Context
		*allNamespaces = settings.AllNamespaces
		selectedNamespaces = append([]string(nil), settings.Namespaces...)
		*since = settings.Since
		*collectPrometheus = settings.Prometheus
		*prometheusNamespace = settings.PrometheusNamespace
		*collectPhoenix = settings.Phoenix
		*phoenixNamespace = settings.PhoenixNamespace
		*traceID = settings.TraceID
		*checkZitadel = settings.Zitadel
		*platformNamespace = settings.PlatformNamespace
		*platformPod = settings.PlatformPod
		*platformContainer = settings.PlatformContainer
		*output = settings.Output
		if !settings.Prometheus {
			*prometheusNamespace = ""
			visited["prometheus-namespace"] = false
		}
		if !settings.Phoenix {
			*phoenixNamespace = ""
			*traceID = ""
			visited["phoenix-namespace"] = false
			visited["trace-id"] = false
		}
		if !settings.Zitadel {
			*platformNamespace = ""
			*platformPod = ""
			*platformContainer = ""
			visited["platform-namespace"] = false
			visited["platform-pod"] = false
			visited["platform-container"] = false
			visited["probe-timeout"] = false
		}
		if !settings.AllNamespaces {
			*excludeSystemNamespaces = false
		} else if !visited["exclude-system-namespaces"] {
			*excludeSystemNamespaces = true
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
	if err := validatePrometheusFlags(
		*collectPrometheus,
		visited,
		selectedNamespaces,
		*allNamespaces,
		prometheusNamespace,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := validatePhoenixFlags(
		*collectPhoenix,
		visited,
		selectedNamespaces,
		*allNamespaces,
		phoenixNamespace,
		traceID,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	var prometheusConfig *prometheus.Config
	if *collectPrometheus {
		config := buildPrometheusConfig(
			*prometheusNamespace,
			selectedNamespaces,
			*allNamespaces,
			*excludeSystemNamespaces,
			*kubeContext,
			*kubeconfig,
			collectionTime,
			*since,
		)
		if *since > config.MaxWindow {
			_, _ = fmt.Fprintf(
				stderr,
				"--since must not exceed %s when --collect-prometheus is enabled\n",
				config.MaxWindow,
			)
			return 2
		}
		prometheusConfig = &config
	}
	var phoenixConfig *phoenix.Config
	if *collectPhoenix {
		config := buildPhoenixConfig(
			*phoenixNamespace,
			*kubeContext,
			*kubeconfig,
			collectionTime,
			*since,
			*traceID,
		)
		if *since > config.MaxWindow {
			_, _ = fmt.Fprintf(
				stderr,
				"--since must not exceed %s when --collect-phoenix is enabled\n",
				config.MaxWindow,
			)
			return 2
		}
		phoenixConfig = &config
	}
	usedDefaultOutput := false
	if *output == "" {
		usedDefaultOutput = true
		*output, err = defaultOutputPathAt(collectionTime)
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
	progress := newCLIProgressRenderer(stderr, !*noProgress)
	defer closeProgress(progress, stderr)
	progress.Update(progressUpdate{
		ID: "collection", Label: "Qodo Scout collection", Status: progressActive,
	})

	var builder *bundle.Builder
	bundleOptions := []bundle.Option{
		bundle.WithProgress(func(event bundle.Progress) {
			writeBundleProgress(progress, event)
		}),
	}
	if usedDefaultOutput {
		bundleOptions = append(bundleOptions, bundle.OmitAbsolutePaths())
	}
	builder, err = bundle.New(*output, bundleOptions...)
	if err != nil {
		closeProgress(progress, stderr)
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			closeBundle(builder, stderr, &exitCode)
		}
	}()

	progress.Update(progressUpdate{
		ID: "preflight", Label: "kubectl ready", Level: 1,
		Status: progressActive,
	})
	resolvedKubectl, err := resolveKubectl(*kubectl)
	if err != nil {
		progress.Update(progressUpdate{
			ID: "preflight", Label: "kubectl ready", Level: 1,
			Status: progressFailed,
		})
		closeProgress(progress, stderr)
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	progress.Update(progressUpdate{
		ID: "preflight", Label: "kubectl ready", Level: 1,
		Status: progressCompleted,
	})
	runner := kubernetes.ExecRunner{Binary: resolvedKubectl}
	collectors := collection.DefaultCollectors()
	if prometheusConfig != nil || phoenixConfig != nil {
		factory := func(
			binary string,
			config telemetry.ForwardConfig,
		) (telemetry.Forwarder, error) {
			return telemetry.NewKubectlForwarder(binary, config)
		}
		err = configureTelemetryForwarders(
			&collectors,
			resolvedKubectl,
			prometheusConfig,
			phoenixConfig,
			factory,
		)
		if err != nil {
			closeProgress(progress, stderr)
			_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
			return 1
		}
	}
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
		Progress: func(event kubernetes.Progress) {
			writeCollectionProgress(progress, redactor, event)
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
			CurrentTime: func() time.Time {
				return collectionTime
			},
			Activity:   *activity,
			Problem:    *problem,
			Kubernetes: kubernetesConfig,
			Prometheus: prometheusConfig,
			Phoenix:    phoenixConfig,
			Zitadel:    zitadelConfig,
			Progress: func(event collection.Event) {
				writeCollectionEvent(progress, event)
			},
		},
		runner,
		builder,
		redactor,
		collectors,
	)
	if result.CanceledBeforeBundle {
		progress.Cancel()
		closeProgress(progress, stderr)
		return 1
	}
	if err != nil {
		if errors.Is(err, bundle.ErrCleanup) {
			progress.Update(progressUpdate{
				ID: "archive", Label: "Redaction and archive", Level: 1,
				Status: progressWarning, Detail: "saved; cleanup incomplete",
			})
			writeProgressSummary(
				progress,
				redactor,
				result,
				prometheusConfig,
				phoenixConfig,
				true,
			)
			closeProgress(progress, stderr)
			_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", result.ArchivePath)
			_, _ = fmt.Fprintln(stderr, "Bundle created, but temporary data cleanup failed.")
			return 1
		}
		progress.Update(progressUpdate{
			ID: "collection", Label: "Qodo Scout collection",
			Status: progressFailed,
		})
		closeProgress(progress, stderr)
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending = false

	writeProgressSummary(
		progress,
		redactor,
		result,
		prometheusConfig,
		phoenixConfig,
		false,
	)
	closeProgress(progress, stderr)
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
		if !progress.enabled {
			_, _ = fmt.Fprintln(
				stderr,
				"Warning: collection was partial; inspect collection-issues.jsonl.",
			)
		}
		return 3
	}
	return 0
}

func writeProgressSummary(
	progress *progressRenderer,
	redactor *redact.Redactor,
	result collection.Result,
	prometheusConfig *prometheus.Config,
	phoenixConfig *phoenix.Config,
	cleanupIncomplete bool,
) {
	status := progressCompleted
	detail := ""
	if result.Status == collection.CoveragePartial.String() {
		status = progressWarning
		detail = "partial"
	}
	progress.Update(progressUpdate{
		ID: "collection", Label: "Qodo Scout collection",
		Status: status, Detail: detail,
	})
	archiveSize := int64(-1)
	if info, err := os.Stat(result.ArchivePath); err == nil {
		archiveSize = info.Size()
	}
	options := progressSummaryOptions{
		ArchivePath:       progressArchivePath(redactor, result.ArchivePath),
		ArchiveSize:       archiveSize,
		CleanupIncomplete: cleanupIncomplete,
	}
	if prometheusConfig != nil {
		options.PrometheusNamespace = terminalText(redactor, prometheusConfig.Namespace)
	}
	if phoenixConfig != nil {
		options.PhoenixNamespace = terminalText(redactor, phoenixConfig.Namespace)
	}
	progress.Summary(buildProgressSummary(result, options))
}

func progressArchivePath(redactor *redact.Redactor, archivePath string) string {
	cleanPath := filepath.Clean(archivePath)
	home, err := homeDirectory()
	if err == nil && filepath.IsAbs(home) {
		if relative, relativeErr := filepath.Rel(home, cleanPath); relativeErr == nil &&
			relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			if relative == "." {
				cleanPath = "~"
			} else {
				cleanPath = filepath.Join("~", relative)
			}
		}
	}
	return terminalText(redactor, cleanPath)
}

type telemetryForwarderFactory func(
	string,
	telemetry.ForwardConfig,
) (telemetry.Forwarder, error)

func buildPrometheusConfig(
	namespace string,
	namespaces []string,
	allNamespaces bool,
	excludeSystemNamespaces bool,
	kubeContext string,
	kubeconfig string,
	end time.Time,
	since time.Duration,
) prometheus.Config {
	config := prometheus.DefaultConfig()
	config.Namespace = namespace
	config.Namespaces = append([]string(nil), namespaces...)
	config.AllNamespaces = allNamespaces
	config.ExcludeSystemNamespaces = excludeSystemNamespaces
	config.Context = kubeContext
	config.Kubeconfig = kubeconfig
	config.End = end.UTC()
	config.Start = config.End.Add(-since)
	return config
}

func buildPhoenixConfig(
	namespace string,
	kubeContext string,
	kubeconfig string,
	end time.Time,
	since time.Duration,
	traceID string,
) phoenix.Config {
	config := phoenix.DefaultConfig()
	config.Namespace = namespace
	config.Context = kubeContext
	config.Kubeconfig = kubeconfig
	config.End = end.UTC()
	config.Start = config.End.Add(-since)
	config.TraceID = strings.ToLower(traceID)
	return config
}

func buildPrometheusForwarder(
	resolvedKubectl string,
	config prometheus.Config,
	factory telemetryForwarderFactory,
) (telemetry.Forwarder, error) {
	return buildTelemetryForwarder(
		resolvedKubectl,
		config.Namespace,
		config.Context,
		config.Kubeconfig,
		config.ReadinessTimeout,
		"Prometheus",
		factory,
	)
}

func buildPhoenixForwarder(
	resolvedKubectl string,
	config phoenix.Config,
	factory telemetryForwarderFactory,
) (telemetry.Forwarder, error) {
	return buildTelemetryForwarder(
		resolvedKubectl,
		config.Namespace,
		config.Context,
		config.Kubeconfig,
		config.ReadinessTimeout,
		"Phoenix",
		factory,
	)
}

func buildTelemetryForwarder(
	resolvedKubectl string,
	namespace string,
	kubeContext string,
	kubeconfig string,
	readinessTimeout time.Duration,
	source string,
	factory telemetryForwarderFactory,
) (telemetry.Forwarder, error) {
	if factory == nil {
		return nil, fmt.Errorf("create %s telemetry forwarder: invalid factory", source)
	}
	forwarder, err := factory(resolvedKubectl, telemetry.ForwardConfig{
		Namespace:        namespace,
		Context:          kubeContext,
		Kubeconfig:       kubeconfig,
		ReadinessTimeout: readinessTimeout,
		MaxOutputBytes:   defaultForwardOutputLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("create %s telemetry forwarder: %w", source, err)
	}
	if forwarder == nil {
		return nil, fmt.Errorf("create %s telemetry forwarder: invalid result", source)
	}
	return forwarder, nil
}

func configureTelemetryForwarders(
	collectors *collection.Collectors,
	resolvedKubectl string,
	prometheusConfig *prometheus.Config,
	phoenixConfig *phoenix.Config,
	factory telemetryForwarderFactory,
) error {
	if collectors == nil {
		return errors.New("configure telemetry forwarders: invalid collectors")
	}
	switch {
	case prometheusConfig != nil &&
		phoenixConfig != nil &&
		prometheusConfig.Namespace == phoenixConfig.Namespace &&
		prometheusConfig.Context == phoenixConfig.Context &&
		prometheusConfig.Kubeconfig == phoenixConfig.Kubeconfig:
		readinessTimeout := max(
			prometheusConfig.ReadinessTimeout,
			phoenixConfig.ReadinessTimeout,
		)
		forwarder, err := buildTelemetryForwarder(
			resolvedKubectl,
			prometheusConfig.Namespace,
			prometheusConfig.Context,
			prometheusConfig.Kubeconfig,
			readinessTimeout,
			"shared",
			factory,
		)
		if err != nil {
			return err
		}
		collectors.Forwarder = forwarder
	case prometheusConfig != nil && phoenixConfig != nil:
		prometheusForwarder, err := buildPrometheusForwarder(
			resolvedKubectl,
			*prometheusConfig,
			factory,
		)
		if err != nil {
			return err
		}
		phoenixForwarder, err := buildPhoenixForwarder(
			resolvedKubectl,
			*phoenixConfig,
			factory,
		)
		if err != nil {
			return err
		}
		collectors.PrometheusForwarder = prometheusForwarder
		collectors.PhoenixForwarder = phoenixForwarder
	case prometheusConfig != nil:
		forwarder, err := buildPrometheusForwarder(
			resolvedKubectl,
			*prometheusConfig,
			factory,
		)
		if err != nil {
			return err
		}
		collectors.Forwarder = forwarder
	case phoenixConfig != nil:
		forwarder, err := buildPhoenixForwarder(
			resolvedKubectl,
			*phoenixConfig,
			factory,
		)
		if err != nil {
			return err
		}
		collectors.Forwarder = forwarder
	}
	return nil
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, wizardTitle(false))
	_, _ = fmt.Fprintln(writer, `
Usage:
  qodo-support-bundle collect [options]
  qodo-support-bundle version
  qodo-support-bundle help

Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted.
[!] Review the archive before sharing

Collect bounded, redacted Kubernetes metadata, events, and container logs.
The optional --check-zitadel probe runs inside one selected Platform container.
Hierarchical progress and the final local-archive summary are written to stderr.
Interactive terminals use an inline scanner animation during real processing.
Interactive setup starts a brief scanner entrance while kubeconfig checks run.
Use --no-progress to suppress routine progress. --mascot (deprecated; no-op)
remains accepted for compatibility. Use collect --interactive for the optional
setup wizard when stdin and stderr are terminals. The resulting archive is saved locally.
This CLI does not upload it. Share it separately through an approved support channel.`)
}
