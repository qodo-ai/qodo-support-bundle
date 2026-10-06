package collection

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/phoenix"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	zitadelArtifactPath = "connectivity/zitadel.json"
	issuesArtifactPath  = "collection-issues.jsonl"
	summaryArtifactPath = "summary.md"
	workloadReportPath  = "kubernetes/workload-coverage.json"
)

// EventKind identifies a collection event that the application may present.
type EventKind string

const (
	EventKubernetesStarted   EventKind = "kubernetes_started"
	EventKubernetesComplete  EventKind = "kubernetes_complete"
	EventKubernetesPartial   EventKind = "kubernetes_partial"
	EventWorkloadStarted     EventKind = "workload_started"
	EventWorkloadProgress    EventKind = "workload_progress"
	EventWorkloadComplete    EventKind = "workload_complete"
	EventWorkloadPartial     EventKind = "workload_partial"
	EventWorkloadUnavailable EventKind = "workload_unavailable"
	EventArchiveSummary      EventKind = "archive_summary"

	EventPrometheusStarted     EventKind = "prometheus_started"
	EventPrometheusComplete    EventKind = "prometheus_complete"
	EventPrometheusPartial     EventKind = "prometheus_partial"
	EventPrometheusUnavailable EventKind = "prometheus_unavailable"

	EventPhoenixStarted     EventKind = "phoenix_started"
	EventPhoenixComplete    EventKind = "phoenix_complete"
	EventPhoenixPartial     EventKind = "phoenix_partial"
	EventPhoenixUnavailable EventKind = "phoenix_unavailable"

	EventZitadelStarted           EventKind = "zitadel_started"
	EventZitadelUnavailable       EventKind = "zitadel_unavailable"
	EventZitadelDiagnosticFailure EventKind = "zitadel_diagnostic_failure"
	EventZitadelPassed            EventKind = "zitadel_passed"
)

// Event carries a stable event kind and an optional sanitized reason.
type Event struct {
	Kind    EventKind
	Reason  string
	Current int
	Total   int
}

// Request contains validated inputs for one collection.
type Request struct {
	CollectorVersion string
	CurrentTime      func() time.Time
	Activity         string
	Problem          string
	Kubernetes       kubernetes.Config
	Prometheus       *prometheus.Config
	Phoenix          *phoenix.Config
	Zitadel          *zitadel.Config
	Progress         func(Event)
}

// Result describes the completed collection and published archive.
type Result struct {
	ArchivePath          string
	Status               string
	Coverage             map[Source]Coverage
	KubernetesReport     kubernetes.Report
	WorkloadReport       *workload.Report
	PrometheusReport     *prometheus.Report
	PhoenixReport        *phoenix.Report
	ConnectivityReport   *zitadel.Report
	ConnectivityFailure  string
	CanceledBeforeBundle bool
}

// Archive receives artifacts and publishes the final bundle.
type Archive interface {
	kubernetes.Sink
	FinalizeContext(context.Context, bundle.Manifest) (string, error)
}

// KubernetesCollector returns the evidence used to derive Kubernetes coverage.
type KubernetesCollector func(
	context.Context,
	kubernetes.Config,
	kubernetes.Runner,
	kubernetes.Sink,
	*redact.Redactor,
) (kubernetes.Report, error)

// WorkloadCollector returns normalized namespace-scoped workload context.
type WorkloadCollector func(
	context.Context,
	workload.Config,
	kubernetes.Runner,
	kubernetes.Sink,
	*redact.Redactor,
) (workload.Report, error)

// PrometheusCollector collects and stages bounded Prometheus telemetry.
type PrometheusCollector func(
	context.Context,
	prometheus.Config,
	kubernetes.Runner,
	telemetry.Forwarder,
	kubernetes.Sink,
	*redact.Redactor,
) (prometheus.Report, error)

// PhoenixCollector collects and stages bounded Phoenix trace telemetry.
type PhoenixCollector func(
	context.Context,
	phoenix.Config,
	kubernetes.Runner,
	telemetry.Forwarder,
	kubernetes.Sink,
	*redact.Redactor,
) (phoenix.Report, error)

// ZitadelCollector executes the optional Platform-to-Zitadel probe.
type ZitadelCollector func(
	context.Context,
	zitadel.Config,
	kubernetes.Runner,
	*redact.Redactor,
) zitadel.Outcome

// Collectors are explicit source collector dependencies.
type Collectors struct {
	Kubernetes KubernetesCollector
	Workload   WorkloadCollector
	Prometheus PrometheusCollector
	Phoenix    PhoenixCollector
	// PrometheusForwarder and PhoenixForwarder may reference the same
	// sequential forwarder when both services are in one namespace.
	PrometheusForwarder telemetry.Forwarder
	PhoenixForwarder    telemetry.Forwarder
	// Forwarder is retained as a shared dependency for callers that collect
	// only one telemetry source or place both sources in one namespace.
	Forwarder telemetry.Forwarder
	Zitadel   ZitadelCollector
}

// DefaultCollectors returns the production source collectors.
func DefaultCollectors() Collectors {
	return Collectors{
		Kubernetes: kubernetes.Collect,
		Workload:   workload.Collect,
		Prometheus: prometheus.Collect,
		Phoenix:    phoenix.Collect,
		Zitadel:    zitadel.Collect,
	}
}

// Execute collects requested sources, stages reports, and publishes the bundle.
func Execute(
	ctx context.Context,
	request Request,
	runner kubernetes.Runner,
	archive Archive,
	redactor *redact.Redactor,
	collectors Collectors,
) (Result, error) {
	if err := validateDependencies(
		ctx,
		runner,
		archive,
		redactor,
		collectors,
		request.CurrentTime,
		request.Prometheus != nil,
		request.Phoenix != nil,
		request.Zitadel != nil,
	); err != nil {
		return Result{}, err
	}
	requested := []Source{SourceKubernetes, SourceWorkload}
	if request.Prometheus != nil {
		requested = append(requested, SourcePrometheus)
	}
	if request.Phoenix != nil {
		requested = append(requested, SourcePhoenix)
	}
	if request.Zitadel != nil {
		requested = append(requested, SourceZitadel)
	}
	result := Result{Coverage: InitializeCoverage(requested)}

	reportEvent(request.Progress, Event{Kind: EventKubernetesStarted})
	kubernetesReport, kubernetesErr := collectors.Kubernetes(
		ctx,
		request.Kubernetes,
		runner,
		archive,
		redactor,
	)
	if ctx.Err() != nil {
		result.CanceledBeforeBundle = true
		return result, ctx.Err()
	}
	if kubernetesErr != nil {
		var unavailable *kubernetes.AuthenticationHelperUnavailableError
		if errors.As(kubernetesErr, &unavailable) {
			return result, unavailable
		}
		kubernetesReport.Issues = append(kubernetesReport.Issues, kubernetes.Issue{
			Operation: "collect Kubernetes diagnostics",
			Message:   redactor.Text(kubernetesErr.Error()),
		})
	}
	result.KubernetesReport = kubernetesReport
	result.Coverage[SourceKubernetes] = KubernetesCoverage(
		kubernetesReport,
		kubernetesErr,
	)
	if result.Coverage[SourceKubernetes].State == CoverageComplete {
		reportEvent(request.Progress, Event{
			Kind:    EventKubernetesComplete,
			Current: len(kubernetesReport.Namespaces),
			Total:   kubernetesReport.NamespacesRequested,
		})
	} else {
		reportEvent(request.Progress, Event{
			Kind:    EventKubernetesPartial,
			Current: len(kubernetesReport.Namespaces),
			Total:   kubernetesReport.NamespacesRequested,
		})
	}

	workloadNamespaces := workloadCollectionNamespaces(request.Kubernetes, kubernetesReport)
	reportEvent(request.Progress, Event{
		Kind:  EventWorkloadStarted,
		Total: len(workloadNamespaces),
	})
	workloadReport, workloadErr := collectors.Workload(
		ctx,
		workload.Config{
			Namespaces:       workloadNamespaces,
			Context:          request.Kubernetes.Context,
			Kubeconfig:       request.Kubernetes.Kubeconfig,
			Timeout:          request.Kubernetes.Timeout,
			MaxResponseBytes: workload.DefaultMaxResponseBytes,
			MaxSourceBytes:   workload.DefaultMaxSourceBytes,
			MaxTotalBytes:    workload.DefaultMaxTotalBytes,
			MaxNamespaces:    workload.DefaultMaxNamespaces,
			MaxDuration:      workload.DefaultMaxCollectionDuration,
			Progress: func(progress workload.Progress) {
				reportEvent(request.Progress, Event{
					Kind:    EventWorkloadProgress,
					Current: progress.Current,
					Total:   progress.Total,
				})
			},
		},
		runner,
		archive,
		redactor,
	)
	result.WorkloadReport = &workloadReport
	if ctx.Err() != nil {
		result.CanceledBeforeBundle = true
		return result, ctx.Err()
	}
	workloadReportData, err := MarshalWorkloadReport(workloadReport, redactor)
	if err != nil {
		return result, err
	}
	if err := archive.Add(workloadReportPath, workloadReportData); err != nil {
		return result, err
	}
	workloadCoverage := WorkloadCoverage(workloadReport, workloadErr)
	result.Coverage[SourceWorkload] = workloadCoverage
	workloadEvent := Event{
		Current: len(workloadReport.Namespaces),
		Total:   len(workloadNamespaces),
	}
	switch workloadCoverage.State {
	case CoverageComplete:
		workloadEvent.Kind = EventWorkloadComplete
	case CoveragePartial:
		workloadEvent.Kind = EventWorkloadPartial
	default:
		workloadEvent.Kind = EventWorkloadUnavailable
	}
	reportEvent(request.Progress, workloadEvent)
	kubernetesReport.Issues = append(
		kubernetesReport.Issues,
		workloadCollectionIssues(workloadReport, workloadErr, redactor)...,
	)

	if request.Prometheus != nil {
		reportEvent(request.Progress, Event{Kind: EventPrometheusStarted})
		prometheusConfig := effectivePrometheusConfig(
			*request.Prometheus,
			request.Kubernetes,
		)
		prometheusReport, prometheusErr := collectors.Prometheus(
			ctx,
			prometheusConfig,
			runner,
			sourceForwarder(collectors.PrometheusForwarder, collectors.Forwarder),
			archive,
			redactor,
		)
		result.PrometheusReport = &prometheusReport
		if ctx.Err() != nil {
			result.CanceledBeforeBundle = true
			return result, ctx.Err()
		}
		if errors.Is(prometheusErr, prometheus.ErrArtifactStaging) {
			return result, prometheusErr
		}
		prometheusCoverage := PrometheusCoverage(prometheusReport, prometheusErr)
		result.Coverage[SourcePrometheus] = prometheusCoverage
		switch prometheusCoverage.State {
		case CoverageComplete:
			reportEvent(request.Progress, Event{Kind: EventPrometheusComplete})
		case CoveragePartial:
			kubernetesReport.Issues = append(
				kubernetesReport.Issues,
				prometheusCollectionIssue(prometheusCoverage),
			)
			reportEvent(request.Progress, Event{
				Kind:   EventPrometheusPartial,
				Reason: prometheusCoverage.Reason,
			})
		default:
			kubernetesReport.Issues = append(
				kubernetesReport.Issues,
				prometheusCollectionIssue(prometheusCoverage),
			)
			reportEvent(request.Progress, Event{
				Kind:   EventPrometheusUnavailable,
				Reason: prometheusCoverage.Reason,
			})
		}
	}

	if request.Phoenix != nil {
		reportEvent(request.Progress, Event{Kind: EventPhoenixStarted})
		phoenixReport, phoenixErr := collectors.Phoenix(
			ctx,
			*request.Phoenix,
			runner,
			sourceForwarder(collectors.PhoenixForwarder, collectors.Forwarder),
			archive,
			redactor,
		)
		result.PhoenixReport = &phoenixReport
		if ctx.Err() != nil {
			result.CanceledBeforeBundle = true
			return result, ctx.Err()
		}
		if errors.Is(phoenixErr, phoenix.ErrArtifactStaging) {
			return result, phoenixErr
		}
		phoenixCoverage := PhoenixCoverage(phoenixReport, phoenixErr)
		result.Coverage[SourcePhoenix] = phoenixCoverage
		switch phoenixCoverage.State {
		case CoverageComplete:
			reportEvent(request.Progress, Event{Kind: EventPhoenixComplete})
		case CoveragePartial:
			kubernetesReport.Issues = append(
				kubernetesReport.Issues,
				phoenixCollectionIssue(phoenixCoverage),
			)
			reportEvent(request.Progress, Event{
				Kind:   EventPhoenixPartial,
				Reason: phoenixCoverage.Reason,
			})
		default:
			kubernetesReport.Issues = append(
				kubernetesReport.Issues,
				phoenixCollectionIssue(phoenixCoverage),
			)
			reportEvent(request.Progress, Event{
				Kind:   EventPhoenixUnavailable,
				Reason: phoenixCoverage.Reason,
			})
		}
	}

	var outcome zitadel.Outcome
	if request.Zitadel != nil {
		reportEvent(request.Progress, Event{Kind: EventZitadelStarted})
		outcome = collectors.Zitadel(ctx, *request.Zitadel, runner, redactor)
		result.ConnectivityReport = outcome.Report
		result.ConnectivityFailure = sanitizeReason(outcome.Reason, redactor)
		switch {
		case result.ConnectivityFailure != "":
			outcome.Reason = result.ConnectivityFailure
			result.Coverage[SourceZitadel] = ZitadelCoverage(true, outcome)
			kubernetesReport.Issues = append(kubernetesReport.Issues, kubernetes.Issue{
				Operation: "collect Zitadel connectivity probe",
				Resource: redactor.Text(
					request.Zitadel.Namespace + "/" +
						request.Zitadel.Pod + "/" +
						request.Zitadel.Container,
				),
				Message: result.ConnectivityFailure,
			})
			reportEvent(request.Progress, Event{
				Kind:   EventZitadelUnavailable,
				Reason: result.ConnectivityFailure,
			})
		case outcome.Report == nil:
			result.ConnectivityFailure = reasonMissingReport
			result.Coverage[SourceZitadel] = Coverage{
				State:  CoverageUnavailable,
				Reason: reasonMissingReport,
			}
			kubernetesReport.Issues = append(kubernetesReport.Issues, kubernetes.Issue{
				Operation: "collect Zitadel connectivity probe",
				Resource: redactor.Text(
					request.Zitadel.Namespace + "/" +
						request.Zitadel.Pod + "/" +
						request.Zitadel.Container,
				),
				Message: reasonMissingReport,
			})
			reportEvent(request.Progress, Event{
				Kind:   EventZitadelUnavailable,
				Reason: reasonMissingReport,
			})
		case len(outcome.Data) == 0:
			result.ConnectivityReport = nil
			result.ConnectivityFailure = reasonMissingArtifact
			result.Coverage[SourceZitadel] = Coverage{
				State:  CoverageUnavailable,
				Reason: reasonMissingArtifact,
			}
			kubernetesReport.Issues = append(kubernetesReport.Issues, kubernetes.Issue{
				Operation: "collect Zitadel connectivity probe",
				Resource: redactor.Text(
					request.Zitadel.Namespace + "/" +
						request.Zitadel.Pod + "/" +
						request.Zitadel.Container,
				),
				Message: reasonMissingArtifact,
			})
			reportEvent(request.Progress, Event{
				Kind:   EventZitadelUnavailable,
				Reason: reasonMissingArtifact,
			})
		default:
			result.Coverage[SourceZitadel] = ZitadelCoverage(true, outcome)
			if err := archive.Add(zitadelArtifactPath, outcome.Data); err != nil {
				return result, err
			}
			if outcome.Report.FailedChecks() > 0 {
				reportEvent(request.Progress, Event{
					Kind: EventZitadelDiagnosticFailure,
				})
			} else {
				reportEvent(request.Progress, Event{Kind: EventZitadelPassed})
			}
		}
	}
	result.KubernetesReport = kubernetesReport
	result.Status = AggregateStatus(result.Coverage)

	issuesData, err := MarshalIssues(kubernetesReport.Issues)
	if err != nil {
		return result, err
	}
	if len(issuesData) > 0 {
		if err := archive.Add(issuesArtifactPath, issuesData); err != nil {
			return result, err
		}
	}

	generatedAt := request.CurrentTime().UTC()
	customerContext := BuildCustomerContext(
		request.Activity,
		request.Problem,
		redactor,
	)
	reportEvent(request.Progress, Event{Kind: EventArchiveSummary})
	summary := BuildSummary(
		generatedAt,
		result.Status,
		kubernetesReport,
		customerContext,
		request.Zitadel != nil,
		result.ConnectivityReport,
		result.ConnectivityFailure,
		SummaryOptions{
			Prometheus: PrometheusSummary{
				Requested: request.Prometheus != nil,
				Coverage:  result.Coverage[SourcePrometheus],
				Report:    result.PrometheusReport,
			},
			Phoenix: PhoenixSummary{
				Requested: request.Phoenix != nil,
				Coverage:  result.Coverage[SourcePhoenix],
				Report:    result.PhoenixReport,
			},
		},
	)
	if err := archive.Add(summaryArtifactPath, []byte(summary)); err != nil {
		return result, err
	}

	connectivityMetadata := BuildConnectivityMetadata(
		request.Zitadel != nil,
		zitadelNamespace(request.Zitadel),
		zitadelPod(request.Zitadel),
		zitadelContainer(request.Zitadel),
		zitadelProbeTimeout(request.Zitadel),
		zitadel.Outcome{
			Report: result.ConnectivityReport,
			Reason: result.ConnectivityFailure,
		},
		redactor,
	)
	prometheusMetadata := BuildPrometheusMetadata(
		request.Prometheus,
		result.PrometheusReport,
		result.Coverage[SourcePrometheus],
		redactor,
	)
	phoenixMetadata := BuildPhoenixMetadata(
		request.Phoenix,
		result.PhoenixReport,
		result.Coverage[SourcePhoenix],
		redactor,
	)
	ruleset := redactor.Ruleset()
	selectedNamespaces := request.Kubernetes.Namespaces
	if len(selectedNamespaces) == 0 && request.Kubernetes.Namespace != "" {
		selectedNamespaces = []string{request.Kubernetes.Namespace}
	}
	result.ArchivePath, err = archive.FinalizeContext(ctx, bundle.Manifest{
		CollectorVersion: request.CollectorVersion,
		GeneratedAt:      generatedAt,
		Redaction: map[string]string{
			"version": ruleset.Version,
			"sha256":  ruleset.SHA256,
		},
		CustomerContext: customerContext,
		Collection: BuildCollectionManifest(
			result.Status,
			selectedNamespaces,
			request.Kubernetes.AllNamespaces,
			request.Kubernetes.ExcludeSystemNamespaces,
			request.Kubernetes.Selector,
			request.Kubernetes.Since,
			request.Kubernetes.MaxMetadataBytes,
			kubernetesReport,
			connectivityMetadata,
			redactor,
			CollectionManifestOptions{
				Coverage:   result.Coverage,
				Prometheus: prometheusMetadata,
				Phoenix:    phoenixMetadata,
			},
		),
	})
	return result, err
}

func validateDependencies(
	ctx context.Context,
	runner kubernetes.Runner,
	archive Archive,
	redactor *redact.Redactor,
	collectors Collectors,
	currentTime func() time.Time,
	requirePrometheus bool,
	requirePhoenix bool,
	requireZitadel bool,
) error {
	switch {
	case ctx == nil:
		return errors.New("collection context is required")
	case runner == nil:
		return errors.New("Kubernetes runner is required")
	case archive == nil:
		return errors.New("bundle archive is required")
	case redactor == nil || !redactor.Ready():
		return errors.New("configured redactor is required")
	case currentTime == nil:
		return errors.New("current time source is required")
	case collectors.Kubernetes == nil:
		return errors.New("Kubernetes collector is required")
	case collectors.Workload == nil:
		return errors.New("workload collector is required")
	case requirePrometheus && collectors.Prometheus == nil:
		return errors.New("Prometheus collector is required")
	case requirePrometheus &&
		sourceForwarder(collectors.PrometheusForwarder, collectors.Forwarder) == nil:
		return errors.New("Prometheus telemetry forwarder is required")
	case requirePhoenix && collectors.Phoenix == nil:
		return errors.New("Phoenix collector is required")
	case requirePhoenix &&
		sourceForwarder(collectors.PhoenixForwarder, collectors.Forwarder) == nil:
		return errors.New("Phoenix telemetry forwarder is required")
	case requireZitadel && collectors.Zitadel == nil:
		return errors.New("Zitadel collector is required")
	default:
		return nil
	}
}

func sourceForwarder(
	specific telemetry.Forwarder,
	shared telemetry.Forwarder,
) telemetry.Forwarder {
	if specific != nil {
		return specific
	}
	return shared
}

func sanitizeReason(reason string, redactor *redact.Redactor) string {
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, redactor.Text(reason))
}

func reportEvent(progress func(Event), event Event) {
	if progress != nil {
		progress(event)
	}
}

func workloadCollectionNamespaces(
	config kubernetes.Config,
	report kubernetes.Report,
) []string {
	var namespaces []string
	if config.AllNamespaces {
		namespaces = report.CollectionNamespaces
	} else if len(config.Namespaces) > 0 {
		namespaces = config.Namespaces
	} else if config.Namespace != "" {
		namespaces = []string{config.Namespace}
	}
	seen := make(map[string]struct{}, len(namespaces))
	normalized := make([]string, 0, len(namespaces))
	for _, value := range namespaces {
		namespace := strings.TrimSpace(value)
		if _, exists := seen[namespace]; exists {
			continue
		}
		seen[namespace] = struct{}{}
		normalized = append(normalized, namespace)
	}
	return normalized
}

func effectivePrometheusConfig(
	config prometheus.Config,
	kubernetesConfig kubernetes.Config,
) prometheus.Config {
	if kubernetesConfig.AllNamespaces {
		config.ExcludeSystemNamespaces =
			kubernetesConfig.ExcludeSystemNamespaces
	}
	return config
}

func workloadCollectionIssues(
	report workload.Report,
	collectionErr error,
	redactor *redact.Redactor,
) []kubernetes.Issue {
	issues := make([]kubernetes.Issue, 0)
	if collectionErr != nil {
		issues = append(issues, kubernetes.Issue{
			Operation: "collect workload context",
			Message:   sanitizeReason(collectionErr.Error(), redactor),
		})
	}
	for _, coverage := range report.Coverage {
		if coverage.State == workload.CoverageCollected {
			continue
		}
		message := "workload context " + string(coverage.State)
		if coverage.Reason != "" {
			message += ": " + coverage.Reason
		}
		if diagnostic := sanitizeReason(coverage.Diagnostic, redactor); diagnostic != "" {
			message += ": " + diagnostic
		}
		issues = append(issues, kubernetes.Issue{
			Operation: "collect workload context",
			Resource: redactor.Text(
				coverage.Namespace + "/" + coverage.Source,
			),
			Message: redactor.Text(message),
		})
	}
	return issues
}

func prometheusCollectionIssue(coverage Coverage) kubernetes.Issue {
	return kubernetes.Issue{
		Operation: "collect Prometheus telemetry",
		Message: "Prometheus telemetry " +
			coverage.State.String() + ": " + coverage.Reason,
	}
}

func phoenixCollectionIssue(coverage Coverage) kubernetes.Issue {
	return kubernetes.Issue{
		Operation: "collect Phoenix telemetry",
		Message: "Phoenix telemetry " +
			coverage.State.String() + ": " + coverage.Reason,
	}
}

func zitadelNamespace(config *zitadel.Config) string {
	if config == nil {
		return ""
	}
	return config.Namespace
}

func zitadelPod(config *zitadel.Config) string {
	if config == nil {
		return ""
	}
	return config.Pod
}

func zitadelContainer(config *zitadel.Config) string {
	if config == nil {
		return ""
	}
	return config.Container
}

func zitadelProbeTimeout(config *zitadel.Config) time.Duration {
	if config == nil {
		return 0
	}
	return config.ProbeTimeout
}
