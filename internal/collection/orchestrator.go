package collection

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	zitadelArtifactPath = "connectivity/zitadel.json"
	issuesArtifactPath  = "collection-issues.jsonl"
	summaryArtifactPath = "summary.md"
)

// EventKind identifies a collection event that the application may present.
type EventKind string

const (
	EventZitadelStarted           EventKind = "zitadel_started"
	EventZitadelUnavailable       EventKind = "zitadel_unavailable"
	EventZitadelDiagnosticFailure EventKind = "zitadel_diagnostic_failure"
	EventZitadelPassed            EventKind = "zitadel_passed"
)

// Event carries a stable event kind and an optional sanitized reason.
type Event struct {
	Kind   EventKind
	Reason string
}

// Request contains validated inputs for one collection.
type Request struct {
	CollectorVersion string
	GeneratedAt      time.Time
	Activity         string
	Problem          string
	Kubernetes       kubernetes.Config
	Zitadel          *zitadel.Config
	Progress         func(Event)
}

// Result describes the completed collection and published archive.
type Result struct {
	ArchivePath          string
	Status               string
	Coverage             map[Source]Coverage
	KubernetesReport     kubernetes.Report
	ConnectivityReport   *zitadel.Report
	ConnectivityFailure  string
	CanceledBeforeBundle bool
}

// Archive receives artifacts and publishes the final bundle.
type Archive interface {
	kubernetes.Sink
	FinalizeContext(context.Context, bundle.Manifest) (string, error)
}

// KubernetesCollector collects Kubernetes artifacts into the supplied sink.
type KubernetesCollector func(
	context.Context,
	kubernetes.Config,
	kubernetes.Runner,
	kubernetes.Sink,
	*redact.Redactor,
) (kubernetes.Report, error)

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
	Zitadel    ZitadelCollector
}

// DefaultCollectors returns the production source collectors.
func DefaultCollectors() Collectors {
	return Collectors{
		Kubernetes: kubernetes.Collect,
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
		request.Zitadel != nil,
	); err != nil {
		return Result{}, err
	}
	requested := []Source{SourceKubernetes}
	if request.Zitadel != nil {
		requested = append(requested, SourceZitadel)
	}
	result := Result{Coverage: InitializeCoverage(requested)}

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

	customerContext := BuildCustomerContext(
		request.Activity,
		request.Problem,
		redactor,
	)
	summary := BuildSummary(
		request.GeneratedAt,
		result.Status,
		kubernetesReport,
		customerContext,
		request.Zitadel != nil,
		result.ConnectivityReport,
		result.ConnectivityFailure,
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
	ruleset := redactor.Ruleset()
	selectedNamespaces := request.Kubernetes.Namespaces
	if len(selectedNamespaces) == 0 && request.Kubernetes.Namespace != "" {
		selectedNamespaces = []string{request.Kubernetes.Namespace}
	}
	result.ArchivePath, err = archive.FinalizeContext(ctx, bundle.Manifest{
		CollectorVersion: request.CollectorVersion,
		GeneratedAt:      request.GeneratedAt,
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
	requireZitadel bool,
) error {
	switch {
	case ctx == nil:
		return errors.New("collection context is required")
	case runner == nil:
		return errors.New("Kubernetes runner is required")
	case archive == nil:
		return errors.New("bundle archive is required")
	case redactor == nil:
		return errors.New("redactor is required")
	case collectors.Kubernetes == nil:
		return errors.New("Kubernetes collector is required")
	case requireZitadel && collectors.Zitadel == nil:
		return errors.New("Zitadel collector is required")
	default:
		return nil
	}
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
