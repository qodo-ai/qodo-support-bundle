package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
)

const progressIssueGuidance = "Review collection-issues.jsonl for details."

type progressSummaryOutcome struct {
	Label   string
	Status  progressStatus
	Message string
}

type progressSummaryOptions struct {
	PrometheusNamespace string
	PhoenixNamespace    string
	ArchivePath         string
	ArchiveSize         int64
	CleanupIncomplete   bool
}

func sanitizeProgressSummary(summary progressSummary) progressSummary {
	summary.ArchivePath = terminalLine(summary.ArchivePath)
	summary.Namespaces = max(summary.Namespaces, 0)
	summary.Pods = max(summary.Pods, 0)
	summary.LogStreams = max(summary.LogStreams, 0)
	summary.WarningCount = max(summary.WarningCount, 0)
	for index := range summary.SourceOutcomes {
		summary.SourceOutcomes[index].Label = terminalLine(summary.SourceOutcomes[index].Label)
		summary.SourceOutcomes[index].Message = terminalLine(summary.SourceOutcomes[index].Message)
	}
	return summary
}

func buildProgressSummary(
	result collection.Result,
	options progressSummaryOptions,
) progressSummary {
	summary := progressSummary{
		ArchivePath: options.ArchivePath,
		ArchiveSize: options.ArchiveSize,
		Namespaces:  len(result.KubernetesReport.Namespaces),
		Pods:        result.KubernetesReport.Pods,
		LogStreams:  result.KubernetesReport.LogStreamsCollected,
	}
	for _, source := range []collection.Source{
		collection.SourceKubernetes,
		collection.SourceWorkload,
		collection.SourcePrometheus,
		collection.SourcePhoenix,
		collection.SourceZitadel,
	} {
		coverage, exists := result.Coverage[source]
		if !exists || coverage.State == collection.CoverageNotRequested {
			continue
		}
		outcome := progressSummaryOutcome{
			Label:  progressSourceLabel(source),
			Status: progressCompleted,
		}
		if coverage.State != collection.CoverageComplete {
			outcome.Label = progressIncompleteSourceLabel(source, coverage.State)
			outcome.Status = progressWarning
			outcome.Message = safeProgressReason(
				source,
				progressSourceReason(result, source, coverage.Reason),
				options,
			)
		} else if source == collection.SourceZitadel &&
			result.ConnectivityReport != nil &&
			result.ConnectivityReport.FailedChecks() > 0 {
			outcome.Label = "Zitadel diagnostics reported failures"
			outcome.Status = progressWarning
			outcome.Message = progressIssueGuidance
		}
		if outcome.Status != progressCompleted {
			summary.WarningCount++
		}
		summary.SourceOutcomes = append(summary.SourceOutcomes, outcome)
	}
	if options.CleanupIncomplete {
		summary.SourceOutcomes = append(summary.SourceOutcomes, progressSummaryOutcome{
			Label:   "Temporary data cleanup incomplete",
			Status:  progressWarning,
			Message: "The bundle was saved, but temporary collection data could not be fully removed.",
		})
		summary.WarningCount++
	}
	if result.Status == collection.CoveragePartial.String() && summary.WarningCount == 0 {
		summary.SourceOutcomes = append(summary.SourceOutcomes, progressSummaryOutcome{
			Label:   "Collection coverage incomplete",
			Status:  progressWarning,
			Message: progressIssueGuidance,
		})
		summary.WarningCount = 1
	}
	return summary
}

func progressSourceReason(
	result collection.Result,
	source collection.Source,
	fallback string,
) string {
	switch source {
	case collection.SourcePrometheus:
		if result.PrometheusReport != nil && knownProgressReason(result.PrometheusReport.Reason) {
			return result.PrometheusReport.Reason
		}
	case collection.SourcePhoenix:
		if result.PhoenixReport != nil && knownProgressReason(result.PhoenixReport.Reason) {
			return result.PhoenixReport.Reason
		}
	}
	return fallback
}

func progressSourceLabel(source collection.Source) string {
	switch source {
	case collection.SourceKubernetes:
		return "Read-only Kubernetes data"
	case collection.SourceWorkload:
		return "Workload and service context"
	case collection.SourcePrometheus:
		return "Prometheus telemetry"
	case collection.SourcePhoenix:
		return "Phoenix telemetry"
	case collection.SourceZitadel:
		return "Zitadel connectivity"
	default:
		return "Diagnostics"
	}
}

func progressIncompleteSourceLabel(
	source collection.Source,
	state collection.CoverageState,
) string {
	switch source {
	case collection.SourcePrometheus:
		if state == collection.CoverageUnavailable {
			return "Prometheus not collected"
		}
		return "Prometheus partially collected"
	case collection.SourcePhoenix:
		if state == collection.CoverageUnavailable {
			return "Phoenix not collected"
		}
		return "Phoenix partially collected"
	case collection.SourceZitadel:
		return "Zitadel connectivity incomplete"
	case collection.SourceWorkload:
		return "Workload and service context incomplete"
	case collection.SourceKubernetes:
		return "Read-only Kubernetes data incomplete"
	default:
		return "Diagnostics incomplete"
	}
}

func knownProgressReason(reason string) bool {
	switch reason {
	case "service_absent",
		"discovery_failed",
		"service_ambiguous",
		"collection_error",
		"collection_unavailable",
		"issues_reported",
		"missing_report",
		"missing_artifact",
		"invalid_report",
		"query_coverage_incomplete",
		"trace_coverage_incomplete",
		"query_limit_exceeded",
		"series_limit_exceeded",
		"sample_limit_exceeded",
		"project_limit_exceeded",
		"trace_limit_exceeded",
		"span_limit_exceeded",
		"page_limit_exceeded",
		"response_byte_limit_exceeded",
		"per_query_byte_budget_exceeded",
		"per_trace_byte_budget_exceeded",
		"total_byte_budget_exceeded",
		"timeout",
		"request_deadline_exceeded",
		"idle_deadline_exceeded",
		"forward_failed",
		"tunnel_unavailable",
		"collection_canceled":
		return true
	default:
		return false
	}
}

func safeProgressReason(
	source collection.Source,
	reason string,
	options progressSummaryOptions,
) string {
	namespace := ""
	sourceName := progressSourceLabel(source)
	switch source {
	case collection.SourcePrometheus:
		namespace = terminalLine(options.PrometheusNamespace)
		sourceName = "Prometheus"
	case collection.SourcePhoenix:
		namespace = terminalLine(options.PhoenixNamespace)
		sourceName = "Phoenix"
	}
	switch reason {
	case "service_absent":
		if namespace != "" {
			return fmt.Sprintf("No %s service found in %s.", sourceName, namespace)
		}
		return fmt.Sprintf("No %s service was found.", sourceName)
	case "discovery_failed":
		if namespace != "" {
			return fmt.Sprintf("%s could not be discovered in %s.", sourceName, namespace)
		}
		return fmt.Sprintf("%s could not be discovered.", sourceName)
	case "service_ambiguous":
		if namespace != "" {
			return fmt.Sprintf("Multiple %s services matched in %s.", sourceName, namespace)
		}
		return fmt.Sprintf("Multiple %s services matched.", sourceName)
	case "query_limit_exceeded", "series_limit_exceeded", "sample_limit_exceeded",
		"project_limit_exceeded", "trace_limit_exceeded", "span_limit_exceeded",
		"page_limit_exceeded", "response_byte_limit_exceeded",
		"per_query_byte_budget_exceeded", "per_trace_byte_budget_exceeded",
		"total_byte_budget_exceeded":
		return sourceName + " reached a configured collection limit. " + progressIssueGuidance
	case "query_coverage_incomplete", "trace_coverage_incomplete":
		return sourceName + " coverage is incomplete. " + progressIssueGuidance
	case "timeout", "request_deadline_exceeded", "idle_deadline_exceeded":
		return sourceName + " collection timed out. " + progressIssueGuidance
	case "forward_failed", "tunnel_unavailable":
		return sourceName + " could not establish a local telemetry connection. " +
			progressIssueGuidance
	case "collection_canceled":
		return sourceName + " collection was canceled. " + progressIssueGuidance
	default:
		return progressIssueGuidance
	}
}

func progressSummaryLines(
	summary progressSummary,
	duration time.Duration,
	unicode bool,
) []string {
	lines := []string{"Qodo Scout"}
	switch summary.WarningCount {
	case 0:
		lines = append(lines, "Bundle created")
	case 1:
		lines = append(lines, "Bundle created"+separatorForUnicode(unicode)+"1 warning")
	default:
		lines = append(lines, fmt.Sprintf(
			"Bundle created%s%d warnings",
			separatorForUnicode(unicode),
			summary.WarningCount,
		))
	}
	separator := " | "
	if unicode {
		separator = " · "
	}
	lines = append(lines, strings.Join([]string{
		fmt.Sprintf("%d %s", summary.Namespaces, plural(summary.Namespaces, "namespace", "namespaces")),
		fmt.Sprintf("%d %s", summary.Pods, plural(summary.Pods, "pod", "pods")),
		fmt.Sprintf("%d %s", summary.LogStreams, plural(summary.LogStreams, "log source", "log sources")),
		formatProgressDuration(max(duration, 0)),
	}, separator))
	lines = append(lines, "")
	for _, outcome := range summary.SourceOutcomes {
		lines = append(lines, progressSummaryMarker(outcome.Status, unicode)+" "+outcome.Label)
		if outcome.Message != "" {
			lines = append(lines, "  "+outcome.Message)
		}
	}
	archive := progressSummaryMarker(progressCompleted, unicode) +
		" Archive prepared with redaction"
	if summary.ArchiveSize >= 0 {
		archive += separator + formatProgressBytes(summary.ArchiveSize)
	}
	lines = append(lines, archive)
	if summary.ArchivePath != "" {
		lines = append(lines, "", archivePathLine(summary.ArchivePath, false))
	}
	lines = append(lines, progressSummaryMarker(progressWarning, unicode)+" Review before sharing")
	return lines
}

func separatorForUnicode(unicode bool) string {
	if unicode {
		return " · "
	}
	return " | "
}

func progressSummaryMarker(status progressStatus, unicode bool) string {
	if unicode {
		switch status {
		case progressCompleted:
			return "✓"
		case progressFailed:
			return "✗"
		default:
			return "!"
		}
	}
	switch status {
	case progressCompleted:
		return "[ok]"
	case progressFailed:
		return "[x]"
	default:
		return "[!]"
	}
}
