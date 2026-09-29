package collection

import (
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/phoenix"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	reasonCollectionError              = "collection_error"
	reasonIssuesReported               = "issues_reported"
	reasonMissingReport                = "missing_report"
	reasonMissingArtifact              = "missing_artifact"
	reasonPrometheusInvalidReport      = "invalid_report"
	reasonPrometheusUnavailable        = "collection_unavailable"
	reasonPrometheusCoverageIncomplete = "query_coverage_incomplete"
	reasonPhoenixInvalidReport         = "invalid_report"
	reasonPhoenixUnavailable           = "collection_unavailable"
	reasonPhoenixCoverageIncomplete    = "trace_coverage_incomplete"
)

// KubernetesCoverage derives coverage from a completed Kubernetes collection.
// Errors are represented by a stable reason code rather than their raw text.
func KubernetesCoverage(report kubernetes.Report, collectionErr error) Coverage {
	if collectionErr != nil {
		return Coverage{
			State:  CoveragePartial,
			Reason: reasonCollectionError,
		}
	}
	if len(report.Issues) != 0 {
		return Coverage{
			State:  CoveragePartial,
			Reason: reasonIssuesReported,
		}
	}
	return Coverage{State: CoverageComplete}
}

// WorkloadCoverage derives source coverage from normalized workload artifacts
// and their per-resource coverage entries.
func WorkloadCoverage(report workload.Report, collectionErr error) Coverage {
	coverage := Coverage{
		RetainedBytes: int64(report.RetainedBytes),
		RecordCount:   int64(report.RetainedRecords),
		Truncated:     report.Truncated,
	}
	if collectionErr != nil {
		coverage.State = CoverageUnavailable
		if report.RetainedRecords > 0 {
			coverage.State = CoveragePartial
		}
		coverage.Reason = reasonCollectionError
		return coverage
	}
	if err := workload.ValidateCompleteCoverage(report); err != nil {
		coverage.State = CoveragePartial
		coverage.Reason = reasonIssuesReported
		return coverage
	}
	coverage.State = CoverageComplete
	return coverage
}

// PrometheusCoverage derives source coverage from the collector's sanitized
// report. Raw collector errors and diagnostics never become coverage reasons.
func PrometheusCoverage(report prometheus.Report, collectionErr error) Coverage {
	coverage := Coverage{
		RequestedStart: prometheusReportTime(report.RequestedStart),
		RequestedEnd:   prometheusReportTime(report.RequestedEnd),
		ActualStart:    prometheusReportTime(report.ActualStart),
		ActualEnd:      prometheusReportTime(report.ActualEnd),
		RetainedBytes:  max(report.RetainedBytes, 0),
		RecordCount:    int64(max(report.RetainedRecords, 0)),
		Truncated:      report.Truncated,
	}
	completeErr := prometheus.ValidateCompleteCoverage(report)
	if collectionErr == nil && completeErr == nil {
		coverage.State = CoverageComplete
		return coverage
	}

	switch {
	case report.State == prometheus.ReportPartial:
		coverage.State = CoveragePartial
	case report.State == prometheus.ReportFailed:
		coverage.State = CoverageUnavailable
	case collectionErr != nil && report.RetainedRecords <= 0:
		coverage.State = CoverageUnavailable
	case report.Truncated || prometheusReportHasIncompleteQuery(report):
		coverage.State = CoveragePartial
	case report.RetainedRecords <= 0:
		coverage.State = CoverageUnavailable
	default:
		coverage.State = CoveragePartial
	}

	switch {
	case collectionErr != nil:
		coverage.Reason = reasonCollectionError
	case stablePrometheusReason(report.Reason) != "":
		coverage.Reason = stablePrometheusReason(report.Reason)
	case stablePrometheusCoverageReason(report) != "":
		coverage.Reason = stablePrometheusCoverageReason(report)
	case report.State == prometheus.ReportComplete && completeErr != nil:
		coverage.Reason = reasonPrometheusInvalidReport
	case coverage.State == CoveragePartial:
		coverage.Reason = reasonPrometheusCoverageIncomplete
	default:
		coverage.Reason = reasonPrometheusUnavailable
	}
	return coverage
}

// PhoenixCoverage derives source coverage from the collector's sanitized
// report. Only stable Phoenix reason codes are propagated.
func PhoenixCoverage(report phoenix.Report, collectionErr error) Coverage {
	coverage := Coverage{
		RequestedStart: phoenixReportTime(report.RequestedStart),
		RequestedEnd:   phoenixReportTime(report.RequestedEnd),
		ActualStart:    phoenixReportTime(report.ActualStart),
		ActualEnd:      phoenixReportTime(report.ActualEnd),
		RetainedBytes:  max(report.Coverage.RetainedBytes, 0),
		RecordCount:    int64(max(report.Coverage.TracesRetained, 0)),
		Truncated:      report.Coverage.Truncated,
	}
	completeErr := phoenix.ValidateCompleteCoverage(report)
	if collectionErr == nil && completeErr == nil {
		coverage.State = CoverageComplete
		return coverage
	}

	switch {
	case report.State == phoenix.ReportPartial:
		coverage.State = CoveragePartial
	case report.State == phoenix.ReportFailed:
		coverage.State = CoverageUnavailable
	case collectionErr != nil && coverage.RecordCount == 0:
		coverage.State = CoverageUnavailable
	case coverage.Truncated || coverage.RecordCount > 0:
		coverage.State = CoveragePartial
	default:
		coverage.State = CoverageUnavailable
	}
	switch {
	case collectionErr != nil:
		coverage.Reason = reasonCollectionError
	case stablePhoenixReason(report.Reason) != "":
		coverage.Reason = stablePhoenixReason(report.Reason)
	case report.State == phoenix.ReportComplete && completeErr != nil:
		coverage.Reason = reasonPhoenixInvalidReport
	case coverage.State == CoveragePartial:
		coverage.Reason = reasonPhoenixCoverageIncomplete
	default:
		coverage.Reason = reasonPhoenixUnavailable
	}
	return coverage
}

// ZitadelCoverage derives coverage from the optional Zitadel probe. A probe
// report is complete even when it contains failed diagnostic checks because
// those checks are collected evidence. An enabled probe with no result is
// unavailable so incomplete outcomes fail conservatively.
func ZitadelCoverage(enabled bool, outcome zitadel.Outcome) Coverage {
	if !enabled {
		return Coverage{State: CoverageNotRequested}
	}
	if outcome.Reason != "" {
		return Coverage{
			State:  CoveragePartial,
			Reason: outcome.Reason,
		}
	}
	if outcome.Report != nil {
		return Coverage{State: CoverageComplete}
	}
	return Coverage{
		State:  CoverageUnavailable,
		Reason: reasonMissingReport,
	}
}

// AggregateStatus returns the schema-4 manifest collection status. Coverage
// must contain exactly every supported source; missing or unsupported sources
// fail closed as partial. Invalid, partial, and unavailable states also make the
// aggregate partial.
func AggregateStatus(coverage map[Source]Coverage) string {
	supported := SupportedSources()
	if len(coverage) != len(supported) {
		return CoveragePartial.String()
	}
	for _, source := range supported {
		sourceCoverage, exists := coverage[source]
		if !exists {
			return CoveragePartial.String()
		}
		switch sourceCoverage.State {
		case CoverageComplete, CoverageNotRequested:
			continue
		default:
			return CoveragePartial.String()
		}
	}
	return CoverageComplete.String()
}

func prometheusReportTime(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}

func prometheusReportHasIncompleteQuery(report prometheus.Report) bool {
	for _, query := range report.Coverage {
		switch query.State {
		case prometheus.CoverageCollected, prometheus.CoverageNoData:
			if query.Truncated {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func stablePrometheusCoverageReason(report prometheus.Report) string {
	for _, query := range report.Coverage {
		if reason := stablePrometheusReason(query.Reason); reason != "" {
			return reason
		}
	}
	return ""
}

func stablePrometheusReason(reason string) string {
	switch reason {
	case "query_limit_exceeded",
		"series_limit_exceeded",
		"sample_limit_exceeded",
		"per_query_byte_budget_exceeded",
		"total_byte_budget_exceeded",
		"response_byte_limit_exceeded",
		"invalid_response",
		"http_status_error",
		"request_failed",
		"request_deadline_exceeded",
		"idle_deadline_exceeded",
		"discovery_failed",
		"forward_failed",
		"invalid_tunnel_endpoint",
		"tunnel_unavailable",
		"tunnel_cleanup_failed",
		"artifact_staging_failed",
		"collection_canceled",
		reasonPrometheusCoverageIncomplete:
		return reason
	default:
		return ""
	}
}

func phoenixReportTime(value string) *time.Time {
	if value == "" {
		return nil
	}
	return prometheusReportTime(value)
}

func stablePhoenixReason(reason string) string {
	switch reason {
	case "project_limit_exceeded",
		"trace_limit_exceeded",
		"span_limit_exceeded",
		"page_limit_exceeded",
		"per_trace_byte_budget_exceeded",
		"total_byte_budget_exceeded",
		"response_byte_limit_exceeded",
		"invalid_response",
		"http_status_error",
		"request_failed",
		"request_deadline_exceeded",
		"idle_deadline_exceeded",
		"discovery_failed",
		"forward_failed",
		"invalid_tunnel_endpoint",
		"tunnel_unavailable",
		"tunnel_cleanup_failed",
		"artifact_staging_failed",
		"collection_canceled",
		reasonPhoenixCoverageIncomplete:
		return reason
	default:
		return ""
	}
}
