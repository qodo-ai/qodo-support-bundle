package collection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

// CollectionManifestOptions adds source-wide collection metadata while keeping
// the existing manifest fields stable.
type CollectionManifestOptions struct {
	Coverage   map[Source]Coverage
	Prometheus map[string]any
}

// PrometheusSummary supplies the optional human-readable Prometheus section.
type PrometheusSummary struct {
	Requested bool
	Coverage  Coverage
	Report    *prometheus.Report
}

// BuildCustomerContext returns the non-empty, sanitized customer descriptions.
func BuildCustomerContext(
	activity string,
	problem string,
	redactor *redact.Redactor,
) map[string]string {
	context := make(map[string]string, 2)
	if value := strings.TrimSpace(redactor.Text(activity)); value != "" {
		context["activity"] = value
	}
	if value := strings.TrimSpace(redactor.Text(problem)); value != "" {
		context["problem"] = value
	}
	return context
}

// BuildConnectivityMetadata returns the schema-4 connectivity metadata.
func BuildConnectivityMetadata(
	enabled bool,
	namespace string,
	pod string,
	container string,
	probeTimeout time.Duration,
	outcome zitadel.Outcome,
	redactor *redact.Redactor,
) map[string]any {
	metadata := map[string]any{"enabled": enabled}
	if !enabled {
		return metadata
	}

	metadata["namespace"] = redactor.Text(namespace)
	metadata["pod"] = redactor.Text(pod)
	metadata["container"] = redactor.Text(container)
	metadata["probe_timeout"] = probeTimeout.String()
	switch {
	case outcome.Reason != "":
		metadata["collection_status"] = CoveragePartial.String()
		metadata["reason"] = outcome.Reason
	case outcome.Report != nil:
		metadata["collection_status"] = CoverageComplete.String()
		metadata["failed_checks"] = outcome.Report.FailedChecks()
	default:
		metadata["collection_status"] = CoveragePartial.String()
		metadata["reason"] = reasonMissingReport
	}
	return metadata
}

// BuildCollectionManifest returns the collection section of a schema-4 manifest.
func BuildCollectionManifest(
	status string,
	selectedNamespaces []string,
	allNamespaces bool,
	excludeSystemNamespaces bool,
	selector string,
	since time.Duration,
	maxMetadataBytes int64,
	report kubernetes.Report,
	connectivity map[string]any,
	redactor *redact.Redactor,
	options ...CollectionManifestOptions,
) map[string]any {
	manifestNamespaces := selectedNamespaces
	namespaceValue := strings.Join(selectedNamespaces, ",")
	if allNamespaces {
		manifestNamespaces = report.Namespaces
		namespaceValue = "*"
	}
	coverage := InitializeCoverage(nil)
	prometheusMetadata := map[string]any{"enabled": false}
	if len(options) > 0 {
		coverage = completeCoverageMap(options[0].Coverage)
		if options[0].Prometheus != nil {
			prometheusMetadata = options[0].Prometheus
		}
	}
	return map[string]any{
		"status":                    status,
		"namespace":                 redactor.Text(namespaceValue),
		"namespaces":                redactStrings(manifestNamespaces, redactor),
		"all_namespaces":            allNamespaces,
		"exclude_system_namespaces": excludeSystemNamespaces,
		"selector":                  redactor.Text(selector),
		"since":                     since.String(),
		"max_metadata_bytes":        maxMetadataBytes,
		"kubernetes":                report,
		"connectivity":              connectivity,
		"coverage":                  coverage,
		"prometheus":                prometheusMetadata,
	}
}

// BuildPrometheusMetadata returns only bounded, non-sensitive configuration
// and sanitized report metadata. It deliberately excludes queries, labels,
// endpoints, command output, credentials, and raw diagnostics.
func BuildPrometheusMetadata(
	config *prometheus.Config,
	report *prometheus.Report,
	coverage Coverage,
	redactor *redact.Redactor,
) map[string]any {
	metadata := map[string]any{"enabled": config != nil}
	if config == nil {
		return metadata
	}

	effective := config.WithDefaults()
	metadata["namespace"] = summaryValue(redactor.Text(config.Namespace))
	metadata["namespaces"] = sanitizeMetadataStrings(effective.Namespaces, redactor)
	metadata["all_namespaces"] = effective.AllNamespaces
	metadata["catalog_version"] = prometheus.CatalogVersion
	addMetadataTime(metadata, "configured_start", config.Start)
	addMetadataTime(metadata, "configured_end", config.End)
	metadata["command_timeout"] = effective.CommandTimeout.String()
	metadata["discovery_timeout"] = effective.DiscoveryTimeout.String()
	metadata["readiness_timeout"] = effective.ReadinessTimeout.String()
	metadata["connect_timeout"] = effective.ConnectTimeout.String()
	metadata["request_timeout"] = effective.RequestTimeout.String()
	metadata["idle_timeout"] = effective.IdleTimeout.String()
	metadata["overall_timeout"] = effective.OverallTimeout.String()
	metadata["max_response_bytes"] = effective.MaxResponseBytes
	metadata["max_retained_bytes_per_query"] = effective.MaxRetainedBytesPerQuery
	metadata["max_total_retained_bytes"] = effective.MaxTotalRetainedBytes
	metadata["max_queries"] = effective.MaxQueries
	metadata["max_series_per_query"] = effective.MaxSeriesPerQuery
	metadata["max_samples_per_series"] = effective.MaxSamplesPerSeries
	metadata["max_namespaces"] = prometheus.MaximumNamespaces
	metadata["step_seconds"] = int64(effective.Step / time.Second)
	metadata["max_window"] = effective.MaxWindow.String()
	metadata["collection_status"] = stableCoverageState(coverage.State).String()
	metadata["retained_records"] = max(coverage.RecordCount, 0)
	metadata["retained_bytes"] = max(coverage.RetainedBytes, 0)
	metadata["truncated"] = coverage.Truncated
	if reason := stablePrometheusMetadataReason(coverage); reason != "" {
		metadata["reason"] = reason
	}
	if report == nil {
		return metadata
	}

	if report.CatalogVersion == prometheus.CatalogVersion {
		metadata["catalog_version"] = report.CatalogVersion
	}
	if requestedStart := prometheusReportTime(report.RequestedStart); requestedStart != nil {
		metadata["requested_start"] = requestedStart.Format(time.RFC3339Nano)
	}
	if requestedEnd := prometheusReportTime(report.RequestedEnd); requestedEnd != nil {
		metadata["requested_end"] = requestedEnd.Format(time.RFC3339Nano)
	}
	if actualStart := prometheusReportTime(report.ActualStart); actualStart != nil {
		metadata["actual_start"] = actualStart.Format(time.RFC3339Nano)
	}
	if actualEnd := prometheusReportTime(report.ActualEnd); actualEnd != nil {
		metadata["actual_end"] = actualEnd.Format(time.RFC3339Nano)
	}
	switch report.State {
	case prometheus.ReportComplete, prometheus.ReportPartial, prometheus.ReportFailed:
		metadata["report_state"] = string(report.State)
	}
	metadata["queries_total"] = len(report.Coverage)
	queryCounters := prometheusQueryCounters(report)
	for key, value := range queryCounters {
		metadata[key] = value
	}
	return metadata
}

// BuildSummary returns the human-readable support bundle summary.
func BuildSummary(
	generatedAt time.Time,
	status string,
	report kubernetes.Report,
	customerContext map[string]string,
	probeEnabled bool,
	connectivity *zitadel.Report,
	probeFailure string,
	prometheusSummaries ...PrometheusSummary,
) string {
	var summary strings.Builder
	fmt.Fprintln(&summary, "# Qodo support bundle summary")
	fmt.Fprintf(&summary, "\n- Captured: %s\n", generatedAt.Format(time.RFC3339Nano))
	fmt.Fprintf(&summary, "- Collection status: %s\n", status)
	if value := summaryValue(customerContext["activity"]); value != "" {
		fmt.Fprintf(&summary, "- Customer activity: %s\n", value)
	}
	if value := summaryValue(customerContext["problem"]); value != "" {
		fmt.Fprintf(&summary, "- Reported problem: %s\n", value)
	}
	fmt.Fprintln(&summary, "\n## Kubernetes")
	fmt.Fprintf(
		&summary,
		"\n- Scope: %d/%d namespaces, %d pods, %d containers (%d init, %d ephemeral)\n",
		len(report.Namespaces),
		report.NamespacesRequested,
		report.Pods,
		report.Containers,
		report.InitContainers,
		report.EphemeralContainers,
	)
	fmt.Fprintf(&summary, "- Container restarts: %d\n", report.ContainerRestarts)
	fmt.Fprintf(&summary, "- OOMKills: %d\n", report.OOMKills)
	fmt.Fprintf(
		&summary,
		"- Metadata bytes: %d/%d\n",
		report.MetadataBytes,
		report.MetadataLimitBytes,
	)
	fmt.Fprintf(
		&summary,
		"- Truncated metadata files: %d\n",
		report.TruncatedMetadataFiles,
	)
	fmt.Fprintf(
		&summary,
		"- Namespaces skipped by metadata limit: %d\n",
		report.MetadataNamespacesSkipped,
	)
	fmt.Fprintf(&summary, "- Log files: %d\n", report.LogFiles)
	fmt.Fprintf(&summary, "- Truncated log files: %d\n", report.TruncatedLogFiles)
	fmt.Fprintf(&summary, "- Collection issues: %d\n", len(report.Issues))
	if probeEnabled {
		fmt.Fprintln(&summary, "\n## Platform to Zitadel")
		switch {
		case probeFailure != "":
			fmt.Fprintf(&summary, "\n- Probe collection: unavailable (%s)\n", probeFailure)
		case connectivity != nil:
			fmt.Fprintln(&summary, "\n- Probe collection: complete")
			for _, check := range connectivity.Checks {
				fmt.Fprintf(&summary, "- %s: %s", check.Name, check.Status)
				if check.Reason != "" {
					fmt.Fprintf(&summary, " (%s)", check.Reason)
				}
				fmt.Fprintln(&summary)
			}
			fmt.Fprintln(&summary, "- Login and token issuance were not tested.")
		}
	}
	if len(prometheusSummaries) > 0 && prometheusSummaries[0].Requested {
		prometheusSummary := prometheusSummaries[0]
		fmt.Fprintln(&summary, "\n## Prometheus")
		fmt.Fprintf(
			&summary,
			"\n- Collection: %s",
			stableCoverageState(prometheusSummary.Coverage.State),
		)
		if reason := stablePrometheusMetadataReason(prometheusSummary.Coverage); reason != "" {
			fmt.Fprintf(&summary, " (%s)", reason)
		}
		fmt.Fprintln(&summary)
		if prometheusSummary.Report != nil {
			fmt.Fprintf(
				&summary,
				"- Catalog: %s; retained series: %d; retained bytes: %d; truncated: %t\n",
				prometheus.CatalogVersion,
				max(prometheusSummary.Report.RetainedRecords, 0),
				max(prometheusSummary.Report.RetainedBytes, 0),
				prometheusSummary.Report.Truncated,
			)
		}
	}
	fmt.Fprintln(&summary, "\nReview every file before sharing.")
	return summary.String()
}

// MarshalIssues encodes sanitized collection issues as JSON Lines.
func MarshalIssues(issues []kubernetes.Issue) ([]byte, error) {
	if len(issues) == 0 {
		return nil, nil
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, issue := range issues {
		if err := encoder.Encode(issue); err != nil {
			return nil, fmt.Errorf("encode collection issue: %w", err)
		}
	}
	return output.Bytes(), nil
}

// MarshalWorkloadReport encodes the redacted coverage and retention ledger
// needed to interpret normalized workload artifacts.
func MarshalWorkloadReport(
	report workload.Report,
	redactor *redact.Redactor,
) ([]byte, error) {
	sanitized := report
	sanitized.Namespaces = redactStrings(report.Namespaces, redactor)
	sanitized.Coverage = append([]workload.Coverage(nil), report.Coverage...)
	for index := range sanitized.Coverage {
		coverage := &sanitized.Coverage[index]
		coverage.Namespace = redactor.Text(coverage.Namespace)
		coverage.Diagnostic = strings.Join(
			strings.Fields(redactor.Text(coverage.Diagnostic)),
			" ",
		)
	}
	data, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode workload coverage report: %w", err)
	}
	return append(data, '\n'), nil
}

func summaryValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func redactStrings(values []string, redactor *redact.Redactor) []string {
	redacted := make([]string, 0, len(values))
	for _, value := range values {
		redacted = append(redacted, redactor.Text(value))
	}
	return redacted
}

func completeCoverageMap(input map[Source]Coverage) map[Source]Coverage {
	result := InitializeCoverage(nil)
	for _, source := range SupportedSources() {
		if coverage, exists := input[source]; exists {
			result[source] = coverage
		}
	}
	return result
}

func addMetadataTime(metadata map[string]any, key string, value time.Time) {
	if !value.IsZero() {
		metadata[key] = value.UTC().Format(time.RFC3339Nano)
	}
}

func stablePrometheusMetadataReason(coverage Coverage) string {
	switch coverage.Reason {
	case reasonCollectionError,
		reasonPrometheusInvalidReport,
		reasonPrometheusUnavailable,
		reasonPrometheusCoverageIncomplete:
		return coverage.Reason
	default:
		return stablePrometheusReason(coverage.Reason)
	}
}

func stableCoverageState(state CoverageState) CoverageState {
	if state.Valid() {
		return state
	}
	return CoverageUnavailable
}

func sanitizeMetadataStrings(values []string, redactor *redact.Redactor) []string {
	sanitized := make([]string, 0, len(values))
	for _, value := range values {
		sanitized = append(sanitized, summaryValue(redactor.Text(value)))
	}
	return sanitized
}

func prometheusQueryCounters(report *prometheus.Report) map[string]int {
	counters := map[string]int{
		"queries_collected": 0,
		"queries_no_data":   0,
		"queries_partial":   0,
		"queries_failed":    0,
		"queries_skipped":   0,
	}
	for _, query := range report.Coverage {
		switch query.State {
		case prometheus.CoverageCollected:
			counters["queries_collected"]++
		case prometheus.CoverageNoData:
			counters["queries_no_data"]++
		case prometheus.CoveragePartial:
			counters["queries_partial"]++
		case prometheus.CoverageFailed:
			counters["queries_failed"]++
		case prometheus.CoverageSkipped:
			counters["queries_skipped"]++
		}
	}
	return counters
}
