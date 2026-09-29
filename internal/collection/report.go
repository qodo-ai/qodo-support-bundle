package collection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

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

// BuildConnectivityMetadata returns the schema-3 connectivity metadata.
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

// BuildCollectionManifest returns the collection section of a schema-3 manifest.
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
) map[string]any {
	manifestNamespaces := selectedNamespaces
	namespaceValue := strings.Join(selectedNamespaces, ",")
	if allNamespaces {
		manifestNamespaces = report.Namespaces
		namespaceValue = "*"
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
	}
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
