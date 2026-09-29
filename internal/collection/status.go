package collection

import (
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	reasonCollectionError = "collection_error"
	reasonIssuesReported  = "issues_reported"
	reasonMissingReport   = "missing_report"
	reasonMissingArtifact = "missing_artifact"
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

// AggregateStatus returns the schema-3 manifest collection status. Coverage
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
