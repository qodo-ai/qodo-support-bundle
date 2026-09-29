package prometheus

import (
	"fmt"
	"time"
)

// ValidateCompleteCoverage fails closed unless every built-in query completed
// without truncation. A valid no-data response is complete coverage.
func ValidateCompleteCoverage(report Report) error {
	catalog := BuiltinCatalog()
	if report.CatalogVersion != catalog.Version {
		return fmt.Errorf("%w: catalog version mismatch", ErrCoverageInvalid)
	}
	if report.State != ReportComplete || report.Truncated {
		return fmt.Errorf("%w: report is not complete", ErrCoverageInvalid)
	}
	requestedStart, startErr := time.Parse(time.RFC3339Nano, report.RequestedStart)
	requestedEnd, endErr := time.Parse(time.RFC3339Nano, report.RequestedEnd)
	actualStart, actualStartErr := time.Parse(time.RFC3339Nano, report.ActualStart)
	actualEnd, actualEndErr := time.Parse(time.RFC3339Nano, report.ActualEnd)
	if startErr != nil ||
		endErr != nil ||
		actualStartErr != nil ||
		actualEndErr != nil ||
		!requestedStart.Before(requestedEnd) ||
		!requestedStart.Equal(actualStart) ||
		!requestedEnd.Equal(actualEnd) ||
		report.StepSeconds < int64(MinimumStep/time.Second) ||
		report.StepSeconds > int64(MaximumStep/time.Second) {
		return fmt.Errorf("%w: invalid collection bounds", ErrCoverageInvalid)
	}
	if len(report.Coverage) != len(catalog.Queries) {
		return fmt.Errorf("%w: coverage entry count mismatch", ErrCoverageInvalid)
	}
	expected := make(map[string]Query, len(catalog.Queries))
	for _, query := range catalog.Queries {
		expected[query.ID] = query
	}
	seen := make(map[string]struct{}, len(report.Coverage))
	retainedRecords := 0
	var retainedBytes int64
	for _, coverage := range report.Coverage {
		query, exists := expected[coverage.QueryID]
		if !exists {
			return fmt.Errorf("%w: unknown query id", ErrCoverageInvalid)
		}
		if _, duplicate := seen[coverage.QueryID]; duplicate {
			return fmt.Errorf("%w: duplicate query id", ErrCoverageInvalid)
		}
		seen[coverage.QueryID] = struct{}{}
		if coverage.Category != query.Category {
			return fmt.Errorf("%w: category mismatch", ErrCoverageInvalid)
		}
		if coverage.State != CoverageCollected && coverage.State != CoverageNoData {
			return fmt.Errorf("%w: query is incomplete", ErrCoverageInvalid)
		}
		if coverage.Reason != "" ||
			coverage.Diagnostic != "" ||
			coverage.Truncated ||
			coverage.SeriesFound < coverage.SeriesRetained ||
			coverage.SamplesFound < coverage.SamplesRetained ||
			coverage.RetainedBytes < 0 {
			return fmt.Errorf("%w: invalid query counters", ErrCoverageInvalid)
		}
		if coverage.State == CoverageNoData &&
			(coverage.SeriesRetained != 0 ||
				coverage.SamplesRetained != 0 ||
				coverage.RetainedBytes != 0) {
			return fmt.Errorf("%w: no-data query retained data", ErrCoverageInvalid)
		}
		retainedRecords += coverage.SeriesRetained
		retainedBytes += coverage.RetainedBytes
	}
	if retainedRecords != report.RetainedRecords ||
		retainedBytes != report.RetainedBytes {
		return fmt.Errorf("%w: report counters do not reconcile", ErrCoverageInvalid)
	}
	if report.Reason != "" || report.Diagnostic != "" {
		return fmt.Errorf("%w: complete report has failure metadata", ErrCoverageInvalid)
	}
	coverageArtifact, coverageArtifacts := findArtifacts(
		report.Artifacts,
		CoverageArtifactPath,
	)
	if coverageArtifacts != 1 ||
		coverageArtifact.Records != len(report.Coverage) ||
		coverageArtifact.Bytes <= 0 {
		return fmt.Errorf("%w: coverage artifact is absent", ErrCoverageInvalid)
	}
	metricsArtifact, metricsArtifacts := findArtifacts(
		report.Artifacts,
		MetricsArtifactPath,
	)
	if retainedRecords > 0 {
		if metricsArtifacts != 1 ||
			metricsArtifact.Records != retainedRecords ||
			metricsArtifact.Bytes != retainedBytes {
			return fmt.Errorf("%w: metrics artifact is invalid", ErrCoverageInvalid)
		}
	} else if metricsArtifacts != 0 {
		return fmt.Errorf("%w: unexpected metrics artifact", ErrCoverageInvalid)
	}
	if len(report.Artifacts) != coverageArtifacts+metricsArtifacts {
		return fmt.Errorf("%w: unknown artifact metadata", ErrCoverageInvalid)
	}
	return nil
}

func findArtifacts(artifacts []Artifact, path string) (Artifact, int) {
	var result Artifact
	count := 0
	for _, artifact := range artifacts {
		if artifact.Path != path {
			continue
		}
		result = artifact
		count++
	}
	return result, count
}
