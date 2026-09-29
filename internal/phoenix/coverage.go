package phoenix

import (
	"fmt"
	"time"
)

// ValidateCompleteCoverage fails closed unless collection completed without
// truncation. A valid no-data response is complete coverage.
func ValidateCompleteCoverage(report Report) error {
	if report.ContractVersion != ContractVersion {
		return fmt.Errorf("%w: contract version mismatch", ErrCoverageInvalid)
	}
	if report.Mode != "window" && report.Mode != "trace_id" {
		return fmt.Errorf("%w: invalid collection mode", ErrCoverageInvalid)
	}
	if report.State != ReportComplete || report.Coverage.Truncated {
		return fmt.Errorf("%w: report is not complete", ErrCoverageInvalid)
	}
	if report.Coverage.State != CoverageCollected &&
		report.Coverage.State != CoverageNoData {
		return fmt.Errorf("%w: coverage is incomplete", ErrCoverageInvalid)
	}
	if report.Reason != "" ||
		report.Diagnostic != "" ||
		report.Coverage.Reason != "" ||
		report.Coverage.Diagnostic != "" {
		return fmt.Errorf("%w: complete report has failure metadata", ErrCoverageInvalid)
	}
	start, startErr := time.Parse(time.RFC3339Nano, report.RequestedStart)
	end, endErr := time.Parse(time.RFC3339Nano, report.RequestedEnd)
	actualStart, actualStartErr := time.Parse(time.RFC3339Nano, report.ActualStart)
	actualEnd, actualEndErr := time.Parse(time.RFC3339Nano, report.ActualEnd)
	if startErr != nil || endErr != nil || !start.Before(end) ||
		end.Sub(start) > MaximumWindow ||
		actualStartErr != nil || actualEndErr != nil ||
		!actualStart.Before(actualEnd) {
		return fmt.Errorf("%w: invalid collection bounds", ErrCoverageInvalid)
	}
	if report.Mode == "trace_id" {
		if report.TraceID == "" ||
			report.TraceID != normalizeTraceID(report.TraceID) ||
			!validTraceID(report.TraceID) {
			return fmt.Errorf("%w: invalid exact trace id", ErrCoverageInvalid)
		}
	} else if report.TraceID != "" {
		return fmt.Errorf("%w: window report contains a trace id", ErrCoverageInvalid)
	}
	coverage := report.Coverage
	if coverage.ProjectsFound < 0 ||
		coverage.ProjectsRead < 0 ||
		coverage.TracesFound < 0 ||
		coverage.TracesRetained < 0 ||
		coverage.SpansFound < 0 ||
		coverage.SpansRetained < 0 ||
		coverage.PagesRead < 0 ||
		coverage.RetainedBytes < 0 ||
		coverage.ProjectsRead > coverage.ProjectsFound ||
		coverage.TracesRetained > coverage.TracesFound ||
		coverage.SpansRetained > coverage.SpansFound {
		return fmt.Errorf("%w: invalid coverage counters", ErrCoverageInvalid)
	}
	if coverage.State == CoverageNoData &&
		(coverage.TracesRetained != 0 ||
			coverage.SpansRetained != 0 ||
			coverage.RetainedBytes != 0) {
		return fmt.Errorf("%w: no-data coverage retained data", ErrCoverageInvalid)
	}
	coverageArtifact, coverageCount := findArtifact(report.Artifacts, CoverageArtifactPath)
	if coverageCount != 1 || coverageArtifact.Records != 1 || coverageArtifact.Bytes <= 0 {
		return fmt.Errorf("%w: coverage artifact is absent", ErrCoverageInvalid)
	}
	tracesArtifact, tracesCount := findArtifact(report.Artifacts, TracesArtifactPath)
	if coverage.TracesRetained > 0 {
		if tracesCount != 1 ||
			tracesArtifact.Records != coverage.TracesRetained ||
			tracesArtifact.Bytes != coverage.RetainedBytes {
			return fmt.Errorf("%w: traces artifact is invalid", ErrCoverageInvalid)
		}
	} else if tracesCount != 0 {
		return fmt.Errorf("%w: unexpected traces artifact", ErrCoverageInvalid)
	}
	if len(report.Artifacts) != coverageCount+tracesCount {
		return fmt.Errorf("%w: unknown artifact metadata", ErrCoverageInvalid)
	}
	return nil
}

func normalizeTraceID(value string) string {
	result := make([]byte, len(value))
	for index := range value {
		character := value[index]
		if character >= 'A' && character <= 'F' {
			character += 'a' - 'A'
		}
		result[index] = character
	}
	return string(result)
}

func findArtifact(artifacts []Artifact, path string) (Artifact, int) {
	var result Artifact
	count := 0
	for _, artifact := range artifacts {
		if artifact.Path == path {
			result = artifact
			count++
		}
	}
	return result, count
}
