package prometheus

import (
	"errors"
	"testing"
	"time"
)

func TestValidateCompleteCoverageRejectsNegativeCounters(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	catalog := BuiltinCatalog()
	coverage := make([]Coverage, len(catalog.Queries))
	for index, query := range catalog.Queries {
		coverage[index] = Coverage{
			QueryID:  query.ID,
			Category: query.Category,
			State:    CoverageNoData,
		}
	}
	report := Report{
		CatalogVersion: CatalogVersion,
		RequestedStart: start.Format(time.RFC3339Nano),
		RequestedEnd:   start.Add(time.Hour).Format(time.RFC3339Nano),
		ActualStart:    start.Format(time.RFC3339Nano),
		ActualEnd:      start.Add(time.Hour).Format(time.RFC3339Nano),
		StepSeconds:    int64(DefaultStep / time.Second),
		State:          ReportComplete,
		Coverage:       coverage,
		Artifacts: []Artifact{{
			Path:    CoverageArtifactPath,
			Records: len(coverage),
			Bytes:   1,
		}},
	}
	if err := ValidateCompleteCoverage(report); err != nil {
		t.Fatalf("valid baseline report rejected: %v", err)
	}

	report.Coverage[0].SeriesFound = -1
	report.Coverage[0].SeriesRetained = -1
	report.Coverage[0].SamplesFound = -1
	report.Coverage[0].SamplesRetained = -1
	report.RetainedRecords = -1
	if err := ValidateCompleteCoverage(report); !errors.Is(err, ErrCoverageInvalid) {
		t.Fatalf("negative counters error = %v", err)
	}
}
