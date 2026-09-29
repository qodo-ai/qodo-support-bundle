package collection

import (
	"errors"
	"reflect"
	"testing"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

func TestKubernetesCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report kubernetes.Report
		err    error
		want   Coverage
	}{
		{
			name: "clean collection is complete",
			want: Coverage{State: CoverageComplete},
		},
		{
			name: "reported issue is partial",
			report: kubernetes.Report{Issues: []kubernetes.Issue{{
				Operation: "list pods",
				Message:   "forbidden",
			}}},
			want: Coverage{State: CoveragePartial, Reason: "issues_reported"},
		},
		{
			name: "collection error is partial with stable reason",
			err:  errors.New("raw sensitive error details"),
			want: Coverage{State: CoveragePartial, Reason: "collection_error"},
		},
		{
			name: "collection error takes precedence over issues",
			report: kubernetes.Report{Issues: []kubernetes.Issue{{
				Operation: "list pods",
				Message:   "forbidden",
			}}},
			err:  errors.New("raw sensitive error details"),
			want: Coverage{State: CoveragePartial, Reason: "collection_error"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := KubernetesCoverage(test.report, test.err); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("KubernetesCoverage() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestWorkloadCoverage(t *testing.T) {
	t.Parallel()
	completeReport := completeWorkloadCoverageReport("qodo")
	completeReport.RetainedBytes = 42
	completeReport.RetainedRecords = 2
	completeReport.Coverage[0].RecordsFound = 2
	completeReport.Coverage[0].RecordsRetained = 2
	completeReport.Coverage[0].RetainedBytes = 42
	partialReport := completeWorkloadCoverageReport("qodo")
	partialReport.RetainedBytes = 20
	partialReport.RetainedRecords = 1
	partialReport.Truncated = true
	partialReport.Coverage[0].State = workload.CoveragePartial
	partialReport.Coverage[0].Truncated = true
	tests := []struct {
		name   string
		report workload.Report
		err    error
		want   Coverage
	}{
		{
			name:   "complete",
			report: completeReport,
			want: Coverage{
				State:         CoverageComplete,
				RetainedBytes: 42,
				RecordCount:   2,
			},
		},
		{
			name:   "partial source",
			report: partialReport,
			want: Coverage{
				State:         CoveragePartial,
				RetainedBytes: 20,
				RecordCount:   1,
				Truncated:     true,
				Reason:        reasonIssuesReported,
			},
		},
		{
			name: "failed before artifacts",
			err:  errors.New("failed"),
			want: Coverage{
				State:  CoverageUnavailable,
				Reason: reasonCollectionError,
			},
		},
		{
			name: "failed after retaining records",
			report: workload.Report{
				RetainedBytes:   20,
				RetainedRecords: 1,
			},
			err: errors.New("failed"),
			want: Coverage{
				State:         CoveragePartial,
				RetainedBytes: 20,
				RecordCount:   1,
				Reason:        reasonCollectionError,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := WorkloadCoverage(test.report, test.err); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("WorkloadCoverage() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func completeWorkloadCoverageReport(namespace string) workload.Report {
	report := workload.Report{Namespaces: []string{namespace}}
	for _, source := range []struct {
		name string
		path string
	}{
		{"deployments", workload.WorkloadsArtifactPath},
		{"statefulsets", workload.WorkloadsArtifactPath},
		{"daemonsets", workload.WorkloadsArtifactPath},
		{"jobs", workload.WorkloadsArtifactPath},
		{"cronjobs", workload.WorkloadsArtifactPath},
		{"services", workload.ServicesArtifactPath},
		{"endpointslices", workload.ServicesArtifactPath},
		{"horizontalpodautoscalers", workload.AutoscalersArtifactPath},
		{"persistentvolumeclaims", workload.StorageArtifactPath},
	} {
		report.Coverage = append(report.Coverage, workload.Coverage{
			Namespace:    namespace,
			Source:       source.name,
			State:        workload.CoverageCollected,
			ArtifactPath: source.path,
		})
	}
	return report
}

func TestZitadelCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
		outcome zitadel.Outcome
		want    Coverage
	}{
		{
			name: "disabled is not requested",
			outcome: zitadel.Outcome{
				Reason: zitadel.ReasonTimeout,
			},
			want: Coverage{State: CoverageNotRequested},
		},
		{
			name:    "report with failed diagnostic check is complete",
			enabled: true,
			outcome: zitadel.Outcome{Report: &zitadel.Report{
				SchemaVersion: 1,
				Checks: []zitadel.Check{{
					Name:   "discovery",
					Status: zitadel.StatusFailed,
					Reason: zitadel.ReasonTimeout,
				}},
			}},
			want: Coverage{State: CoverageComplete},
		},
		{
			name:    "bounded collection reason is partial",
			enabled: true,
			outcome: zitadel.Outcome{
				Reason: zitadel.ReasonExecTimeout,
			},
			want: Coverage{State: CoveragePartial, Reason: zitadel.ReasonExecTimeout},
		},
		{
			name:    "missing report is unavailable",
			enabled: true,
			want:    Coverage{State: CoverageUnavailable, Reason: "missing_report"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ZitadelCoverage(test.enabled, test.outcome); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ZitadelCoverage() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDerivedCoverageLeavesReservedSourcesNotRequested(t *testing.T) {
	t.Parallel()

	coverage := InitializeCoverage([]Source{SourceKubernetes, SourceZitadel})
	coverage[SourceKubernetes] = KubernetesCoverage(kubernetes.Report{}, nil)
	coverage[SourceZitadel] = ZitadelCoverage(true, zitadel.Outcome{
		Report: &zitadel.Report{SchemaVersion: 1},
	})

	for _, source := range []Source{SourceWorkload, SourcePrometheus, SourcePhoenix} {
		if got := coverage[source].State; got != CoverageNotRequested {
			t.Errorf("%s state = %q, want %q", source, got, CoverageNotRequested)
		}
	}
}

func TestAggregateStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		coverage map[Source]Coverage
		want     string
	}{
		{
			name: "all supported complete or not requested aggregate complete",
			coverage: map[Source]Coverage{
				SourceKubernetes: {State: CoverageComplete},
				SourceZitadel:    {State: CoverageNotRequested},
				SourceWorkload:   {State: CoverageNotRequested},
				SourcePrometheus: {State: CoverageComplete},
				SourcePhoenix:    {State: CoverageNotRequested},
			},
			want: "complete",
		},
		{
			name: "one complete source is missing evidence",
			coverage: map[Source]Coverage{
				SourceKubernetes: {State: CoverageComplete},
			},
			want: "partial",
		},
		{
			name: "unsupported complete source fails closed",
			coverage: map[Source]Coverage{
				SourceKubernetes:      {State: CoverageComplete},
				SourceZitadel:         {State: CoverageNotRequested},
				SourceWorkload:        {State: CoverageNotRequested},
				SourcePrometheus:      {State: CoverageNotRequested},
				SourcePhoenix:         {State: CoverageNotRequested},
				Source("unsupported"): {State: CoverageComplete},
			},
			want: "partial",
		},
		{
			name: "partial aggregates partial",
			coverage: map[Source]Coverage{
				SourceKubernetes: {State: CoveragePartial},
			},
			want: "partial",
		},
		{
			name: "unavailable aggregates partial",
			coverage: map[Source]Coverage{
				SourceKubernetes: {State: CoverageUnavailable},
			},
			want: "partial",
		},
		{
			name: "invalid state aggregates partial",
			coverage: map[Source]Coverage{
				SourceKubernetes: {State: CoverageState("invalid")},
			},
			want: "partial",
		},
		{
			name:     "nil coverage fails closed",
			coverage: nil,
			want:     "partial",
		},
		{
			name:     "empty coverage fails closed",
			coverage: map[Source]Coverage{},
			want:     "partial",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := AggregateStatus(test.coverage); got != test.want {
				t.Fatalf("AggregateStatus() = %q, want %q", got, test.want)
			}
		})
	}
}
