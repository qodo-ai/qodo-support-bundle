package collection

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/phoenix"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

func TestPhoenixCoverageMapsCompletePartialAndStableFailures(t *testing.T) {
	t.Parallel()
	config := phoenixConfig()
	complete := completeNoDataPhoenixReport(config.Start, config.End)
	got := PhoenixCoverage(complete, nil)
	if got.State != CoverageComplete ||
		got.RequestedStart == nil ||
		got.RequestedEnd == nil ||
		got.ActualStart == nil ||
		got.ActualEnd == nil ||
		!got.RequestedStart.Equal(config.Start) ||
		!got.ActualEnd.Equal(config.End) ||
		got.Reason != "" {
		t.Fatalf("unexpected complete Phoenix coverage: %+v", got)
	}

	partial := complete
	partial.State = phoenix.ReportPartial
	partial.Reason = "span_limit_exceeded"
	partial.Coverage = phoenix.Coverage{
		State:          phoenix.CoveragePartial,
		Reason:         "span_limit_exceeded",
		TracesFound:    2,
		TracesRetained: 1,
		SpansFound:     5,
		SpansRetained:  3,
		RetainedBytes:  42,
		Truncated:      true,
	}
	got = PhoenixCoverage(partial, nil)
	if got.State != CoveragePartial ||
		got.Reason != "span_limit_exceeded" ||
		got.RecordCount != 1 ||
		got.RetainedBytes != 42 ||
		!got.Truncated {
		t.Fatalf("unexpected partial Phoenix coverage: %+v", got)
	}

	failed := complete
	failed.State = phoenix.ReportFailed
	failed.Reason = "password=raw-secret"
	failed.Diagnostic = "raw stderr"
	failed.Coverage = phoenix.Coverage{State: phoenix.CoverageFailed}
	got = PhoenixCoverage(failed, errors.New("raw collector secret"))
	if got.State != CoverageUnavailable ||
		got.Reason != reasonCollectionError ||
		strings.Contains(got.Reason, "secret") {
		t.Fatalf("collector details leaked into Phoenix coverage: %+v", got)
	}
}

func TestDefaultCollectorsWirePhoenixCollector(t *testing.T) {
	t.Parallel()
	if DefaultCollectors().Phoenix == nil {
		t.Fatal("production Phoenix collector is not wired")
	}
}

func TestBuildPhoenixMetadataMarksExactModeWithNormalizedTraceID(t *testing.T) {
	t.Parallel()
	config := phoenix.DefaultConfig()
	config.Namespace = "phoenix"
	config.TraceID = "ABCDEF0123456789ABCDEF0123456789"
	config.Start = time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	config.End = config.Start.Add(time.Hour)
	metadata := BuildPhoenixMetadata(
		&config,
		nil,
		Coverage{State: CoverageComplete},
		redact.New(),
	)
	if metadata["enabled"] != true ||
		metadata["mode"] != "trace_id" ||
		metadata["trace_id"] != "abcdef0123456789abcdef0123456789" ||
		metadata["configured_start"] != config.Start.Format(time.RFC3339Nano) ||
		metadata["contract_version"] != phoenix.ContractVersion {
		t.Fatalf("unexpected exact-mode metadata: %#v", metadata)
	}
}

func TestExecuteCollectsPhoenixAfterPrometheusBeforeZitadel(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	forwarder := &unusedForwarder{}
	redactor := redact.New()
	config := phoenixConfig()
	promConfig := prometheusConfig()
	var order []string
	var events []Event

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  promConfig,
			Phoenix:     config,
			Zitadel: &zitadel.Config{
				Namespace: "qodo",
				Pod:       "platform-0",
				Container: "platform",
			},
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		archive,
		redactor,
		Collectors{
			Kubernetes: func(
				context.Context,
				kubernetes.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (kubernetes.Report, error) {
				order = append(order, "kubernetes")
				return successfulKubernetesCollector(
					context.Background(),
					kubernetes.Config{},
					unusedRunner{},
					archive,
					redactor,
				)
			},
			Workload: func(
				ctx context.Context,
				config workload.Config,
				runner kubernetes.Runner,
				sink kubernetes.Sink,
				redactor *redact.Redactor,
			) (workload.Report, error) {
				order = append(order, "workload")
				return successfulWorkloadCollector(ctx, config, runner, sink, redactor)
			},
			Prometheus: func(
				_ context.Context,
				gotConfig prometheus.Config,
				_ kubernetes.Runner,
				gotForwarder telemetry.Forwarder,
				_ kubernetes.Sink,
				_ *redact.Redactor,
			) (prometheus.Report, error) {
				order = append(order, "prometheus")
				if !reflect.DeepEqual(gotConfig, *promConfig) ||
					gotForwarder != forwarder {
					t.Fatal("Prometheus dependencies were not preserved")
				}
				return completeNoDataPrometheusReport(
					promConfig.Start,
					promConfig.End,
				), nil
			},
			Phoenix: func(
				_ context.Context,
				gotConfig phoenix.Config,
				_ kubernetes.Runner,
				gotForwarder telemetry.Forwarder,
				sink kubernetes.Sink,
				gotRedactor *redact.Redactor,
			) (phoenix.Report, error) {
				order = append(order, "phoenix")
				if !reflect.DeepEqual(gotConfig, *config) ||
					gotForwarder != forwarder ||
					sink != archive ||
					gotRedactor != redactor {
					t.Fatal("Phoenix dependencies were not preserved")
				}
				report := completeNoDataPhoenixReport(config.Start, config.End)
				if err := sink.Add(phoenix.CoverageArtifactPath, []byte("{}\n")); err != nil {
					return report, errors.Join(phoenix.ErrArtifactStaging, err)
				}
				return report, nil
			},
			Forwarder: forwarder,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				order = append(order, "zitadel")
				return zitadel.Outcome{
					Report: &zitadel.Report{SchemaVersion: 1},
					Data:   []byte(`{"schema_version":1}`),
				}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "kubernetes,workload,prometheus,phoenix,zitadel" {
		t.Fatalf("unexpected collector order: %v", order)
	}
	if result.PhoenixReport == nil ||
		result.Coverage[SourcePhoenix].State != CoverageComplete ||
		result.Status != CoverageComplete.String() {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(events) != 6 ||
		events[0].Kind != EventPrometheusStarted ||
		events[1].Kind != EventPrometheusComplete ||
		events[2].Kind != EventPhoenixStarted ||
		events[3].Kind != EventPhoenixComplete ||
		events[4].Kind != EventZitadelStarted ||
		events[5].Kind != EventZitadelPassed {
		t.Fatalf("unexpected events: %+v", events)
	}
	metadata, ok := archive.manifest.Collection["phoenix"].(map[string]any)
	if !ok ||
		metadata["enabled"] != true ||
		metadata["namespace"] != "phoenix" ||
		metadata["mode"] != "window" ||
		metadata["contract_version"] != phoenix.ContractVersion ||
		metadata["collection_status"] != CoverageComplete.String() {
		t.Fatalf("unexpected Phoenix metadata: %#v", metadata)
	}
	summary := string(archive.files[summaryArtifactPath])
	if !strings.Contains(summary, "## Phoenix") ||
		!strings.Contains(summary, "- Collection: complete") ||
		!strings.Contains(summary, "Mode: window") {
		t.Fatalf("Phoenix summary missing: %s", summary)
	}
}

func TestExecuteRecordsPhoenixPartialAndTreatsStagingAsFatal(t *testing.T) {
	t.Parallel()
	config := phoenixConfig()
	partial := completeNoDataPhoenixReport(config.Start, config.End)
	partial.State = phoenix.ReportPartial
	partial.Reason = "span_limit_exceeded"
	partial.Coverage = phoenix.Coverage{
		State:          phoenix.CoveragePartial,
		Reason:         "span_limit_exceeded",
		TracesFound:    2,
		TracesRetained: 1,
		SpansFound:     3,
		SpansRetained:  2,
		RetainedBytes:  20,
		Truncated:      true,
	}
	archive := &recordingArchive{}
	var events []Event
	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Phoenix:     config,
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		phoenixCollectors(func(
			context.Context,
			phoenix.Config,
			kubernetes.Runner,
			telemetry.Forwarder,
			kubernetes.Sink,
			*redact.Redactor,
		) (phoenix.Report, error) {
			return partial, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoveragePartial.String() ||
		result.Coverage[SourcePhoenix].Reason != "span_limit_exceeded" ||
		len(events) != 2 ||
		events[1].Kind != EventPhoenixPartial ||
		!strings.Contains(string(archive.files[issuesArtifactPath]), "collect Phoenix telemetry") {
		t.Fatalf("partial Phoenix collection was not represented: result=%+v events=%+v", result, events)
	}

	fatalArchive := &recordingArchive{}
	fatalResult, fatalErr := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Phoenix:     config,
		},
		unusedRunner{},
		fatalArchive,
		redact.New(),
		phoenixCollectors(func(
			context.Context,
			phoenix.Config,
			kubernetes.Runner,
			telemetry.Forwarder,
			kubernetes.Sink,
			*redact.Redactor,
		) (phoenix.Report, error) {
			return phoenix.Report{}, errors.Join(
				phoenix.ErrArtifactStaging,
				errors.New("raw archive detail"),
			)
		}),
	)
	if !errors.Is(fatalErr, phoenix.ErrArtifactStaging) ||
		fatalResult.ArchivePath != "" ||
		fatalArchive.finalizeCalls != 0 {
		t.Fatalf("Phoenix staging failure was not fatal: result=%+v err=%v", fatalResult, fatalErr)
	}
}

func TestExecuteRequiresPhoenixDependenciesOnlyWhenRequested(t *testing.T) {
	t.Parallel()
	config := phoenixConfig()
	valid := phoenixCollectors(func(
		context.Context,
		phoenix.Config,
		kubernetes.Runner,
		telemetry.Forwarder,
		kubernetes.Sink,
		*redact.Redactor,
	) (phoenix.Report, error) {
		return completeNoDataPhoenixReport(config.Start, config.End), nil
	})
	for name, collectors := range map[string]Collectors{
		"collector": {
			Kubernetes: valid.Kubernetes,
			Workload:   valid.Workload,
			Forwarder:  valid.Forwarder,
		},
		"forwarder": {
			Kubernetes: valid.Kubernetes,
			Workload:   valid.Workload,
			Phoenix:    valid.Phoenix,
		},
	} {
		collectors := collectors
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Execute(
				context.Background(),
				Request{
					CurrentTime: time.Now,
					Phoenix:     config,
				},
				unusedRunner{},
				&recordingArchive{},
				redact.New(),
				collectors,
			); err == nil {
				t.Fatal("expected Phoenix dependency validation error")
			}
		})
	}
}

func phoenixConfig() *phoenix.Config {
	start := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	config := phoenix.DefaultConfig()
	config.Namespace = "phoenix"
	config.Start = start
	config.End = start.Add(time.Hour)
	return &config
}

func phoenixCollectors(collector PhoenixCollector) Collectors {
	return Collectors{
		Kubernetes: successfulKubernetesCollector,
		Workload:   successfulWorkloadCollector,
		Phoenix:    collector,
		Forwarder:  &unusedForwarder{},
	}
}

func completeNoDataPhoenixReport(start, end time.Time) phoenix.Report {
	return phoenix.Report{
		ContractVersion: phoenix.ContractVersion,
		Mode:            "window",
		RequestedStart:  start.Format(time.RFC3339Nano),
		RequestedEnd:    end.Format(time.RFC3339Nano),
		ActualStart:     start.Format(time.RFC3339Nano),
		ActualEnd:       end.Format(time.RFC3339Nano),
		State:           phoenix.ReportComplete,
		Coverage:        phoenix.Coverage{State: phoenix.CoverageNoData},
		Artifacts: []phoenix.Artifact{{
			Path:    phoenix.CoverageArtifactPath,
			Records: 1,
			Bytes:   1,
		}},
	}
}
