package collection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

type unusedForwarder struct{}

func (*unusedForwarder) Forward(
	context.Context,
	telemetry.Target,
) (*telemetry.Tunnel, error) {
	return nil, errors.New("unexpected forwarder call")
}

func TestPrometheusCoverageCompleteIncludesUTCBoundsAndAllowsNoData(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	report := completeNoDataPrometheusReport(start, end)

	got := PrometheusCoverage(report, nil)
	if got.State != CoverageComplete ||
		got.Reason != "" ||
		got.RecordCount != 0 ||
		got.RetainedBytes != 0 ||
		got.Truncated ||
		got.RequestedStart == nil ||
		got.RequestedEnd == nil ||
		got.ActualStart == nil ||
		got.ActualEnd == nil ||
		!got.RequestedStart.Equal(start) ||
		!got.RequestedEnd.Equal(end) ||
		got.RequestedStart.Location() != time.UTC ||
		got.ActualEnd.Location() != time.UTC {
		t.Fatalf("unexpected complete no-data coverage: %+v", got)
	}
}

func TestPrometheusCoveragePartialAndUnavailableUseStableReasons(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	partial := partialPrometheusReport(start, end)
	partial.Coverage[0].Diagnostic = "https://127.0.0.1:1234?q=secret"
	gotPartial := PrometheusCoverage(partial, nil)
	if gotPartial.State != CoveragePartial ||
		gotPartial.Reason != reasonPrometheusCoverageIncomplete {
		t.Fatalf("unexpected partial coverage: %+v", gotPartial)
	}

	unavailable := failedPrometheusReport(start, end, "discovery_failed")
	unavailable.Diagnostic = "stderr password=secret"
	gotUnavailable := PrometheusCoverage(unavailable, nil)
	if gotUnavailable.State != CoverageUnavailable ||
		gotUnavailable.Reason != "discovery_failed" {
		t.Fatalf("unexpected unavailable coverage: %+v", gotUnavailable)
	}

	unavailable.Reason = "password=raw-secret"
	gotError := PrometheusCoverage(unavailable, errors.New("raw HTTP error secret"))
	if gotError.State != CoverageUnavailable ||
		gotError.Reason != reasonCollectionError ||
		strings.Contains(gotError.Reason, "secret") {
		t.Fatalf("collector error leaked into coverage: %+v", gotError)
	}
}

func TestDefaultCollectorsWireInjectablePrometheusCollector(t *testing.T) {
	t.Parallel()
	collectors := DefaultCollectors()
	if collectors.Prometheus == nil {
		t.Fatal("production Prometheus collector is not wired")
	}
	injected := false
	collectors.Prometheus = func(
		context.Context,
		prometheus.Config,
		kubernetes.Runner,
		telemetry.Forwarder,
		kubernetes.Sink,
		*redact.Redactor,
	) (prometheus.Report, error) {
		injected = true
		return failedPrometheusReport(time.Now().UTC(), time.Now().UTC().Add(time.Hour), "discovery_failed"), nil
	}
	collectors.Forwarder = &unusedForwarder{}
	collectors.Kubernetes = successfulKubernetesCollector
	collectors.Workload = successfulWorkloadCollector

	_, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  prometheusConfig(),
		},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		collectors,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !injected {
		t.Fatal("injected Prometheus collector was not called")
	}
}

func TestExecuteExcludesSystemNamespacesWithoutExpandingLargeScope(t *testing.T) {
	t.Parallel()
	config := prometheusConfig()
	config.Namespaces = nil
	config.AllNamespaces = true
	var captured prometheus.Config
	applicationNamespaces := make([]string, prometheus.MaximumNamespaces+1)
	for index := range applicationNamespaces {
		applicationNamespaces[index] = fmt.Sprintf("team-%03d", index)
	}

	collectors := Collectors{
		Kubernetes: func(
			context.Context,
			kubernetes.Config,
			kubernetes.Runner,
			kubernetes.Sink,
			*redact.Redactor,
		) (kubernetes.Report, error) {
			return kubernetes.Report{
				Namespaces:           applicationNamespaces,
				CollectionNamespaces: applicationNamespaces,
				ExcludedNamespaces:   []string{"kube-system"},
				NamespacesRequested:  len(applicationNamespaces),
			}, nil
		},
		Workload: successfulWorkloadCollector,
		Prometheus: func(
			_ context.Context,
			got prometheus.Config,
			_ kubernetes.Runner,
			_ telemetry.Forwarder,
			_ kubernetes.Sink,
			_ *redact.Redactor,
		) (prometheus.Report, error) {
			captured = got
			return failedPrometheusReport(
				config.Start,
				config.End,
				"discovery_failed",
			), nil
		},
		Forwarder: &unusedForwarder{},
	}

	_, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				AllNamespaces:           true,
				ExcludeSystemNamespaces: true,
			},
			Prometheus: config,
		},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		collectors,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !captured.AllNamespaces ||
		!captured.ExcludeSystemNamespaces ||
		len(captured.Namespaces) != 0 {
		t.Fatalf("Prometheus scope expanded discovered namespaces: %+v", captured)
	}
}

func TestExecuteCollectsPrometheusBetweenWorkloadAndZitadel(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	forwarder := &unusedForwarder{}
	redactor := redact.New()
	config := prometheusConfig()
	var order []string
	var events []Event

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  config,
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
				sink kubernetes.Sink,
				gotRedactor *redact.Redactor,
			) (prometheus.Report, error) {
				order = append(order, "prometheus")
				if !reflect.DeepEqual(gotConfig, *config) ||
					gotForwarder != forwarder ||
					sink != archive ||
					gotRedactor != redactor {
					t.Fatalf("Prometheus dependencies were not preserved")
				}
				report := completeNoDataPrometheusReport(config.Start, config.End)
				if err := sink.Add(prometheus.CoverageArtifactPath, []byte("{}\n")); err != nil {
					return report, errors.Join(prometheus.ErrArtifactStaging, err)
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
	if strings.Join(order, ",") != "kubernetes,workload,prometheus,zitadel" {
		t.Fatalf("unexpected collector order: %v", order)
	}
	if result.PrometheusReport == nil ||
		result.Coverage[SourcePrometheus].State != CoverageComplete ||
		result.Status != CoverageComplete.String() {
		t.Fatalf("unexpected result: %+v", result)
	}
	if archive.addCalls[prometheus.CoverageArtifactPath] != 1 ||
		archive.addCalls[prometheus.MetricsArtifactPath] != 0 {
		t.Fatalf("Prometheus artifacts were duplicated: %+v", archive.addCalls)
	}
	if len(events) != 4 ||
		events[0].Kind != EventPrometheusStarted ||
		events[1].Kind != EventPrometheusComplete ||
		events[2].Kind != EventZitadelStarted ||
		events[3].Kind != EventZitadelPassed {
		t.Fatalf("unexpected events: %+v", events)
	}
	assertPrometheusManifestAndSummary(t, archive, *config, result.Coverage)
}

func TestExecuteRepresentsPrometheusPartialAndUnavailableAsUsableBundles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		report     prometheus.Report
		wantState  CoverageState
		wantEvent  EventKind
		wantReason string
	}{
		{
			name:       "partial query coverage",
			report:     partialPrometheusReport(prometheusConfig().Start, prometheusConfig().End),
			wantState:  CoveragePartial,
			wantEvent:  EventPrometheusPartial,
			wantReason: reasonPrometheusCoverageIncomplete,
		},
		{
			name:       "discovery unavailable",
			report:     failedPrometheusReport(prometheusConfig().Start, prometheusConfig().End, "discovery_failed"),
			wantState:  CoverageUnavailable,
			wantEvent:  EventPrometheusUnavailable,
			wantReason: "discovery_failed",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			archive := &recordingArchive{}
			var events []Event
			result, err := Execute(
				context.Background(),
				Request{
					CurrentTime: time.Now,
					Kubernetes:  kubernetes.Config{Namespace: "qodo"},
					Prometheus:  prometheusConfig(),
					Progress: func(event Event) {
						events = append(events, event)
					},
				},
				unusedRunner{},
				archive,
				redact.New(),
				prometheusCollectors(func(
					_ context.Context,
					_ prometheus.Config,
					_ kubernetes.Runner,
					_ telemetry.Forwarder,
					sink kubernetes.Sink,
					_ *redact.Redactor,
				) (prometheus.Report, error) {
					if err := sink.Add(prometheus.CoverageArtifactPath, []byte("{}\n")); err != nil {
						return test.report, errors.Join(prometheus.ErrArtifactStaging, err)
					}
					return test.report, nil
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			got := result.Coverage[SourcePrometheus]
			if got.State != test.wantState ||
				got.Reason != test.wantReason ||
				result.Status != CoveragePartial.String() ||
				result.ArchivePath == "" ||
				archive.finalizeCalls != 1 {
				t.Fatalf("unexpected source gap result: %+v", result)
			}
			if len(events) != 2 ||
				events[0].Kind != EventPrometheusStarted ||
				events[1].Kind != test.wantEvent ||
				events[1].Reason != test.wantReason {
				t.Fatalf("unexpected events: %+v", events)
			}
			issues := string(archive.files[issuesArtifactPath])
			if !strings.Contains(issues, test.wantReason) ||
				!strings.Contains(issues, "collect Prometheus telemetry") {
				t.Fatalf("Prometheus issue missing stable category: %s", issues)
			}
		})
	}
}

func TestExecuteTreatsPrometheusArtifactStagingFailureAsFatal(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  prometheusConfig(),
		},
		unusedRunner{},
		archive,
		redact.New(),
		prometheusCollectors(func(
			context.Context,
			prometheus.Config,
			kubernetes.Runner,
			telemetry.Forwarder,
			kubernetes.Sink,
			*redact.Redactor,
		) (prometheus.Report, error) {
			return prometheus.Report{}, errors.Join(
				prometheus.ErrArtifactStaging,
				errors.New("raw archive path and secret"),
			)
		}),
	)
	if !errors.Is(err, prometheus.ErrArtifactStaging) ||
		result.ArchivePath != "" ||
		archive.finalizeCalls != 0 {
		t.Fatalf("artifact staging failure was not fatal: result=%+v err=%v", result, err)
	}
}

func TestExecuteTreatsPrometheusParentCancellationAsFatal(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	archive := &recordingArchive{}
	result, err := Execute(
		ctx,
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  prometheusConfig(),
		},
		unusedRunner{},
		archive,
		redact.New(),
		prometheusCollectors(func(
			context.Context,
			prometheus.Config,
			kubernetes.Runner,
			telemetry.Forwarder,
			kubernetes.Sink,
			*redact.Redactor,
		) (prometheus.Report, error) {
			cancel()
			return prometheus.Report{}, context.Canceled
		}),
	)
	if !errors.Is(err, context.Canceled) ||
		!result.CanceledBeforeBundle ||
		result.ArchivePath != "" ||
		archive.finalizeCalls != 0 {
		t.Fatalf("cancellation was not fatal: result=%+v err=%v", result, err)
	}
}

func TestExecuteRequiresPrometheusDependenciesOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	valid := prometheusCollectors(func(
		context.Context,
		prometheus.Config,
		kubernetes.Runner,
		telemetry.Forwarder,
		kubernetes.Sink,
		*redact.Redactor,
	) (prometheus.Report, error) {
		config := prometheusConfig()
		return completeNoDataPrometheusReport(config.Start, config.End), nil
	})
	tests := []struct {
		name       string
		collectors Collectors
	}{
		{
			name: "collector",
			collectors: Collectors{
				Kubernetes: valid.Kubernetes,
				Workload:   valid.Workload,
				Forwarder:  valid.Forwarder,
			},
		},
		{
			name: "forwarder",
			collectors: Collectors{
				Kubernetes: valid.Kubernetes,
				Workload:   valid.Workload,
				Prometheus: valid.Prometheus,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Execute(
				context.Background(),
				Request{
					CurrentTime: time.Now,
					Prometheus:  prometheusConfig(),
				},
				unusedRunner{},
				&recordingArchive{},
				redact.New(),
				test.collectors,
			); err == nil {
				t.Fatal("expected Prometheus dependency validation error")
			}
		})
	}

	disabled := valid
	disabled.Prometheus = nil
	disabled.Forwarder = nil
	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
		},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		disabled,
	)
	if err != nil || result.Coverage[SourcePrometheus].State != CoverageNotRequested {
		t.Fatalf("disabled Prometheus required dependencies: result=%+v err=%v", result, err)
	}
}

func TestExecuteDoesNotLeakPrometheusErrorsQueriesOrCredentials(t *testing.T) {
	t.Parallel()
	const secret = "raw-prometheus-secret"
	const rawQuery = `sum(rate(secret_metric{password="credential"}[5m]))`
	archive := &recordingArchive{}
	var events []Event
	config := prometheusConfig()
	config.Context = "password=" + secret
	config.Kubeconfig = "/tmp/" + secret

	report := partialPrometheusReport(config.Start, config.End)
	report.Reason = "https://127.0.0.1:9090/" + secret
	report.Diagnostic = "stderr: " + secret
	report.Coverage[0].QueryID = rawQuery
	report.Coverage[0].Category = "label=" + secret
	report.Coverage[0].Reason = "raw_http_error_" + secret
	report.Coverage[0].Diagnostic = "password=" + secret
	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{Namespace: "qodo"},
			Prometheus:  config,
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		prometheusCollectors(func(
			context.Context,
			prometheus.Config,
			kubernetes.Runner,
			telemetry.Forwarder,
			kubernetes.Sink,
			*redact.Redactor,
		) (prometheus.Report, error) {
			return report, errors.New("GET tunnel failed: " + secret)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := json.Marshal(archive.manifest)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{
		string(manifestData),
		string(archive.files[issuesArtifactPath]),
		string(archive.files[summaryArtifactPath]),
		result.Coverage[SourcePrometheus].Reason,
	}
	for _, event := range events {
		values = append(values, event.Reason)
	}
	for _, value := range values {
		for _, forbidden := range []string{
			secret,
			rawQuery,
			"127.0.0.1",
			"stderr",
			"raw_http_error",
			"credential",
		} {
			if strings.Contains(value, forbidden) {
				t.Fatalf("Prometheus output leaked %q: %s", forbidden, value)
			}
		}
	}
}

func prometheusConfig() *prometheus.Config {
	start := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	config := prometheus.DefaultConfig()
	config.Namespace = "qodo"
	config.Namespaces = []string{"qodo"}
	config.Start = start
	config.End = start.Add(time.Hour)
	return &config
}

func prometheusCollectors(collector PrometheusCollector) Collectors {
	return Collectors{
		Kubernetes: successfulKubernetesCollector,
		Workload:   successfulWorkloadCollector,
		Prometheus: collector,
		Forwarder:  &unusedForwarder{},
	}
}

func completeNoDataPrometheusReport(start time.Time, end time.Time) prometheus.Report {
	catalog := prometheus.BuiltinCatalog()
	queryCoverage := make([]prometheus.Coverage, len(catalog.Queries))
	for index, query := range catalog.Queries {
		queryCoverage[index] = prometheus.Coverage{
			QueryID:  query.ID,
			Category: query.Category,
			State:    prometheus.CoverageNoData,
		}
	}
	return prometheus.Report{
		CatalogVersion: catalog.Version,
		RequestedStart: start.Format(time.RFC3339Nano),
		RequestedEnd:   end.Format(time.RFC3339Nano),
		ActualStart:    start.Format(time.RFC3339Nano),
		ActualEnd:      end.Format(time.RFC3339Nano),
		StepSeconds:    int64(prometheus.DefaultStep / time.Second),
		State:          prometheus.ReportComplete,
		Coverage:       queryCoverage,
		Artifacts: []prometheus.Artifact{{
			Path:    prometheus.CoverageArtifactPath,
			Records: len(queryCoverage),
			Bytes:   1,
		}},
	}
}

func partialPrometheusReport(start time.Time, end time.Time) prometheus.Report {
	report := completeNoDataPrometheusReport(start, end)
	report.State = prometheus.ReportPartial
	report.Reason = reasonPrometheusCoverageIncomplete
	report.Coverage[0].State = prometheus.CoverageFailed
	report.Coverage[0].Reason = "request_failed"
	return report
}

func failedPrometheusReport(start time.Time, end time.Time, reason string) prometheus.Report {
	report := completeNoDataPrometheusReport(start, end)
	report.State = prometheus.ReportFailed
	report.Reason = reason
	for index := range report.Coverage {
		report.Coverage[index].State = prometheus.CoverageFailed
		report.Coverage[index].Reason = reason
	}
	return report
}

func assertPrometheusManifestAndSummary(
	t *testing.T,
	archive *recordingArchive,
	config prometheus.Config,
	coverage map[Source]Coverage,
) {
	t.Helper()
	manifestCoverage, ok := archive.manifest.Collection["coverage"].(map[Source]Coverage)
	if !ok || len(manifestCoverage) != len(SupportedSources()) {
		t.Fatalf("manifest coverage is incomplete: %#v", archive.manifest.Collection["coverage"])
	}
	for _, source := range SupportedSources() {
		if _, exists := manifestCoverage[source]; !exists {
			t.Fatalf("manifest omitted source %q: %#v", source, manifestCoverage)
		}
	}
	if manifestCoverage[SourcePrometheus].State != CoverageComplete ||
		manifestCoverage[SourcePrometheus].RequestedStart == nil ||
		manifestCoverage[SourcePhoenix].State != CoverageNotRequested {
		t.Fatalf("manifest source coverage was not preserved: %#v", manifestCoverage)
	}
	metadata, ok := archive.manifest.Collection["prometheus"].(map[string]any)
	if !ok ||
		metadata["enabled"] != true ||
		metadata["namespace"] != "qodo" ||
		!reflect.DeepEqual(metadata["namespaces"], []string{"qodo"}) ||
		metadata["all_namespaces"] != false ||
		metadata["catalog_version"] != prometheus.CatalogVersion ||
		metadata["configured_start"] != config.Start.Format(time.RFC3339Nano) ||
		metadata["requested_start"] != config.Start.Format(time.RFC3339Nano) ||
		metadata["collection_status"] != CoverageComplete.String() ||
		metadata["queries_no_data"] != len(prometheus.BuiltinCatalog().Queries) {
		t.Fatalf("unexpected Prometheus metadata: %#v", metadata)
	}
	if coverage[SourcePrometheus].RequestedEnd == nil ||
		metadata["configured_end"] != coverage[SourcePrometheus].RequestedEnd.Format(time.RFC3339Nano) {
		t.Fatalf("Prometheus bounds were not preserved: metadata=%#v coverage=%+v", metadata, coverage)
	}
	summary := string(archive.files[summaryArtifactPath])
	if !strings.Contains(summary, "## Prometheus") ||
		!strings.Contains(summary, "- Collection: complete") ||
		!strings.Contains(summary, "Catalog: v1") {
		t.Fatalf("Prometheus summary missing: %s", summary)
	}
}
