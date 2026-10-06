package collection

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

type recordingArchive struct {
	files         map[string][]byte
	addCalls      map[string]int
	manifest      bundle.Manifest
	finalizeCalls int
}

type unusedRunner struct{}

func (unusedRunner) Run(
	context.Context,
	int64,
	...string,
) (kubernetes.CommandResult, error) {
	return kubernetes.CommandResult{}, errors.New("unexpected runner call")
}

func (archive *recordingArchive) Add(path string, data []byte) error {
	if archive.files == nil {
		archive.files = make(map[string][]byte)
	}
	if archive.addCalls == nil {
		archive.addCalls = make(map[string]int)
	}
	archive.addCalls[path]++
	archive.files[path] = append([]byte(nil), data...)
	return nil
}

func (archive *recordingArchive) FinalizeContext(
	_ context.Context,
	manifest bundle.Manifest,
) (string, error) {
	archive.finalizeCalls++
	archive.manifest = manifest
	return "/tmp/support-bundle.tar.gz", nil
}

func TestExecutePublishesCompleteKubernetesCollection(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	generatedAt := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	collectorFinished := false
	report := kubernetes.Report{
		Namespaces:          []string{"qodo"},
		NamespacesRequested: 1,
		Pods:                2,
		Containers:          3,
	}

	result, err := Execute(
		context.Background(),
		Request{
			CollectorVersion: "test",
			CurrentTime: func() time.Time {
				if !collectorFinished {
					t.Fatal("capture time sampled before collection finished")
				}
				return generatedAt
			},
			Activity: "deploying",
			Kubernetes: kubernetes.Config{
				Namespace:        "qodo",
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: func(
				context.Context,
				kubernetes.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (kubernetes.Report, error) {
				collectorFinished = true
				return report, nil
			},
			Workload: successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				t.Fatal("unexpected Zitadel collection")
				return zitadel.Outcome{}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoverageComplete.String() ||
		result.ArchivePath != "/tmp/support-bundle.tar.gz" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Coverage[SourceKubernetes].State != CoverageComplete ||
		result.Coverage[SourceZitadel].State != CoverageNotRequested ||
		result.Coverage[SourceWorkload].State != CoverageComplete ||
		result.Coverage[SourcePrometheus].State != CoverageNotRequested ||
		result.Coverage[SourcePhoenix].State != CoverageNotRequested {
		t.Fatalf("unexpected coverage: %+v", result.Coverage)
	}
	if archive.finalizeCalls != 1 ||
		archive.manifest.Collection["status"] != CoverageComplete.String() {
		t.Fatalf("unexpected manifest: %+v", archive.manifest)
	}
	if archive.manifest.Collection["namespace"] != "qodo" {
		t.Fatalf("singular namespace was omitted: %+v", archive.manifest.Collection)
	}
	if archive.manifest.GeneratedAt != generatedAt ||
		archive.manifest.CollectorVersion != "test" ||
		archive.manifest.CustomerContext["activity"] != "deploying" {
		t.Fatalf("manifest inputs were not preserved: %+v", archive.manifest)
	}
	if _, exists := archive.files[issuesArtifactPath]; exists {
		t.Fatalf("unexpected issues artifact: %+v", archive.files)
	}
	if !strings.Contains(
		string(archive.files[summaryArtifactPath]),
		"Collection status: complete",
	) {
		t.Fatalf("unexpected summary: %s", archive.files[summaryArtifactPath])
	}
}

func TestExecuteStopsBeforeArchiveForMissingAuthenticationHelper(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	workloadCalled := false

	_, err := Execute(
		context.Background(),
		Request{
			CollectorVersion: "test",
			CurrentTime:      time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces: []string{"qodo"},
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: func(
				context.Context,
				kubernetes.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (kubernetes.Report, error) {
				return kubernetes.Report{},
					&kubernetes.AuthenticationHelperUnavailableError{
						Command: "company-kube-auth",
					}
			},
			Workload: func(
				context.Context,
				workload.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (workload.Report, error) {
				workloadCalled = true
				return workload.Report{}, nil
			},
		},
	)

	var unavailable *kubernetes.AuthenticationHelperUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Command != "company-kube-auth" {
		t.Fatalf("error=%T %v", err, err)
	}
	if workloadCalled || archive.finalizeCalls != 0 || len(archive.files) != 0 {
		t.Fatalf(
			"collection continued: workload=%t finalize=%d files=%v",
			workloadCalled,
			archive.finalizeCalls,
			archive.files,
		)
	}
}

func TestExecuteReportsKubernetesWorkloadAndSummaryStages(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	var events []Event

	_, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces:       []string{"qodo", "qodo"},
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload: func(
				_ context.Context,
				config workload.Config,
				_ kubernetes.Runner,
				_ kubernetes.Sink,
				_ *redact.Redactor,
			) (workload.Report, error) {
				if !reflect.DeepEqual(config.Namespaces, []string{"qodo"}) {
					t.Fatalf("workload namespaces were not normalized: %v", config.Namespaces)
				}
				config.Progress(workload.Progress{
					Stage:   workload.ProgressNamespaceComplete,
					Current: 1,
					Total:   1,
				})
				return successfulWorkloadCollector(
					context.Background(),
					config,
					nil,
					nil,
					nil,
				)
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var kinds []EventKind
	for _, event := range events {
		kinds = append(kinds, event.Kind)
	}
	want := []EventKind{
		EventKubernetesStarted,
		EventKubernetesComplete,
		EventWorkloadStarted,
		EventWorkloadProgress,
		EventWorkloadComplete,
		EventArchiveSummary,
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("events=%+v want=%v", events, want)
	}
	if events[3].Current != 1 || events[3].Total != 1 {
		t.Fatalf("workload counts were not forwarded: %+v", events[3])
	}
	if events[4].Current != 1 || events[4].Total != 1 {
		t.Fatalf("workload completion changed count units: %+v", events[4])
	}
}

func TestExecuteReportsWorkloadFailureWithoutClaimingCompletion(t *testing.T) {
	t.Parallel()
	var events []Event
	_, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces:       []string{"qodo"},
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload: func(
				context.Context,
				workload.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (workload.Report, error) {
				return workload.Report{}, errors.New("password=private-workload-error")
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var foundUnavailable bool
	for _, event := range events {
		if event.Kind == EventWorkloadComplete {
			t.Fatalf("failed workload reported complete: %+v", events)
		}
		if event.Kind == EventWorkloadUnavailable {
			foundUnavailable = true
			if event.Reason != "" {
				t.Fatalf("raw workload error reached progress: %+v", event)
			}
		}
	}
	if !foundUnavailable {
		t.Fatalf("missing workload unavailable event: %+v", events)
	}
}

func TestExecuteReportsKubernetesPartialWithoutClaimingCompletion(t *testing.T) {
	t.Parallel()
	var events []Event
	_, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces:       []string{"qodo"},
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		Collectors{
			Kubernetes: func(
				context.Context,
				kubernetes.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (kubernetes.Report, error) {
				return kubernetes.Report{
					Namespaces:           []string{"qodo"},
					CollectionNamespaces: []string{"qodo"},
					NamespacesRequested:  1,
					Issues: []kubernetes.Issue{{
						Operation: "collect pods",
						Message:   "request failed",
					}},
				}, nil
			},
			Workload: successfulWorkloadCollector,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var foundPartial bool
	for _, event := range events {
		if event.Kind == EventKubernetesComplete {
			t.Fatalf("partial Kubernetes collection reported complete: %+v", events)
		}
		if event.Kind == EventKubernetesPartial {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatalf("missing Kubernetes partial event: %+v", events)
	}
}

func TestExecuteTreatsCollectedZitadelFailureAsComplete(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	var events []Event
	status := 503
	probeReport := &zitadel.Report{
		SchemaVersion: 1,
		Checks: []zitadel.Check{{
			Name:       "discovery",
			Status:     zitadel.StatusFailed,
			Reason:     zitadel.ReasonHTTPError,
			HTTPStatus: &status,
		}},
	}

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces:       []string{"qodo"},
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Zitadel: &zitadel.Config{
				Namespace:    "qodo",
				Pod:          "platform-0",
				Container:    "platform",
				ProbeTimeout: 15 * time.Second,
			},
			Progress: func(event Event) {
				events = append(events, event)
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload:   successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				return zitadel.Outcome{
					Report: probeReport,
					Data:   []byte(`{"schema_version":1}`),
				}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoverageComplete.String() ||
		result.Coverage[SourceZitadel].State != CoverageComplete {
		t.Fatalf("diagnostic evidence should be complete: %+v", result)
	}
	if string(archive.files[zitadelArtifactPath]) != `{"schema_version":1}` {
		t.Fatalf("probe artifact was not staged: %+v", archive.files)
	}
	sourceEvents := optionalSourceEvents(events)
	if len(sourceEvents) != 2 ||
		sourceEvents[0].Kind != EventZitadelStarted ||
		sourceEvents[1].Kind != EventZitadelDiagnosticFailure {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestExecuteFailsClosedWhenRequestedProbeHasNoReport(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespaces:       []string{"qodo"},
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Zitadel: &zitadel.Config{
				Namespace: "qodo",
				Pod:       "platform-0",
				Container: "platform",
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload:   successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				return zitadel.Outcome{}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoveragePartial.String() ||
		result.Coverage[SourceZitadel].State != CoverageUnavailable ||
		result.ConnectivityFailure != reasonMissingReport {
		t.Fatalf("missing evidence did not fail closed: %+v", result)
	}
	if _, exists := archive.files[zitadelArtifactPath]; exists {
		t.Fatal("missing report unexpectedly staged a Zitadel artifact")
	}
	issues := string(archive.files[issuesArtifactPath])
	if !strings.Contains(issues, reasonMissingReport) {
		t.Fatalf("missing report issue was not recorded: %s", issues)
	}
}

func TestExecuteRejectsZitadelReportWithoutArtifact(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespace:        "qodo",
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
			Zitadel: &zitadel.Config{
				Namespace: "qodo",
				Pod:       "platform-0",
				Container: "platform",
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload:   successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				return zitadel.Outcome{
					Report: &zitadel.Report{
						SchemaVersion: 1,
						Checks: []zitadel.Check{{
							Name:   "configuration",
							Status: zitadel.StatusPassed,
						}},
					},
				}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoveragePartial.String() ||
		result.Coverage[SourceZitadel].State != CoverageUnavailable ||
		result.ConnectivityFailure != reasonMissingArtifact {
		t.Fatalf("missing artifact did not fail closed: %+v", result)
	}
	if _, exists := archive.files[zitadelArtifactPath]; exists {
		t.Fatal("empty Zitadel artifact was staged")
	}
}

func TestExecuteSanitizesCollectorFailureReason(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	var events []Event
	const secret = "raw-secret"

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespace:        "qodo",
				Since:            time.Hour,
				MaxMetadataBytes: 1024,
			},
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
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload:   successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				return zitadel.Outcome{
					Reason: "password=" + secret + "\r\nforged",
				}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	issues := string(archive.files[issuesArtifactPath])
	summary := string(archive.files[summaryArtifactPath])
	sourceEvents := optionalSourceEvents(events)
	eventReason := sourceEvents[len(sourceEvents)-1].Reason
	for name, value := range map[string]string{
		"result":  result.ConnectivityFailure,
		"issues":  issues,
		"summary": summary,
		"event":   eventReason,
	} {
		if strings.Contains(value, secret) ||
			strings.ContainsAny(value, "\r\n") && name == "event" {
			t.Fatalf("%s retained unsafe reason: %q", name, value)
		}
	}
}

func TestExecuteValidatesRequiredDependencies(t *testing.T) {
	t.Parallel()
	request := Request{
		CurrentTime: time.Now,
		Zitadel:     &zitadel.Config{},
	}
	validCollectors := Collectors{
		Kubernetes: successfulKubernetesCollector,
		Workload:   successfulWorkloadCollector,
		Zitadel: func(
			context.Context,
			zitadel.Config,
			kubernetes.Runner,
			*redact.Redactor,
		) zitadel.Outcome {
			return zitadel.Outcome{}
		},
	}
	tests := []struct {
		name       string
		ctx        context.Context
		runner     kubernetes.Runner
		archive    Archive
		redactor   *redact.Redactor
		collectors Collectors
	}{
		{"context", nil, unusedRunner{}, &recordingArchive{}, redact.New(), validCollectors},
		{"runner", context.Background(), nil, &recordingArchive{}, redact.New(), validCollectors},
		{"archive", context.Background(), unusedRunner{}, nil, redact.New(), validCollectors},
		{"redactor", context.Background(), unusedRunner{}, &recordingArchive{}, nil, validCollectors},
		{
			"unconfigured redactor",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			&redact.Redactor{},
			validCollectors,
		},
		{
			"kubernetes collector",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			redact.New(),
			Collectors{
				Workload: validCollectors.Workload,
				Zitadel:  validCollectors.Zitadel,
			},
		},
		{
			"workload collector",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			redact.New(),
			Collectors{
				Kubernetes: validCollectors.Kubernetes,
				Zitadel:    validCollectors.Zitadel,
			},
		},
		{
			"Zitadel collector",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			redact.New(),
			Collectors{
				Kubernetes: validCollectors.Kubernetes,
				Workload:   validCollectors.Workload,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Execute(
				test.ctx,
				request,
				test.runner,
				test.archive,
				test.redactor,
				test.collectors,
			); err == nil {
				t.Fatal("expected dependency validation error")
			}
		})
	}
	if _, err := Execute(
		context.Background(),
		Request{Zitadel: &zitadel.Config{}},
		unusedRunner{},
		&recordingArchive{},
		redact.New(),
		validCollectors,
	); err == nil {
		t.Fatal("expected current time dependency validation error")
	}
}

func TestExecuteInvokesProductionWorkloadCollectorAndStagesArtifact(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	defaults := DefaultCollectors()
	defaults.Kubernetes = successfulKubernetesCollector
	runner := workloadAPIRunner{}

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespace:  "qodo",
				Context:    "production-context",
				Kubeconfig: "/tmp/production-kubeconfig",
				Timeout:    time.Second,
				Since:      time.Hour,
			},
		},
		&runner,
		archive,
		redact.New(),
		defaults,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkloadReport == nil ||
		result.WorkloadReport.RetainedRecords != 1 ||
		result.Coverage[SourceWorkload].State != CoverageComplete {
		t.Fatalf("production workload collector was not reflected in result: %+v", result)
	}
	artifact := string(archive.files[workload.WorkloadsArtifactPath])
	if !strings.Contains(artifact, `"kind":"Deployment"`) ||
		!strings.Contains(artifact, `"namespace":"qodo"`) {
		t.Fatalf("production collector did not stage normalized artifact: %s", artifact)
	}
	coverageArtifact := string(archive.files[workloadReportPath])
	if !strings.Contains(coverageArtifact, `"namespaces":`) ||
		!strings.Contains(coverageArtifact, `"coverage":`) ||
		!strings.Contains(coverageArtifact, `"retained_records": 1`) ||
		!strings.Contains(coverageArtifact, `"max_total_bytes": 16777216`) {
		t.Fatalf("production collector did not stage its coverage ledger: %s", coverageArtifact)
	}
	if len(runner.calls) != 9 {
		t.Fatalf("production workload API calls=%d, want 9", len(runner.calls))
	}
	for _, call := range runner.calls {
		if call.maxBytes != workload.DefaultMaxResponseBytes ||
			call.arguments[0] != "--kubeconfig" ||
			call.arguments[1] != "/tmp/production-kubeconfig" ||
			call.arguments[2] != "--context" ||
			call.arguments[3] != "production-context" {
			t.Fatalf("production transport inputs were not preserved: %+v", call)
		}
	}
}

func TestExecuteDerivesWorkloadConfigForExplicitAndAllNamespaceScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		kubernetesConfig kubernetes.Config
		kubernetesReport kubernetes.Report
		kubernetesErr    error
		wantNamespaces   []string
	}{
		{
			name: "explicit list survives pod collector failure",
			kubernetesConfig: kubernetes.Config{
				Namespaces: []string{"beta", "alpha"},
			},
			kubernetesErr:  errors.New("pod collection failed"),
			wantNamespaces: []string{"beta", "alpha"},
		},
		{
			name: "singular explicit namespace",
			kubernetesConfig: kubernetes.Config{
				Namespace: "platform",
			},
			wantNamespaces: []string{"platform"},
		},
		{
			name: "all namespaces use collected report scope",
			kubernetesConfig: kubernetes.Config{
				AllNamespaces: true,
				Namespaces:    []string{"must-not-be-used"},
			},
			kubernetesReport: kubernetes.Report{
				Namespaces:           []string{"application-a"},
				CollectionNamespaces: []string{"application-a", "application-b"},
			},
			wantNamespaces: []string{"application-a", "application-b"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			archive := &recordingArchive{}
			var received workload.Config
			kubernetesConfig := test.kubernetesConfig
			kubernetesConfig.Context = "cluster-context"
			kubernetesConfig.Kubeconfig = "/tmp/kubeconfig"
			kubernetesConfig.Timeout = 17 * time.Second
			kubernetesConfig.Since = time.Hour

			_, err := Execute(
				context.Background(),
				Request{
					CurrentTime: time.Now,
					Kubernetes:  kubernetesConfig,
				},
				unusedRunner{},
				archive,
				redact.New(),
				Collectors{
					Kubernetes: func(
						context.Context,
						kubernetes.Config,
						kubernetes.Runner,
						kubernetes.Sink,
						*redact.Redactor,
					) (kubernetes.Report, error) {
						return test.kubernetesReport, test.kubernetesErr
					},
					Workload: func(
						_ context.Context,
						config workload.Config,
						_ kubernetes.Runner,
						sink kubernetes.Sink,
						_ *redact.Redactor,
					) (workload.Report, error) {
						received = config
						if err := sink.Add(
							workload.WorkloadsArtifactPath,
							[]byte("{\"kind\":\"Deployment\"}\n"),
						); err != nil {
							return workload.Report{}, err
						}
						report, err := successfulWorkloadCollector(
							context.Background(),
							config,
							unusedRunner{},
							sink,
							redact.New(),
						)
						report.RetainedRecords = 1
						report.RetainedBytes = 22
						return report, err
					},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(received.Namespaces, test.wantNamespaces) {
				t.Fatalf("workload namespaces=%v, want %v", received.Namespaces, test.wantNamespaces)
			}
			if received.Context != "cluster-context" ||
				received.Kubeconfig != "/tmp/kubeconfig" ||
				received.Timeout != 17*time.Second ||
				received.MaxResponseBytes != workload.DefaultMaxResponseBytes ||
				received.MaxSourceBytes != workload.DefaultMaxSourceBytes ||
				received.MaxTotalBytes != workload.DefaultMaxTotalBytes ||
				received.MaxNamespaces != workload.DefaultMaxNamespaces ||
				received.MaxDuration != workload.DefaultMaxCollectionDuration {
				t.Fatalf("unexpected workload config: %+v", received)
			}
			if _, exists := archive.files[workload.WorkloadsArtifactPath]; !exists {
				t.Fatal("workload collector did not receive the shared archive")
			}
		})
	}
}

func TestExecuteTreatsWorkloadFailureAsSanitizedPartialCollection(t *testing.T) {
	t.Parallel()
	archive := &recordingArchive{}
	const secret = "raw-workload-secret"

	result, err := Execute(
		context.Background(),
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespace: "qodo",
				Timeout:   time.Second,
				Since:     time.Hour,
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload: func(
				context.Context,
				workload.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (workload.Report, error) {
				return workload.Report{
					Namespaces: []string{"qodo"},
					Coverage: []workload.Coverage{{
						Namespace:    "qodo",
						Source:       "deployments",
						State:        workload.CoverageFailed,
						ArtifactPath: workload.WorkloadsArtifactPath,
						Reason:       "request_failed",
						Diagnostic:   "password=" + secret + "\naccess denied",
					}},
				}, errors.New("password=" + secret + "\r\nforged")
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CoveragePartial.String() ||
		result.Coverage[SourceWorkload].State != CoverageUnavailable ||
		result.Coverage[SourceWorkload].Reason != reasonCollectionError {
		t.Fatalf("workload failure did not produce partial coverage: %+v", result)
	}
	issues := string(archive.files[issuesArtifactPath])
	if strings.Contains(issues, secret) || !strings.Contains(issues, redact.Replacement) ||
		!strings.Contains(issues, "qodo/deployments") ||
		!strings.Contains(issues, "access denied") {
		t.Fatalf("workload issues were not safely represented: %s", issues)
	}
	coverageArtifact := string(archive.files[workloadReportPath])
	if strings.Contains(coverageArtifact, secret) ||
		!strings.Contains(coverageArtifact, redact.Replacement) ||
		!strings.Contains(coverageArtifact, `"diagnostic": "password=[REDACTED] access denied"`) {
		t.Fatalf("workload coverage ledger was not safely staged: %s", coverageArtifact)
	}
}

func TestExecuteTreatsWorkloadCancellationAsFatal(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	archive := &recordingArchive{}

	result, err := Execute(
		ctx,
		Request{
			CurrentTime: time.Now,
			Kubernetes: kubernetes.Config{
				Namespace: "qodo",
				Timeout:   time.Second,
			},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: successfulKubernetesCollector,
			Workload: func(
				context.Context,
				workload.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (workload.Report, error) {
				cancel()
				return workload.Report{}, context.Canceled
			},
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				t.Fatal("unexpected Zitadel collection")
				return zitadel.Outcome{}
			},
		},
	)
	if !errors.Is(err, context.Canceled) || !result.CanceledBeforeBundle {
		t.Fatalf("unexpected cancellation result: result=%+v err=%v", result, err)
	}
	if archive.finalizeCalls != 0 || len(archive.files) != 0 {
		t.Fatalf("canceled workload collection staged or finalized data: %+v", archive)
	}
}

func TestExecuteStopsBeforeProbeAndFinalizationAfterCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	archive := &recordingArchive{}

	result, err := Execute(
		ctx,
		Request{
			CurrentTime: time.Now,
			Kubernetes:  kubernetes.Config{},
			Zitadel:     &zitadel.Config{},
		},
		unusedRunner{},
		archive,
		redact.New(),
		Collectors{
			Kubernetes: func(
				context.Context,
				kubernetes.Config,
				kubernetes.Runner,
				kubernetes.Sink,
				*redact.Redactor,
			) (kubernetes.Report, error) {
				cancel()
				return kubernetes.Report{}, errors.New("interrupted")
			},
			Workload: successfulWorkloadCollector,
			Zitadel: func(
				context.Context,
				zitadel.Config,
				kubernetes.Runner,
				*redact.Redactor,
			) zitadel.Outcome {
				t.Fatal("unexpected Zitadel collection")
				return zitadel.Outcome{}
			},
		},
	)
	if !errors.Is(err, context.Canceled) || !result.CanceledBeforeBundle {
		t.Fatalf("unexpected cancellation result: result=%+v err=%v", result, err)
	}
	if archive.finalizeCalls != 0 || len(archive.files) != 0 {
		t.Fatalf("canceled collection staged or finalized data: %+v", archive)
	}
}

func successfulKubernetesCollector(
	context.Context,
	kubernetes.Config,
	kubernetes.Runner,
	kubernetes.Sink,
	*redact.Redactor,
) (kubernetes.Report, error) {
	return kubernetes.Report{
		Namespaces:           []string{"qodo"},
		CollectionNamespaces: []string{"qodo"},
		NamespacesRequested:  1,
	}, nil
}

func optionalSourceEvents(events []Event) []Event {
	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		switch event.Kind {
		case EventKubernetesStarted,
			EventKubernetesComplete,
			EventKubernetesPartial,
			EventWorkloadStarted,
			EventWorkloadProgress,
			EventWorkloadComplete,
			EventWorkloadPartial,
			EventWorkloadUnavailable,
			EventArchiveSummary:
			continue
		default:
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func successfulWorkloadCollector(
	_ context.Context,
	config workload.Config,
	_ kubernetes.Runner,
	_ kubernetes.Sink,
	_ *redact.Redactor,
) (workload.Report, error) {
	report := workload.Report{
		Namespaces:       append([]string(nil), config.Namespaces...),
		MaxResponseBytes: config.MaxResponseBytes,
		MaxSourceBytes:   config.MaxSourceBytes,
		MaxTotalBytes:    config.MaxTotalBytes,
	}
	sources := []struct {
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
	}
	for _, namespace := range config.Namespaces {
		for _, source := range sources {
			report.Coverage = append(report.Coverage, workload.Coverage{
				Namespace:    namespace,
				Source:       source.name,
				State:        workload.CoverageCollected,
				ArtifactPath: source.path,
			})
		}
	}
	return report, nil
}

type workloadAPICall struct {
	maxBytes  int64
	arguments []string
}

type workloadAPIRunner struct {
	calls []workloadAPICall
}

func (runner *workloadAPIRunner) Run(
	_ context.Context,
	maxBytes int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	runner.calls = append(runner.calls, workloadAPICall{
		maxBytes:  maxBytes,
		arguments: append([]string(nil), arguments...),
	})
	apiPath := arguments[len(arguments)-1]
	var response string
	switch {
	case strings.Contains(apiPath, "/deployments?"):
		response = `{"kind":"DeploymentList","items":[{"kind":"Deployment","metadata":{"name":"api","namespace":"qodo"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"registry/api:1"}]}}},"status":{}}]}`
	case strings.Contains(apiPath, "/statefulsets?"):
		response = `{"kind":"StatefulSetList","items":[]}`
	case strings.Contains(apiPath, "/daemonsets?"):
		response = `{"kind":"DaemonSetList","items":[]}`
	case strings.Contains(apiPath, "/cronjobs?"):
		response = `{"kind":"CronJobList","items":[]}`
	case strings.Contains(apiPath, "/jobs?"):
		response = `{"kind":"JobList","items":[]}`
	case strings.Contains(apiPath, "/services?"):
		response = `{"kind":"ServiceList","items":[]}`
	case strings.Contains(apiPath, "/endpointslices?"):
		response = `{"kind":"EndpointSliceList","items":[]}`
	case strings.Contains(apiPath, "/horizontalpodautoscalers?"):
		response = `{"kind":"HorizontalPodAutoscalerList","items":[]}`
	case strings.Contains(apiPath, "/persistentvolumeclaims?"):
		response = `{"kind":"PersistentVolumeClaimList","items":[]}`
	default:
		return kubernetes.CommandResult{}, errors.New("unexpected workload API path")
	}
	return kubernetes.CommandResult{Stdout: []byte(response)}, nil
}
