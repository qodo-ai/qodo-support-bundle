package collection

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

type recordingArchive struct {
	files         map[string][]byte
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
		result.Coverage[SourceWorkload].State != CoverageNotRequested ||
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
	if len(events) != 2 ||
		events[0].Kind != EventZitadelStarted ||
		events[1].Kind != EventZitadelDiagnosticFailure {
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
	eventReason := events[len(events)-1].Reason
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
			"kubernetes collector",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			redact.New(),
			Collectors{Zitadel: validCollectors.Zitadel},
		},
		{
			"Zitadel collector",
			context.Background(),
			unusedRunner{},
			&recordingArchive{},
			redact.New(),
			Collectors{Kubernetes: validCollectors.Kubernetes},
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
		Namespaces:          []string{"qodo"},
		NamespacesRequested: 1,
	}, nil
}
