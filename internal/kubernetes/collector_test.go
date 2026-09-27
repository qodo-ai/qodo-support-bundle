package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

type fakeRunner struct {
	mutex     sync.Mutex
	calls     []string
	limits    []int64
	logLimits []int64
	run       func(arguments string) (CommandResult, error)
}

func (runner *fakeRunner) Run(
	_ context.Context,
	maxBytes int64,
	arguments ...string,
) (CommandResult, error) {
	joined := strings.Join(arguments, " ")
	runner.mutex.Lock()
	runner.calls = append(runner.calls, joined)
	runner.limits = append(runner.limits, maxBytes)
	if strings.HasPrefix(joined, "logs ") {
		runner.logLimits = append(runner.logLimits, maxBytes)
	}
	runner.mutex.Unlock()
	return runner.run(joined)
}

type memorySink struct {
	files map[string][]byte
}

func (sink *memorySink) Add(path string, data []byte) error {
	if sink.files == nil {
		sink.files = make(map[string][]byte)
	}
	sink.files[path] = append([]byte(nil), data...)
	return nil
}

func TestCollectRejectsNonPositiveTimeout(t *testing.T) {
	t.Parallel()
	for _, timeout := range []time.Duration{0, -time.Second} {
		_, err := Collect(
			context.Background(),
			Config{
				Namespace:        "qodo",
				Timeout:          timeout,
				MaxMetadataBytes: 1 << 20,
				MaxLogBytes:      1 << 20,
				MaxTotalLogBytes: 10 << 20,
			},
			&fakeRunner{},
			&memorySink{},
			redact.New(),
		)
		if err == nil || !strings.Contains(err.Error(), "timeout must be positive") {
			t.Fatalf("timeout %s returned %v", timeout, err)
		}
	}
}

func TestCollectRejectsUnsafeMetadataBounds(t *testing.T) {
	t.Parallel()
	for _, limit := range []int64{0, -1, MaximumMetadataBytes + 1} {
		_, err := Collect(
			context.Background(),
			Config{
				Namespace:        "qodo",
				Since:            time.Minute,
				Timeout:          time.Second,
				MaxMetadataBytes: limit,
				MaxLogBytes:      1024,
				MaxTotalLogBytes: 1024,
			},
			&fakeRunner{},
			&memorySink{},
			redact.New(),
		)
		if err == nil || !strings.Contains(err.Error(), "max metadata bytes") {
			t.Fatalf("limit %d returned %v", limit, err)
		}
	}
}

func TestCollectStopsBeforeNamespaceScanWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{
		run: func(string) (CommandResult, error) {
			t.Fatal("collector ran a command after cancellation")
			return CommandResult{}, nil
		},
	}

	_, err := Collect(
		ctx,
		Config{
			Namespace:        "qodo",
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      1 << 20,
			MaxTotalLogBytes: 10 << 20,
		},
		runner,
		&memorySink{},
		redact.New(),
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestCollectWritesSanitizedMetadataEventsAndLogs(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get pods"):
				return CommandResult{Stdout: []byte(`{"items":[{
				  "metadata":{"name":"platform-1","namespace":"qodo","labels":{"app":"platform"}},
				  "spec":{"nodeName":"node-1","containers":[{"name":"platform","image":"registry/platform:1"}]},
				  "status":{
				    "phase":"Running",
				    "startTime":"2026-09-15T06:00:00Z",
				    "containerStatuses":[{
				      "name":"platform",
				      "ready":true,
				      "restartCount":1,
				      "image":"registry/platform:1",
				      "imageID":"sha256:123"
				    }]
				  }
				}]}`)}, nil
			case strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[{
				  "metadata":{"name":"started","namespace":"qodo","creationTimestamp":"2026-09-15T06:00:00Z"},
				  "involvedObject":{"kind":"Pod","namespace":"qodo","name":"platform-1"},
				  "type":"Normal",
				  "reason":"Started",
				  "message":"Started for user@example.com",
				  "count":1
				}]}`)}, nil
			case strings.HasPrefix(arguments, "logs "):
				return CommandResult{Stdout: []byte(
					`2026-09-15T06:00:00Z {"request_id":"req-1","email":"user@example.com","token":"raw-token"}` + "\n",
				)}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}
	sink := &memorySink{}

	report, err := Collect(
		context.Background(),
		Config{
			Namespace:        "qodo",
			Selector:         "app=platform",
			Since:            30 * time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      1 << 20,
			MaxTotalLogBytes: 10 << 20,
		},
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if report.Pods != 1 || report.Containers != 1 || report.LogFiles != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, path := range []string{
		"kubernetes/pods.jsonl",
		"kubernetes/events.jsonl",
		"kubernetes/logs/platform-1/platform.log",
		"kubernetes/logs/platform-1/platform-previous.log",
	} {
		if _, exists := sink.files[path]; !exists {
			t.Fatalf("expected bundle file %q; files: %+v", path, sink.files)
		}
	}
	for path, data := range sink.files {
		output := string(data)
		for _, forbidden := range []string{"user@example.com", "raw-token"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("%s contains sensitive value %q: %s", path, forbidden, output)
			}
		}
	}
	if !containsCall(runner.calls, "--selector app=platform") {
		t.Fatalf("pod selector was not used: %+v", runner.calls)
	}
	if !containsCall(runner.calls, "--previous=true") {
		t.Fatalf("previous log was not collected: %+v", runner.calls)
	}
}

func TestCollectFailsWhenPodsCannotBeListed(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(string) (CommandResult, error) {
			return CommandResult{Stderr: []byte("unauthorized token=raw-token")}, errors.New("exit 1")
		},
	}

	_, err := Collect(
		context.Background(),
		Config{
			Namespace:        "qodo",
			Since:            time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      1024,
			MaxTotalLogBytes: 1024,
		},
		runner,
		&memorySink{},
		redact.New(),
	)

	if err == nil {
		t.Fatal("expected collection error")
	}
	if strings.Contains(err.Error(), "raw-token") {
		t.Fatalf("error leaked token: %s", err)
	}
}

func TestCollectCoversMultipleNamespacesAndInitContainers(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get pods") &&
				strings.Contains(arguments, "--namespace qodo"):
				return CommandResult{Stdout: []byte(`{"items":[{
				  "metadata":{"name":"platform-1","namespace":"qodo"},
				  "spec":{
				    "containers":[{"name":"platform","image":"registry/platform:1"}],
				    "initContainers":[{"name":"bootstrap","image":"registry/bootstrap:1"}],
				    "ephemeralContainers":[{"name":"debug","image":"registry/debug:1"}]
				  },
				  "status":{
				    "phase":"Running",
				    "startTime":"2026-09-15T06:00:00Z",
				    "containerStatuses":[{"name":"platform","ready":true}],
				    "initContainerStatuses":[{"name":"bootstrap","ready":true}],
				    "ephemeralContainerStatuses":[{
				      "name":"debug",
				      "ready":false,
				      "restartCount":2,
				      "lastState":{"terminated":{"reason":"OOMKilled"}}
				    }]
				  }
				}]}`)}, nil
			case strings.Contains(arguments, "get pods") &&
				strings.Contains(arguments, "--namespace zitadel"):
				return CommandResult{Stdout: []byte(`{"items":[{
				  "metadata":{"name":"zitadel-1","namespace":"zitadel"},
				  "spec":{"containers":[{"name":"zitadel","image":"registry/zitadel:1"}]},
				  "status":{"phase":"Running","startTime":"2026-09-15T06:01:00Z"}
				}]}`)}, nil
			case strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			case strings.HasPrefix(arguments, "logs "):
				return CommandResult{Stdout: []byte("2026-09-15T06:00:00Z ready\n")}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}
	sink := &memorySink{}
	progressStages := make([]string, 0)

	report, err := Collect(
		context.Background(),
		Config{
			Namespaces:       []string{"qodo", "zitadel"},
			Since:            30 * time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      1 << 20,
			MaxTotalLogBytes: 10 << 20,
			Progress: func(progress Progress) {
				progressStages = append(progressStages, progress.Stage)
			},
		},
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if report.Pods != 2 ||
		report.Containers != 4 ||
		report.InitContainers != 1 ||
		report.EphemeralContainers != 1 ||
		report.ContainerRestarts != 2 ||
		report.OOMKills != 1 ||
		report.LogFiles != 4 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, path := range []string{
		"kubernetes/pods/qodo.jsonl",
		"kubernetes/pods/zitadel.jsonl",
		"kubernetes/events/qodo.jsonl",
		"kubernetes/events/zitadel.jsonl",
		"kubernetes/logs/qodo/platform-1/platform.log",
		"kubernetes/logs/qodo/platform-1/bootstrap.log",
		"kubernetes/logs/qodo/platform-1/debug.log",
		"kubernetes/logs/zitadel/zitadel-1/zitadel.log",
	} {
		if _, exists := sink.files[path]; !exists {
			t.Fatalf("expected bundle file %q; files: %+v", path, sink.files)
		}
	}
	if !containsCall(runner.calls, "--namespace qodo") ||
		!containsCall(runner.calls, "--namespace zitadel") {
		t.Fatalf("not all namespaces were collected: %+v", runner.calls)
	}
	if !strings.Contains(
		string(sink.files["kubernetes/pods/qodo.jsonl"]),
		`"init_containers":[`,
	) {
		t.Fatal("init-container metadata is missing")
	}
	if !strings.Contains(
		string(sink.files["kubernetes/pods/qodo.jsonl"]),
		`"ephemeral_containers":[`,
	) {
		t.Fatal("ephemeral-container metadata is missing")
	}
	if containsCall(runner.calls, "--container debug --timestamps=true --since 1800s --previous=true") {
		t.Fatalf("previous ephemeral-container log was requested: %+v", runner.calls)
	}
	stages := strings.Join(progressStages, ",")
	for _, expectedStage := range []string{
		"namespaces_discovered",
		"scan_namespace",
		"collect_logs",
		"logs_progress",
	} {
		if !strings.Contains(stages, expectedStage) {
			t.Fatalf("missing progress stage %q: %s", expectedStage, stages)
		}
	}
}

func TestCollectDerivesMetadataCommandLimitAbove64MiB(t *testing.T) {
	t.Parallel()
	const metadataLimit int64 = 128 << 20
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get pods"),
				strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}

	_, err := Collect(
		context.Background(),
		Config{
			Namespace:        "qodo",
			Since:            time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: metadataLimit,
			MaxLogBytes:      1024,
			MaxTotalLogBytes: 1024,
		},
		runner,
		&memorySink{},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.limits) != 2 {
		t.Fatalf("unexpected calls: %+v", runner.calls)
	}
	for _, limit := range runner.limits {
		if limit != metadataLimit {
			t.Fatalf("metadata command limit=%d want=%d", limit, metadataLimit)
		}
	}
}

func TestCollectEnforcesAggregateMetadataBudgetAcrossNamespaces(t *testing.T) {
	t.Parallel()
	podForNamespace := func(namespace string) pod {
		current := pod{
			Metadata: objectMetadata{
				Name:      "platform-0",
				Namespace: namespace,
				Labels: map[string]string{
					"app": strings.Repeat("platform", 8),
				},
			},
		}
		current.Spec.Containers = []containerSpec{{Name: "platform"}}
		current.Status.Phase = "Running"
		current.Status.ContainerStatuses = []containerStatus{{
			Name:         "platform",
			RestartCount: 1,
			LastState: map[string]containerState{
				"terminated": {Reason: "Error"},
			},
		}}
		return current
	}
	eventForNamespace := func(namespace string) event {
		return event{
			Metadata: objectMetadata{Name: "started", Namespace: namespace},
			Involved: objectReference{
				Kind:      "Pod",
				Namespace: namespace,
				Name:      "platform-0",
			},
			Type:    "Warning",
			Reason:  "Restarted",
			Message: strings.Repeat("bounded event ", 8),
			Count:   1,
		}
	}
	firstPod := podForNamespace("one")
	podRecords, err := marshalPodRecords([]pod{firstPod}, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	containerRecords, _, _, err := marshalContainerEventRecords(
		[]pod{firstPod},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	eventRecords, err := marshalEventRecords(
		[]event{eventForNamespace("one")},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstNamespaceBytes := int64(
		len(podRecords) + len(containerRecords) + len(eventRecords),
	)
	metadataLimit := firstNamespaceBytes + 1

	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			namespace := "one"
			for _, candidate := range []string{"two", "three"} {
				if strings.Contains(arguments, "--namespace "+candidate) {
					namespace = candidate
				}
			}
			switch {
			case strings.Contains(arguments, "get pods"):
				data, marshalErr := json.Marshal(podList{
					Items: []pod{podForNamespace(namespace)},
				})
				return CommandResult{Stdout: data}, marshalErr
			case strings.Contains(arguments, "get events"):
				data, marshalErr := json.Marshal(eventList{
					Items: []event{eventForNamespace(namespace)},
				})
				return CommandResult{Stdout: data}, marshalErr
			case strings.HasPrefix(arguments, "logs "):
				return CommandResult{Stdout: []byte("ready\n")}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}
	sink := &memorySink{}

	report, err := Collect(
		context.Background(),
		Config{
			Namespaces:       []string{"one", "two", "three"},
			Since:            time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: metadataLimit,
			MaxLogBytes:      1 << 20,
			MaxTotalLogBytes: 10 << 20,
			LogWorkers:       2,
		},
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}

	var stagedMetadataBytes int64
	for path, data := range sink.files {
		if strings.HasPrefix(path, "kubernetes/pods/") ||
			strings.HasPrefix(path, "kubernetes/events/") ||
			strings.HasPrefix(path, "kubernetes/container_events/") {
			stagedMetadataBytes += int64(len(data))
		}
	}
	if stagedMetadataBytes != firstNamespaceBytes ||
		report.MetadataBytes != firstNamespaceBytes ||
		stagedMetadataBytes > metadataLimit {
		t.Fatalf(
			"metadata budget failed: staged=%d report=%d limit=%d",
			stagedMetadataBytes,
			report.MetadataBytes,
			metadataLimit,
		)
	}
	if report.MetadataLimitBytes != metadataLimit ||
		report.TruncatedMetadataFiles != 1 ||
		report.MetadataNamespacesSkipped != 1 {
		t.Fatalf("unexpected metadata report: %+v", report)
	}
	if containsCall(runner.calls, "--namespace three") {
		t.Fatalf("collector continued after exhaustion: %+v", runner.calls)
	}
	issueText := ""
	for _, issue := range report.Issues {
		issueText += issue.Message + " "
	}
	if !strings.Contains(issueText, "aggregate metadata limit reached") ||
		!strings.Contains(issueText, "skipped 1 namespaces") {
		t.Fatalf("missing metadata issues: %+v", report.Issues)
	}
}

func TestCollectDiscoversApplicationNamespacesWhenSystemScopeIsExcluded(
	t *testing.T,
) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get namespaces"):
				return CommandResult{Stdout: []byte(`{"items":[
				  {"metadata":{"name":"zitadel"}},
				  {"metadata":{"name":"qodo-platform"}},
				  {"metadata":{"name":"rabbitmq-system"}},
				  {"metadata":{"name":"kube-system"}},
				  {"metadata":{"name":"gke-managed-system"}}
				]}`)}, nil
			case strings.Contains(arguments, "get pods"),
				strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}
	sink := &memorySink{}

	report, err := Collect(
		context.Background(),
		Config{
			AllNamespaces:           true,
			ExcludeSystemNamespaces: true,
			Since:                   time.Minute,
			Timeout:                 time.Second,
			MaxMetadataBytes:        1 << 20,
			MaxLogBytes:             1024,
			MaxTotalLogBytes:        1024,
		},
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !report.AllNamespaces ||
		report.NamespacesRequested != 3 ||
		!reflect.DeepEqual(
			report.Namespaces,
			[]string{"qodo-platform", "rabbitmq-system", "zitadel"},
		) {
		t.Fatalf("unexpected discovery report: %+v", report)
	}
	if !reflect.DeepEqual(
		report.ExcludedNamespaces,
		[]string{"gke-managed-system", "kube-system"},
	) {
		t.Fatalf("unexpected excluded namespaces: %+v", report.ExcludedNamespaces)
	}
	for _, path := range []string{
		"kubernetes/pods/qodo-platform.jsonl",
		"kubernetes/pods/rabbitmq-system.jsonl",
		"kubernetes/pods/zitadel.jsonl",
		"kubernetes/events/qodo-platform.jsonl",
		"kubernetes/events/rabbitmq-system.jsonl",
		"kubernetes/events/zitadel.jsonl",
	} {
		if _, exists := sink.files[path]; !exists {
			t.Fatalf("expected bundle file %q; files: %+v", path, sink.files)
		}
	}
}

func TestCollectContinuesWhenOneOfMultipleNamespacesIsForbidden(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get pods") &&
				strings.Contains(arguments, "--namespace qodo"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			case strings.Contains(arguments, "get pods") &&
				strings.Contains(arguments, "--namespace zitadel"):
				return CommandResult{
					Stderr: []byte("forbidden token=secret-value"),
				}, errors.New("exit 1")
			case strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}

	report, err := Collect(
		context.Background(),
		Config{
			Namespaces:       []string{"qodo", "zitadel"},
			Since:            time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      1024,
			MaxTotalLogBytes: 1024,
		},
		runner,
		&memorySink{},
		redact.New(),
	)

	if err != nil {
		t.Fatal(err)
	}
	if len(report.Namespaces) != 1 ||
		report.Namespaces[0] != "qodo" ||
		len(report.Issues) != 1 {
		t.Fatalf("unexpected partial report: %+v", report)
	}
	if strings.Contains(report.Issues[0].Message, "secret-value") {
		t.Fatalf("issue leaked token: %+v", report.Issues[0])
	}
}

func TestCollectEnforcesAggregateLogBudgetAcrossStreams(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			switch {
			case strings.Contains(arguments, "get pods"):
				return CommandResult{Stdout: []byte(`{"items":[{
				  "metadata":{"name":"platform-1","namespace":"qodo"},
				  "spec":{"containers":[
				    {"name":"first"},
				    {"name":"second"},
				    {"name":"third"},
				    {"name":"fourth"}
				  ]},
				  "status":{"phase":"Running"}
				}]}`)}, nil
			case strings.Contains(arguments, "get events"):
				return CommandResult{Stdout: []byte(`{"items":[]}`)}, nil
			case strings.HasPrefix(arguments, "logs "):
				return CommandResult{Stdout: []byte("abcdefghij")}, nil
			default:
				return CommandResult{}, errors.New("unexpected command")
			}
		},
	}
	sink := &memorySink{}

	report, err := Collect(
		context.Background(),
		Config{
			Namespace:        "qodo",
			Since:            time.Minute,
			Timeout:          time.Second,
			MaxMetadataBytes: 1 << 20,
			MaxLogBytes:      4,
			MaxTotalLogBytes: 10,
			LogWorkers:       3,
		},
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}

	totalLogBytes := 0
	for path, data := range sink.files {
		if strings.HasPrefix(path, "kubernetes/logs/") {
			totalLogBytes += len(data)
		}
	}
	if totalLogBytes != 10 ||
		report.LogFiles != 3 ||
		report.TruncatedLogFiles != 3 {
		t.Fatalf("aggregate log budget was not enforced: report=%+v bytes=%d", report, totalLogBytes)
	}
	if !reflect.DeepEqual(runner.logLimits, []int64{4, 4, 2}) {
		t.Fatalf("unexpected per-command log limits: %+v", runner.logLimits)
	}
	if len(report.Issues) != 4 {
		t.Fatalf("unexpected aggregate budget issues: %+v", report.Issues)
	}
	var issueMessages strings.Builder
	for _, issue := range report.Issues {
		issueMessages.WriteString(issue.Message)
		issueMessages.WriteByte(' ')
	}
	messages := issueMessages.String()
	if !strings.Contains(messages, "truncated this stream") ||
		!strings.Contains(messages, "skipped 1 log streams") ||
		!strings.Contains(messages, "per-stream byte limit") {
		t.Fatalf("missing aggregate budget issue: %+v", report.Issues)
	}
	if containsCall(runner.calls, "--container fourth") {
		t.Fatalf("excess stream was collected: %+v", runner.calls)
	}
}

func TestSanitizeLogRedactsMultilinePrivateKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		footer string
	}{
		{
			name:   "RSA",
			header: "-----BEGIN RSA PRIVATE KEY-----",
			footer: "-----END RSA PRIVATE KEY-----",
		},
		{
			name:   "EC",
			header: "-----BEGIN EC PRIVATE KEY-----",
			footer: "-----END EC PRIVATE KEY-----",
		},
		{
			name:   "OPENSSH",
			header: "-----BEGIN OPENSSH PRIVATE KEY-----",
			footer: "-----END OPENSSH PRIVATE KEY-----",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := "before\nprefix " + test.header + "\n" +
				"raw-private-key-body\nsecond-secret-line\n" +
				test.footer + " suffix\n" +
				"after request_id=req-123\n"

			output := string(sanitizeLog([]byte(input), redact.New()))

			for _, forbidden := range []string{
				test.header,
				test.footer,
				"raw-private-key-body",
				"second-secret-line",
			} {
				if strings.Contains(output, forbidden) {
					t.Fatalf("output contains private-key material %q: %s", forbidden, output)
				}
			}
			for _, expected := range []string{
				"before",
				"prefix " + redact.Replacement,
				"suffix",
				"request_id=req-123",
			} {
				if !strings.Contains(output, expected) {
					t.Fatalf("output omitted safe text %q: %s", expected, output)
				}
			}
		})
	}
}

func TestSanitizeLogRedactsUnterminatedPrivateKey(t *testing.T) {
	t.Parallel()
	input := []byte(
		"safe before\n-----BEGIN RSA PRIVATE KEY-----\n" +
			"raw-private-key-body\nmust-also-be-suppressed\n",
	)

	output := string(sanitizeLog(input, redact.New()))

	if strings.Contains(output, "raw-private-key-body") ||
		strings.Contains(output, "must-also-be-suppressed") {
		t.Fatalf("output contains unterminated private-key material: %s", output)
	}
	if output != "safe before\n"+redact.Replacement+"\n" {
		t.Fatalf("unexpected sanitized output: %q", output)
	}
}

func TestSanitizeLogRedactsSensitiveJSONAssignment(t *testing.T) {
	t.Parallel()
	input := []byte(`request_id=req-123 password={"note":"raw-secret"}` + "\n")

	output := string(sanitizeLog(input, redact.New()))

	if strings.Contains(output, "raw-secret") {
		t.Fatalf("output contains assigned JSON secret: %s", output)
	}
	if !strings.Contains(output, "request_id=req-123") ||
		!strings.Contains(output, "password="+redact.Replacement) {
		t.Fatalf("unexpected sanitized output: %s", output)
	}
}

func TestSanitizeLogPrivateKeyStateIsPerCall(t *testing.T) {
	t.Parallel()
	redactor := redact.New()
	var waitGroup sync.WaitGroup
	for index := 0; index < 20; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			output := string(sanitizeLog(
				[]byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n"),
				redactor,
			))
			if output != redact.Replacement+"\n" {
				t.Errorf("unexpected concurrent output: %q", output)
			}
		}()
	}
	waitGroup.Wait()
}

func TestBoundedBufferCapsOutputWithoutBreakingWriterContract(t *testing.T) {
	t.Parallel()
	buffer := newBoundedBuffer(4)

	written, err := buffer.Write([]byte("abcdefgh"))

	if err != nil || written != 8 {
		t.Fatalf("unexpected write result: written=%d err=%v", written, err)
	}
	if string(buffer.Bytes()) != "abcd" || !buffer.Truncated() {
		t.Fatalf("unexpected buffer state: %q truncated=%v", buffer.Bytes(), buffer.Truncated())
	}
}

func TestStoppingBoundedBufferTerminatesAtScanLimit(t *testing.T) {
	t.Parallel()
	stopped := false
	buffer := newStoppingBoundedBuffer(4, func() {
		stopped = true
	})

	written, err := buffer.Write([]byte("abcdefgh"))

	if !errors.Is(err, errCommandOutputLimit) || written != 4 {
		t.Fatalf("unexpected write result: written=%d err=%v", written, err)
	}
	if string(buffer.Bytes()) != "abcd" || !buffer.Truncated() {
		t.Fatalf("unexpected buffer state: %q truncated=%v", buffer.Bytes(), buffer.Truncated())
	}
	if !stopped {
		t.Fatal("scan limit did not stop the command")
	}
}

func TestReadLogUsesSinceAndRetainsBoundedLog(t *testing.T) {
	t.Parallel()
	runner := &fakeRunner{
		run: func(arguments string) (CommandResult, error) {
			if !strings.Contains(arguments, "--since 1800s") {
				return CommandResult{}, errors.New("missing duration lower bound")
			}
			return CommandResult{Stdout: []byte(
				"2026-09-15T06:01:01Z before\n" +
					"2026-09-15T06:01:02Z error\n",
			)}, nil
		},
	}

	result := readLog(
		context.Background(),
		Config{
			Since:   30 * time.Minute,
			Timeout: time.Second,
		},
		runner,
		redact.New(),
		logRequest{
			namespace:      "qodo",
			namespaceCount: 1,
			podName:        "platform-1",
			containerName:  "platform",
			maxBytes:       1 << 20,
		},
	)

	if result.issue != nil {
		t.Fatalf("unexpected log result: %+v", result)
	}
	if !reflect.DeepEqual(runner.logLimits, []int64{1 << 20}) {
		t.Fatalf("log did not use its retained cap: %+v", runner.logLimits)
	}
	text := string(result.data)
	for _, expected := range []string{"before", "error"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q from log: %s", expected, text)
		}
	}
}

func TestMarshalContainerEventsIncludesRestartsAndOOMKills(t *testing.T) {
	t.Parallel()
	input := []pod{{
		Metadata: objectMetadata{Name: "platform-1", Namespace: "qodo"},
		Status: podStatus{
			StartTime: "2026-09-15T06:00:00Z",
			ContainerStatuses: []containerStatus{{
				Name:         "platform",
				RestartCount: 2,
				LastState: map[string]containerState{
					"terminated": {
						Reason:     "OOMKilled",
						FinishedAt: "2026-09-15T06:05:00Z",
					},
				},
			}},
		},
	}}

	data, restarts, oomKills, err := marshalContainerEventRecords(input, redact.New())

	if err != nil {
		t.Fatal(err)
	}
	if restarts != 2 || oomKills != 1 {
		t.Fatalf("unexpected lifecycle counts: restarts=%d oom=%d", restarts, oomKills)
	}
	text := string(data)
	for _, expected := range []string{
		`"@timestamp":"2026-09-15T06:05:00Z"`,
		`"kind":"OOMKilled"`,
		`"restart_count":2`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %s: %s", expected, text)
		}
	}
}

func containsCall(calls []string, value string) bool {
	for _, call := range calls {
		if strings.Contains(call, value) {
			return true
		}
	}
	return false
}
