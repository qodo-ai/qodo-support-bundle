package kubernetes

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

type fakeRunner struct {
	mutex sync.Mutex
	calls []string
	run   func(arguments string) (CommandResult, error)
}

func (runner *fakeRunner) Run(
	_ context.Context,
	_ int64,
	arguments ...string,
) (CommandResult, error) {
	joined := strings.Join(arguments, " ")
	runner.mutex.Lock()
	runner.calls = append(runner.calls, joined)
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
			Namespace:   "qodo",
			Selector:    "app=platform",
			Since:       30 * time.Minute,
			Timeout:     time.Second,
			MaxLogBytes: 1 << 20,
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
			Namespace:   "qodo",
			Since:       time.Minute,
			Timeout:     time.Second,
			MaxLogBytes: 1024,
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
				    "initContainers":[{"name":"bootstrap","image":"registry/bootstrap:1"}]
				  },
				  "status":{
				    "phase":"Running",
				    "startTime":"2026-09-15T06:00:00Z",
				    "containerStatuses":[{"name":"platform","ready":true}],
				    "initContainerStatuses":[{"name":"bootstrap","ready":true}]
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
			Namespaces:  []string{"qodo", "zitadel"},
			Since:       30 * time.Minute,
			Timeout:     time.Second,
			MaxLogBytes: 1 << 20,
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
		report.Containers != 3 ||
		report.InitContainers != 1 ||
		report.LogFiles != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, path := range []string{
		"kubernetes/pods/qodo.jsonl",
		"kubernetes/pods/zitadel.jsonl",
		"kubernetes/events/qodo.jsonl",
		"kubernetes/events/zitadel.jsonl",
		"kubernetes/logs/qodo/platform-1/platform.log",
		"kubernetes/logs/qodo/platform-1/bootstrap.log",
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
			MaxLogBytes:             1024,
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
			Namespaces:  []string{"qodo", "zitadel"},
			Since:       time.Minute,
			Timeout:     time.Second,
			MaxLogBytes: 1024,
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

func containsCall(calls []string, value string) bool {
	for _, call := range calls {
		if strings.Contains(call, value) {
			return true
		}
	}
	return false
}
