package phoenix

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
)

const (
	testTraceA       = "11111111111111111111111111111111"
	testTraceB       = "22222222222222222222222222222222"
	testSpanA        = "aaaaaaaaaaaaaaaa"
	testSpanB        = "bbbbbbbbbbbbbbbb"
	testSpanC        = "cccccccccccccccc"
	testGlobalSpanID = "U3Bhbjox"
)

type fakeRunner struct {
	err error
}

func (runner *fakeRunner) Run(
	_ context.Context,
	_ int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	if runner.err != nil {
		return kubernetes.CommandResult{}, runner.err
	}
	if contains(arguments, "services") {
		return kubernetes.CommandResult{Stdout: []byte(`{
			"apiVersion":"v1","kind":"ServiceList","items":[{
				"metadata":{"name":"generated-phoenix","namespace":"observability","labels":{"app.kubernetes.io/name":"phoenix"}},
				"spec":{"ports":[{"port":6006}]}
			}]
		}`)}, nil
	}
	return kubernetes.CommandResult{Stdout: []byte(`{
		"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSliceList","items":[{
			"metadata":{"name":"generated-phoenix-abc","namespace":"observability","labels":{"kubernetes.io/service-name":"generated-phoenix"}},
			"endpoints":[{"addresses":["10.0.0.1"],"conditions":{"ready":true}}]
		}]
	}`)}, nil
}

type fakeForwarder struct {
	baseURL string
	target  telemetry.Target
	ctx     context.Context
	err     error
}

func (forwarder *fakeForwarder) Forward(
	ctx context.Context,
	target telemetry.Target,
) (*telemetry.Tunnel, error) {
	forwarder.ctx = ctx
	forwarder.target = target
	if forwarder.err != nil {
		return nil, forwarder.err
	}
	return &telemetry.Tunnel{BaseURL: forwarder.baseURL}, nil
}

type fakeSink struct {
	mu    sync.Mutex
	files map[string][]byte
	fail  string
}

func (sink *fakeSink) Add(path string, data []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if path == sink.fail {
		return errors.New("staging failed with secret detail")
	}
	if sink.files == nil {
		sink.files = make(map[string][]byte)
	}
	sink.files[path] = append([]byte(nil), data...)
	return nil
}

func TestConfigDefaultsValidationAndTraceNormalization(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.TraceID = strings.ToUpper(testTraceA)
	defaulted := config.WithDefaults()
	if defaulted.TraceID != testTraceA {
		t.Fatalf("TraceID = %q", defaulted.TraceID)
	}
	if err := defaulted.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"non UTC", func(config *Config) { config.Start = config.Start.In(time.FixedZone("x", 3600)) }},
		{"long window", func(config *Config) { config.End = config.Start.Add(24*time.Hour + time.Nanosecond) }},
		{"bad trace", func(config *Config) { config.TraceID = "xyz" }},
		{"response bound", func(config *Config) { config.MaxResponseBytes = MaximumResponseBytes + 1 }},
		{"project bound", func(config *Config) { config.MaxProjects = MaximumProjects + 1 }},
		{"trace bound", func(config *Config) { config.MaxTraces = MaximumTraces + 1 }},
		{"span bound", func(config *Config) { config.MaxSpans = MaximumSpans + 1 }},
		{"page bound", func(config *Config) { config.MaxPages = MaximumPages + 1 }},
		{"trace budget", func(config *Config) { config.MaxRetainedBytesPerTrace = MaximumRetainedPerTrace + 1 }},
		{"total budget", func(config *Config) { config.MaxTotalRetainedBytes = MaximumTotalRetained + 1 }},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			config := testConfig().WithDefaults()
			testCase.change(&config)
			if !errors.Is(config.Validate(), ErrInvalidConfig) {
				t.Fatalf("Validate() = %v", config.Validate())
			}
		})
	}
}

func TestCollectWindowStagesDeterministicRedactedArtifacts(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	var mu sync.Mutex
	var requests []string
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		mu.Lock()
		requests = append(requests, request.URL.RequestURI())
		mu.Unlock()
		switch {
		case request.URL.Path == projectsPath && request.URL.Query().Get("cursor") == "":
			assertProjectQuery(t, request.URL.Query(), "")
			writeJSON(t, writer, map[string]any{
				"data": []any{
					map[string]any{"id": "project-b", "name": "Alice Smith oncology", "description": nil},
				},
				"next_cursor": "project-next",
			})
		case request.URL.Path == projectsPath:
			assertProjectQuery(t, request.URL.Query(), "project-next")
			writeJSON(t, writer, map[string]any{
				"data": []any{
					map[string]any{"id": "project-a", "name": "token=project-secret"},
				},
			})
		case request.URL.Path == "/v1/projects/project-a/spans" &&
			request.URL.Query().Get("cursor") == "":
			assertWindowSpanQuery(t, request.URL.Query(), config, "")
			writeJSON(t, writer, map[string]any{
				"data": []any{
					wireSpanJSON(testTraceB, testSpanB, config.Start.Add(3*time.Minute), config.Start.Add(4*time.Minute)),
					wireSpanJSON(testTraceA, testSpanA, config.Start.Add(time.Minute), config.Start.Add(2*time.Minute)),
				},
				"next_cursor": "span-next",
			})
		case request.URL.Path == "/v1/projects/project-a/spans":
			assertWindowSpanQuery(t, request.URL.Query(), config, "span-next")
			outside := wireSpanJSON(testTraceA, testSpanC, config.End, config.End.Add(time.Second))
			inside := wireSpanJSON(testTraceA, testSpanC, config.Start.Add(2*time.Minute), config.Start.Add(3*time.Minute))
			writeJSON(t, writer, map[string]any{"data": []any{outside, inside}})
		case request.URL.Path == "/v1/projects/project-b/spans":
			assertWindowSpanQuery(t, request.URL.Query(), config, "")
			writeJSON(t, writer, map[string]any{"data": []any{}})
		default:
			t.Errorf("unexpected request %s", request.URL.RequestURI())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer stop()

	sink := &fakeSink{}
	forwarder := &fakeForwarder{baseURL: serverURL}
	report, err := Collect(
		context.Background(),
		config,
		&fakeRunner{},
		forwarder,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if report.State != ReportComplete || report.Coverage.State != CoverageCollected {
		t.Fatalf("report = %+v", report)
	}
	if err := ValidateCompleteCoverage(report); err != nil {
		t.Fatalf("ValidateCompleteCoverage() = %v", err)
	}
	if forwarder.target != (telemetry.Target{Service: "generated-phoenix", Port: 6006}) {
		t.Fatalf("target = %+v", forwarder.target)
	}
	select {
	case <-forwarder.ctx.Done():
	default:
		t.Fatal("forward context was not canceled")
	}
	if report.Coverage.ProjectsFound != 2 ||
		report.Coverage.ProjectsRead != 2 ||
		report.Coverage.TracesFound != 2 ||
		report.Coverage.TracesRetained != 2 ||
		report.Coverage.SpansFound != 4 ||
		report.Coverage.SpansRetained != 3 ||
		report.Coverage.PagesRead != 5 {
		t.Fatalf("coverage = %+v", report.Coverage)
	}
	records := decodeJSONLines(t, sink.files[TracesArtifactPath])
	if len(records) != 2 ||
		records[0].Project.ID != "project-a" ||
		records[0].TraceID != testTraceA ||
		records[1].TraceID != testTraceB ||
		records[0].Correlation != "surrounding" ||
		len(records[0].Spans) != 2 ||
		records[0].Spans[0].SpanID != testSpanA {
		t.Fatalf("records = %+v", records)
	}
	tracesText := string(sink.files[TracesArtifactPath])
	coverageText := string(sink.files[CoverageArtifactPath])
	for _, forbidden := range []string{
		"raw description",
		"Alice Smith",
		"oncology",
		"leukemia",
		"status raw secret",
		"event raw secret",
		"attribute raw secret",
		"unknown.attribute",
		"prompt",
		"completion",
		"http://",
		"?token=",
	} {
		if strings.Contains(tracesText, forbidden) || strings.Contains(coverageText, forbidden) {
			t.Fatalf("artifact contains forbidden value %q", forbidden)
		}
	}
	if !strings.Contains(tracesText, redact.Replacement) {
		t.Fatal("expected retained strings to be redacted")
	}
	mu.Lock()
	if len(requests) != 5 {
		t.Fatalf("requests = %#v", requests)
	}
	mu.Unlock()
}

func TestCollectExactTraceNormalizesIDAndRequiresExactResponse(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.TraceID = strings.ToUpper(testTraceA)
	config = config.WithDefaults()
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case projectsPath:
			writeJSON(t, writer, map[string]any{
				"data": []any{map[string]any{"id": "p", "name": "project"}},
			})
		case "/v1/projects/p/spans":
			values := request.URL.Query()
			if !requestHasOnly(values, "limit", "trace_id") ||
				values.Get("trace_id") != testTraceA {
				t.Errorf("exact query = %#v", values)
			}
			writeJSON(t, writer, map[string]any{
				"data": []any{
					wireSpanJSON(strings.ToUpper(testTraceA), strings.ToUpper(testSpanA), config.Start.Add(-time.Hour), config.End.Add(time.Hour)),
				},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer stop()
	sink := &fakeSink{}
	report, err := Collect(
		context.Background(),
		config,
		&fakeRunner{},
		&fakeForwarder{baseURL: serverURL},
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	records := decodeJSONLines(t, sink.files[TracesArtifactPath])
	if report.TraceID != testTraceA ||
		report.Mode != "trace_id" ||
		len(records) != 1 ||
		records[0].Correlation != "direct" ||
		records[0].TraceID != testTraceA {
		t.Fatalf("report=%+v records=%+v", report, records)
	}
}

func TestCollectExactTraceRejectsMismatchedResponseNonfatally(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.TraceID = testTraceA
	serverURL, stop := startSingleProjectServer(t, config.WithDefaults(), func() map[string]any {
		return map[string]any{
			"data": []any{
				wireSpanJSON(testTraceB, testSpanA, config.Start, config.Start.Add(time.Second)),
			},
		}
	})
	defer stop()
	sink := &fakeSink{}
	report, err := Collect(
		context.Background(),
		config,
		&fakeRunner{},
		&fakeForwarder{baseURL: serverURL},
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if report.State != ReportFailed ||
		report.Reason != reasonMalformed ||
		report.Diagnostic != "spans_rejected" ||
		len(sink.files[TracesArtifactPath]) != 0 ||
		len(sink.files[CoverageArtifactPath]) == 0 {
		t.Fatalf("report=%+v files=%v", report, mapKeys(sink.files))
	}
}

func TestStrictWireRejectionsAndWindowDrop(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	valid := fmt.Sprintf(`{"data":[{
		"id":"%s","name":"span","context":{"trace_id":"%s","span_id":"%s"},
		"span_kind":"CHAIN","parent_id":null,
		"start_time":"%s","end_time":"%s","status_code":"OK",
		"status_message":null,"attributes":{},"events":[]
	}]}`,
		testGlobalSpanID,
		testTraceA,
		testSpanA,
		config.Start.Format(time.RFC3339Nano),
		config.Start.Add(time.Second).Format(time.RFC3339Nano),
	)
	cases := map[string][]byte{
		"unknown field":  []byte(strings.Replace(valid, `"events":[]`, `"events":[],"future":true`, 1)),
		"duplicate key":  []byte(strings.Replace(valid, `"name":"span"`, `"name":"span","name":"other"`, 1)),
		"missing events": []byte(strings.Replace(valid, `,"events":[]`, "", 1)),
		"invalid kind":   []byte(strings.Replace(valid, `"span_kind":"CHAIN"`, `"span_kind":"PERSON_NAME"`, 1)),
		"invalid status": []byte(strings.Replace(valid, `"status_code":"OK"`, `"status_code":"DIAGNOSIS"`, 1)),
		"missing data":   []byte(`{}`),
		"null data":      []byte(`{"data":null}`),
		"invalid utf8":   append([]byte(valid), 0xff),
	}
	for name, data := range cases {
		name, data := name, data
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeSpans(data, config, redact.New()); !errors.Is(err, errInvalidResponse) {
				t.Fatalf("decodeSpans() error = %v", err)
			}
		})
	}
	outside := []byte(fmt.Sprintf(`{"data":[{
		"id":"%s","name":"span","context":{"trace_id":"%s","span_id":"%s"},
		"span_kind":"CHAIN","start_time":"%s","end_time":"%s",
		"status_code":"OK","status_message":"","attributes":{},"events":[]
	}]}`,
		testGlobalSpanID,
		testTraceA,
		testSpanA,
		config.End.Format(time.RFC3339Nano),
		config.End.Add(time.Second).Format(time.RFC3339Nano),
	))
	spans, _, found, err := decodeSpans(outside, config, redact.New())
	if err != nil || found != 1 || len(spans) != 0 {
		t.Fatalf("outside decode: spans=%+v found=%d err=%v", spans, found, err)
	}
	crossing := []byte(fmt.Sprintf(`{"data":[{
		"id":"%s","name":"span","context":{"trace_id":"%s","span_id":"%s"},
		"span_kind":"CHAIN","start_time":"%s","end_time":"%s",
		"status_code":"OK","status_message":"","attributes":{},"events":[]
	}]}`,
		testGlobalSpanID,
		testTraceA,
		testSpanA,
		config.End.Add(-time.Second).Format(time.RFC3339Nano),
		config.End.Add(time.Second).Format(time.RFC3339Nano),
	))
	spans, _, found, err = decodeSpans(crossing, config, redact.New())
	if err != nil || found != 1 || len(spans) != 1 {
		t.Fatalf("crossing decode: spans=%+v found=%d err=%v", spans, found, err)
	}
	for name, data := range map[string][]byte{
		"missing project data": []byte(`{}`),
		"null project data":    []byte(`{"data":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeProjects(data); !errors.Is(err, errInvalidResponse) {
				t.Fatalf("decodeProjects() error = %v", err)
			}
		})
	}
}

func TestPaginationLoopAndLimitsProduceStableCoverage(t *testing.T) {
	t.Parallel()
	t.Run("cursor loop", func(t *testing.T) {
		config := testConfig().WithDefaults()
		serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.URL.Path == projectsPath {
				writeJSON(t, writer, map[string]any{
					"data":        []any{},
					"next_cursor": "same",
				})
				return
			}
			writer.WriteHeader(http.StatusNotFound)
		}))
		defer stop()
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			config,
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		if err != nil || report.Reason != reasonMalformed || report.Diagnostic != "cursor_loop" {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("trace limit", func(t *testing.T) {
		config := testConfig()
		config.MaxTraces = 1
		serverURL, stop := startSingleProjectServer(t, config.WithDefaults(), func() map[string]any {
			return map[string]any{
				"data": []any{
					wireSpanJSON(testTraceA, testSpanA, config.Start, config.Start.Add(time.Second)),
					wireSpanJSON(testTraceB, testSpanB, config.Start, config.Start.Add(time.Second)),
				},
			}
		})
		defer stop()
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			config,
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.State != ReportPartial ||
			report.Coverage.Reason != reasonTraceLimit ||
			!report.Coverage.Truncated ||
			report.Coverage.TracesRetained != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("span limit", func(t *testing.T) {
		config := testConfig()
		config.MaxSpans = 1
		serverURL, stop := startSingleProjectServer(t, config.WithDefaults(), func() map[string]any {
			return map[string]any{
				"data": []any{
					wireSpanJSON(testTraceA, testSpanA, config.Start, config.Start.Add(time.Second)),
					wireSpanJSON(testTraceA, testSpanB, config.Start.Add(time.Second), config.Start.Add(2*time.Second)),
				},
			}
		})
		defer stop()
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			config,
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.State != ReportPartial ||
			report.Coverage.Reason != reasonSpanLimit ||
			report.Coverage.SpansFound != 2 ||
			report.Coverage.SpansRetained != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("page limit", func(t *testing.T) {
		config := testConfig()
		config.MaxPages = 1
		serverURL, stop := startSingleProjectServer(t, config.WithDefaults(), func() map[string]any {
			return map[string]any{"data": []any{}}
		})
		defer stop()
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			config,
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.State != ReportPartial ||
			report.Coverage.Reason != reasonPageLimit ||
			report.Coverage.PagesRead != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})
}

func TestFailuresStageCoverageAndArtifactFailureIsFatal(t *testing.T) {
	t.Parallel()
	t.Run("discovery", func(t *testing.T) {
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			testConfig(),
			&fakeRunner{err: errors.New("raw kubectl secret")},
			&fakeForwarder{},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.State != ReportFailed ||
			report.Reason != reasonDiscovery ||
			len(sink.files[CoverageArtifactPath]) == 0 ||
			strings.Contains(string(sink.files[CoverageArtifactPath]), "raw kubectl secret") {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("coverage staging", func(t *testing.T) {
		sink := &fakeSink{fail: CoverageArtifactPath}
		_, err := Collect(
			context.Background(),
			testConfig(),
			&fakeRunner{err: errors.New("discovery")},
			&fakeForwarder{},
			sink,
			redact.New(),
		)
		if !errors.Is(err, ErrArtifactStaging) {
			t.Fatalf("Collect() error = %v", err)
		}
	})

	t.Run("api", func(t *testing.T) {
		serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer stop()
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			testConfig(),
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.Reason != reasonHTTPStatus ||
			report.Diagnostic != "service_unavailable" ||
			len(sink.files[CoverageArtifactPath]) == 0 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("tunnel", func(t *testing.T) {
		sink := &fakeSink{}
		report, err := Collect(
			context.Background(),
			testConfig(),
			&fakeRunner{},
			&fakeForwarder{err: telemetry.ErrForwardStart},
			sink,
			redact.New(),
		)
		if err != nil ||
			report.Reason != reasonForward ||
			len(sink.files[CoverageArtifactPath]) == 0 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		sink := &fakeSink{}
		report, err := Collect(
			ctx,
			testConfig(),
			&fakeRunner{},
			&fakeForwarder{},
			sink,
			redact.New(),
		)
		if !errors.Is(err, context.Canceled) ||
			report.Reason != reasonCanceled ||
			len(sink.files[CoverageArtifactPath]) == 0 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})
}

func TestRetentionBudgetsTruncateAtRecordBoundaries(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	record := Record{
		SchemaVersion:   recordSchemaVersion,
		ContractVersion: ContractVersion,
		Project:         Project{ID: "p"},
		TraceID:         testTraceA,
		Start:           config.Start.Format(time.RFC3339Nano),
		End:             config.Start.Add(2 * time.Second).Format(time.RFC3339Nano),
		Correlation:     "surrounding",
		Spans: []Span{
			{
				SpanID: testSpanA, SpanKind: "CHAIN", StatusCode: "OK",
				Start: config.Start.Format(time.RFC3339Nano), End: config.Start.Add(time.Second).Format(time.RFC3339Nano),
			},
			{
				SpanID: testSpanB, SpanKind: "CHAIN", StatusCode: "OK",
				Attributes: map[string]string{"service.name": strings.Repeat("x", 1000)},
				Start:      config.Start.Add(time.Second).Format(time.RFC3339Nano), End: config.Start.Add(2 * time.Second).Format(time.RFC3339Nano),
			},
		},
	}
	oneSpan := record
	oneSpan.Spans = oneSpan.Spans[:1]
	oneSpanBytes, err := json.Marshal(oneSpan)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxRetainedBytesPerTrace = int64(len(oneSpanBytes) + 1)
	config.MaxTotalRetainedBytes = config.MaxRetainedBytesPerTrace + 4096
	group := &traceGroup{record: record}
	var buffer bytes.Buffer
	coverage := Coverage{}
	retainGroups(&buffer, []*traceGroup{group}, config, &coverage)
	if coverage.Reason != reasonPerTraceBudget ||
		coverage.SpansRetained != 1 ||
		coverage.TracesRetained != 1 ||
		!coverage.Truncated {
		t.Fatalf("coverage = %+v", coverage)
	}

	second := record
	second.TraceID = testTraceB
	second.Spans = second.Spans[:1]
	secondBytes, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxRetainedBytesPerTrace = max(int64(len(oneSpanBytes)+1), int64(len(secondBytes)+1))
	config.MaxTotalRetainedBytes = int64(len(oneSpanBytes) + 1)
	var totalBuffer bytes.Buffer
	coverage = Coverage{}
	retainGroups(
		&totalBuffer,
		[]*traceGroup{{record: oneSpan}, {record: second}},
		config,
		&coverage,
	)
	if coverage.Reason != reasonTotalBudget ||
		coverage.TracesRetained != 1 ||
		!coverage.Truncated {
		t.Fatalf("total coverage = %+v", coverage)
	}
}

func TestAggregationStopsBeforeRetainedMemoryBudget(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	config.MaxRetainedBytesPerTrace = 4 << 10
	config.MaxTotalRetainedBytes = 8 << 10
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case projectsPath:
			writeJSON(t, writer, map[string]any{
				"data": []any{map[string]any{"id": "p", "name": "project"}},
			})
		case "/v1/projects/p/spans":
			span := wireSpanJSON(
				testTraceA,
				testSpanA,
				config.Start.Add(time.Minute),
				config.Start.Add(2*time.Minute),
			)
			span["attributes"] = map[string]any{
				"service.name": strings.Repeat("x", 4<<10),
			}
			writeJSON(t, writer, map[string]any{"data": []any{span}})
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer stop()

	sink := &fakeSink{}
	report, err := Collect(
		context.Background(),
		config,
		&fakeRunner{},
		&fakeForwarder{baseURL: serverURL},
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if report.State != ReportPartial ||
		report.Reason != reasonPerTraceBudget ||
		!report.Coverage.Truncated ||
		report.Coverage.TracesFound != 1 ||
		report.Coverage.TracesRetained != 0 ||
		len(sink.files[TracesArtifactPath]) != 0 {
		t.Fatalf("report=%+v files=%v", report, mapKeys(sink.files))
	}
}

func TestCompatibilityAndCorrelationFixtures(t *testing.T) {
	t.Parallel()
	compatibilityData, err := os.ReadFile("testdata/arize-phoenix-v15.5.1-rest-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var compatibility struct {
		PhoenixTag string `json:"phoenix_tag"`
		Commit     string `json:"commit"`
		APIVersion string `json:"api_version"`
		Service    struct {
			ApprovedLabel map[string]string `json:"approved_label"`
			Port          int               `json:"port"`
		} `json:"service"`
		Endpoints []struct {
			Method      string          `json:"method"`
			Path        string          `json:"path"`
			Query       json.RawMessage `json:"query,omitempty"`
			QueryWindow json.RawMessage `json:"query_window,omitempty"`
			QueryExact  json.RawMessage `json:"query_exact,omitempty"`
			Response    json.RawMessage `json:"response"`
		} `json:"endpoints"`
		CollectorSurface struct {
			LibraryOnly      bool `json:"library_only"`
			CLIFunctionality bool `json:"cli_functionality"`
		} `json:"collector_surface"`
	}
	if err := decodeStrict(compatibilityData, &compatibility); err != nil {
		t.Fatal(err)
	}
	if compatibility.PhoenixTag != "arize-phoenix-v15.5.1" ||
		compatibility.Commit != "a4b65920d4b977ab1f0f948c6bfc7f379b5a0a74" ||
		compatibility.APIVersion != "v1" ||
		compatibility.Service.ApprovedLabel[discoveryLabelKey] != discoveryLabelValue ||
		compatibility.Service.Port != expectedPhoenixPort ||
		len(compatibility.Endpoints) != 2 ||
		compatibility.Endpoints[0].Path != projectsPath ||
		compatibility.CollectorSurface.LibraryOnly ||
		!compatibility.CollectorSurface.CLIFunctionality {
		t.Fatalf("compatibility fixture = %+v", compatibility)
	}

	correlationData, err := os.ReadFile("testdata/correlation-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var correlation struct {
		ProfileVersion string `json:"profile_version"`
		PlatformSource struct {
			ObservedAttribute    string `json:"observed_attribute"`
			RepositoryKeyPresent bool   `json:"repository_key_present"`
		} `json:"platform_source"`
		Phoenix struct {
			RepositoryAvailable  bool     `json:"repository_correlation_available"`
			PullRequestAvailable bool     `json:"pull_request_correlation_available"`
			AvailableAttributes  []string `json:"available_allowlisted_vcs_attributes"`
		} `json:"phoenix_rest_v1_15_5_1"`
		ReleaseGates map[string]struct {
			Gated  bool   `json:"gated"`
			Reason string `json:"reason"`
		} `json:"release_gates"`
	}
	if err := decodeStrict(correlationData, &correlation); err != nil {
		t.Fatal(err)
	}
	if correlation.ProfileVersion != "1" ||
		correlation.PlatformSource.ObservedAttribute != "vcs.repository" ||
		!correlation.PlatformSource.RepositoryKeyPresent ||
		correlation.Phoenix.RepositoryAvailable ||
		correlation.Phoenix.PullRequestAvailable ||
		!reflect.DeepEqual(
			correlation.Phoenix.AvailableAttributes,
			[]string{"vcs.provider", "vcs.event.type"},
		) ||
		!correlation.ReleaseGates["repository_correlation"].Gated ||
		!correlation.ReleaseGates["pull_request_correlation"].Gated {
		t.Fatalf("correlation fixture = %+v", correlation)
	}
}

func testConfig() Config {
	config := DefaultConfig()
	config.Namespace = "observability"
	config.Start = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	config.End = config.Start.Add(time.Hour)
	return config
}

func wireSpanJSON(traceID, spanID string, start, end time.Time) map[string]any {
	return map[string]any{
		"id":   testGlobalSpanID,
		"name": "Alice Smith diagnosis leukemia",
		"context": map[string]any{
			"trace_id": traceID,
			"span_id":  spanID,
		},
		"span_kind":      "CHAIN",
		"parent_id":      nil,
		"start_time":     start.Format(time.RFC3339Nano),
		"end_time":       end.Format(time.RFC3339Nano),
		"status_code":    "OK",
		"status_message": "status raw secret",
		"attributes": map[string]any{
			"service.name":      "token=service-secret",
			"service.version":   "1.2.3",
			"unknown.attribute": "attribute raw secret",
			"prompt":            "prompt raw secret",
			"completion":        "completion raw secret",
			"url":               "http://example.test/path?token=raw",
		},
		"events": []any{
			map[string]any{
				"name":       "event raw secret",
				"attributes": map[string]any{"token": "raw"},
			},
		},
	}
}

func startSingleProjectServer(
	t *testing.T,
	config Config,
	spans func() map[string]any,
) (string, func()) {
	t.Helper()
	return startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case projectsPath:
			writeJSON(t, writer, map[string]any{
				"data": []any{map[string]any{"id": "p", "name": "project"}},
			})
		case "/v1/projects/p/spans":
			if config.TraceID == "" {
				assertWindowSpanQuery(t, request.URL.Query(), config, "")
			}
			writeJSON(t, writer, spans())
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
}

func startIPv4Server(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	return "http://" + listener.Addr().String(), func() {
		_ = server.Close()
		<-done
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func assertProjectQuery(t *testing.T, values url.Values, cursor string) {
	t.Helper()
	keys := []string{"limit", "include_experiment_projects", "include_dataset_evaluator_projects"}
	if cursor != "" {
		keys = append(keys, "cursor")
	}
	if !requestHasOnly(values, keys...) ||
		values.Get("limit") != "100" ||
		values.Get("include_experiment_projects") != "false" ||
		values.Get("include_dataset_evaluator_projects") != "false" ||
		values.Get("cursor") != cursor {
		t.Errorf("project query = %#v", values)
	}
}

func assertWindowSpanQuery(t *testing.T, values url.Values, config Config, cursor string) {
	t.Helper()
	keys := []string{"limit", "start_time", "end_time"}
	if cursor != "" {
		keys = append(keys, "cursor")
	}
	if !requestHasOnly(values, keys...) ||
		values.Get("limit") != "100" ||
		values.Get("start_time") != config.Start.Format(time.RFC3339Nano) ||
		values.Get("end_time") != config.End.Format(time.RFC3339Nano) ||
		values.Get("cursor") != cursor {
		t.Errorf("span query = %#v", values)
	}
}

func decodeJSONLines(t *testing.T, data []byte) []Record {
	t.Helper()
	var records []Record
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
