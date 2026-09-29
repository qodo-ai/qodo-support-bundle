package prometheus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (runner *fakeRunner) Run(
	_ context.Context,
	_ int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	runner.mu.Lock()
	runner.calls = append(runner.calls, append([]string(nil), arguments...))
	runner.mu.Unlock()
	if contains(arguments, "services") {
		return kubernetes.CommandResult{Stdout: []byte(`{
			"apiVersion":"v1","kind":"ServiceList","items":[{
				"metadata":{"name":"prometheus","namespace":"observability","labels":{"app.kubernetes.io/name":"prometheus"}},
				"spec":{"ports":[{"port":9090}]}
			}]
		}`)}, nil
	}
	return kubernetes.CommandResult{Stdout: []byte(`{
		"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSliceList","items":[{
			"metadata":{"name":"prometheus-abcde","namespace":"observability","labels":{"kubernetes.io/service-name":"prometheus"}},
			"endpoints":[{"addresses":["10.0.0.1"],"conditions":{"ready":true}}]
		}]
	}`)}, nil
}

type fakeForwarder struct {
	baseURL string
	ctx     context.Context
	target  telemetry.Target
}

func (forwarder *fakeForwarder) Forward(
	ctx context.Context,
	target telemetry.Target,
) (*telemetry.Tunnel, error) {
	forwarder.ctx = ctx
	forwarder.target = target
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
		return errors.New("sink secret must not escape")
	}
	if sink.files == nil {
		sink.files = make(map[string][]byte)
	}
	sink.files[path] = append([]byte(nil), data...)
	return nil
}

func TestCollectStagesDeterministicRedactedArtifacts(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	catalog := BuiltinCatalog()
	var mu sync.Mutex
	requested := make([]url.Values, 0, len(catalog.Queries))
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodGet || request.URL.Path != queryRangePath {
			t.Errorf("request shape = %s %s", request.Method, request.URL.Path)
		}
		values := request.URL.Query()
		mu.Lock()
		requested = append(requested, values)
		mu.Unlock()
		query := queryByExpression(t, catalog, config, values.Get("query"))
		labels := map[string]string{"unknown": "raw-other-secret"}
		for index, label := range query.RetainLabels {
			labels[label] = fmt.Sprintf("value-%d", index)
		}
		if len(query.RetainLabels) > 0 {
			labels[query.RetainLabels[0]] = "token=raw-label-secret"
		}
		labels["namespace"] = "team-a"
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "matrix",
				"result": []any{map[string]any{
					"metric": labels,
					"values": []any{
						[]any{config.Start.Add(time.Minute).Unix(), "2"},
						[]any{config.Start.Unix(), "1"},
						[]any{config.End.Unix(), "999"},
					},
				}},
			},
		})
	}))
	defer stop()

	runner := &fakeRunner{}
	forwarder := &fakeForwarder{baseURL: serverURL}
	sink := &fakeSink{}
	report, err := Collect(
		context.Background(),
		config,
		runner,
		forwarder,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if report.State != ReportComplete {
		t.Fatalf("report = %+v", report)
	}
	if err := ValidateCompleteCoverage(report); err != nil {
		t.Fatalf("ValidateCompleteCoverage() error = %v", err)
	}
	if forwarder.target != (telemetry.Target{Service: "prometheus", Port: 9090}) {
		t.Fatalf("target = %+v", forwarder.target)
	}
	select {
	case <-forwarder.ctx.Done():
	default:
		t.Fatal("forward context was not canceled during cleanup")
	}
	if len(requested) != len(catalog.Queries) {
		t.Fatalf("requests = %d", len(requested))
	}
	for index, values := range requested {
		query := catalog.Queries[index]
		rendered, err := renderScopedPromQL(query, config)
		if err != nil {
			t.Fatal(err)
		}
		if len(values) != 4 ||
			values.Get("query") != rendered ||
			strings.Contains(values.Get("query"), namespaceRegexToken) ||
			values.Get("start") != config.Start.Format(time.RFC3339Nano) ||
			values.Get("end") != config.End.Format(time.RFC3339Nano) ||
			values.Get("step") != "60" {
			t.Fatalf("request %d = %#v", index, values)
		}
	}
	metrics := string(sink.files[MetricsArtifactPath])
	coverage := string(sink.files[CoverageArtifactPath])
	if metrics == "" || coverage == "" {
		t.Fatalf("staged files = %#v", sink.files)
	}
	var stagedReport Report
	if err := json.Unmarshal([]byte(coverage), &stagedReport); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stagedReport, report) {
		t.Fatalf("staged coverage does not match returned report")
	}
	for _, forbidden := range []string{
		"raw-label-secret",
		"raw-other-secret",
		"unknown",
		"query_range",
		"container_cpu_usage_seconds_total",
		"promql",
		"credentials",
		"warnings",
		namespaceRegexToken,
		"^(?:team-a)$",
	} {
		if strings.Contains(metrics, forbidden) || strings.Contains(coverage, forbidden) {
			t.Fatalf("artifact contains forbidden value %q", forbidden)
		}
	}
	lines := strings.Split(strings.TrimSpace(metrics), "\n")
	if len(lines) != len(catalog.Queries) {
		t.Fatalf("metric records = %d", len(lines))
	}
	previous := ""
	for _, line := range lines {
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.QueryID < previous {
			t.Fatalf("records are not query-id sorted")
		}
		previous = record.QueryID
		if len(record.Samples) != 2 || record.Samples[0].Value != 1 {
			t.Fatalf("samples = %+v", record.Samples)
		}
	}
}

func TestCollectEmptyResultsAreCompleteAndOnlyCoverageIsStaged(t *testing.T) {
	t.Parallel()
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		_, _ = writer.Write([]byte(
			`{"status":"success","data":{"resultType":"matrix","result":[]}}`,
		))
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
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompleteCoverage(report); err != nil {
		t.Fatal(err)
	}
	if _, exists := sink.files[MetricsArtifactPath]; exists {
		t.Fatal("empty metrics artifact was staged")
	}
	if sink.files[CoverageArtifactPath] == nil {
		t.Fatal("coverage artifact was not staged")
	}
	for _, coverage := range report.Coverage {
		if coverage.State != CoverageNoData {
			t.Fatalf("coverage = %+v", coverage)
		}
	}
}

func TestCollectFailsClosedWhenMetricsArtifactCannotBeStaged(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		_, _ = fmt.Fprintf(
			writer,
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"platform"},"values":[[%d,"1"]]}]}}`,
			config.Start.Unix(),
		)
	}))
	defer stop()
	sink := &fakeSink{fail: MetricsArtifactPath}

	report, err := Collect(
		context.Background(),
		config,
		&fakeRunner{},
		&fakeForwarder{baseURL: serverURL},
		sink,
		redact.New(),
	)

	if !errors.Is(err, ErrArtifactStaging) {
		t.Fatalf("Collect() error = %v", err)
	}
	if report.State == ReportComplete ||
		report.Reason != reasonArtifactStaging ||
		report.Diagnostic != "metrics_staging" {
		t.Fatalf("report did not fail closed: %+v", report)
	}
	if coverage := sink.files[CoverageArtifactPath]; len(coverage) == 0 {
		t.Fatal("failure coverage was not staged")
	}
	if err := ValidateCompleteCoverage(report); !errors.Is(err, ErrCoverageInvalid) {
		t.Fatalf("ValidateCompleteCoverage() error = %v", err)
	}
}

func TestCollectPreservesCompletedRecordsOnHTTPFailure(t *testing.T) {
	t.Parallel()
	var count int
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		count++
		switch count {
		case 1:
			_, _ = writer.Write([]byte(fmt.Sprintf(
				`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a","pod":"p","container":"c"},"values":[[%d,"1"]]}]}}`,
				testConfig().Start.Unix(),
			)))
		case 2:
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write([]byte("raw server secret"))
		default:
			_, _ = writer.Write([]byte(
				`{"status":"success","data":{"resultType":"matrix","result":[]}}`,
			))
		}
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
	if err != nil {
		t.Fatal(err)
	}
	if report.State != ReportPartial ||
		report.RetainedRecords != 1 ||
		report.Coverage[1].Reason != reasonHTTPStatus {
		t.Fatalf("report = %+v", report)
	}
	allArtifacts := string(sink.files[MetricsArtifactPath]) +
		string(sink.files[CoverageArtifactPath])
	if strings.Contains(allArtifacts, "raw server secret") {
		t.Fatal("raw HTTP body was staged")
	}
}

func TestCollectCancellationIsReturnedAndCoverageIsStaged(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	serverURL, stop := startIPv4Server(t, http.HandlerFunc(func(
		_ http.ResponseWriter,
		request *http.Request,
	) {
		close(started)
		<-request.Context().Done()
	}))
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	sink := &fakeSink{}
	result := make(chan error, 1)
	go func() {
		_, err := Collect(
			ctx,
			testConfig(),
			&fakeRunner{},
			&fakeForwarder{baseURL: serverURL},
			sink,
			redact.New(),
		)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Collect did not return after cancellation")
	}
	if sink.files[CoverageArtifactPath] == nil {
		t.Fatal("coverage was not staged on cancellation")
	}
}

func TestMaliciousNamespaceCannotReachDiscoveryOrQuery(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Namespaces = []string{`team-a|.*"}`}
	runner := &fakeRunner{}
	sink := &fakeSink{}
	_, err := Collect(
		context.Background(),
		config,
		runner,
		&fakeForwarder{baseURL: "http://127.0.0.1:1"},
		sink,
		redact.New(),
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 0 || len(sink.files) != 0 {
		t.Fatalf("unsafe scope reached collection: calls=%d files=%d", len(runner.calls), len(sink.files))
	}
}

func TestTunnelEndpointRequiresExactIPv4Loopback(t *testing.T) {
	t.Parallel()
	valid, err := validateTunnelEndpoint(
		&telemetry.Tunnel{BaseURL: "http://127.0.0.1:9090"},
	)
	if err != nil || valid.Hostname() != "127.0.0.1" {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
	for _, endpoint := range []string{
		"http://localhost:9090",
		"http://[::1]:9090",
		"https://127.0.0.1:9090",
		"http://127.0.0.1:9090/path",
		"http://user@127.0.0.1:9090",
		"http://127.0.0.2:9090",
	} {
		if _, err := validateTunnelEndpoint(
			&telemetry.Tunnel{BaseURL: endpoint},
		); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestExecuteRangeQueryEnforcesBodyAndIdleLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		handler    http.Handler
		maxBytes   int64
		idle       time.Duration
		wantReason string
	}{
		{
			name: "oversize",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(strings.Repeat("x", 1024)))
			}),
			maxBytes:   100,
			idle:       time.Second,
			wantReason: reasonResponseLimit,
		},
		{
			name: "idle",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				if flusher, ok := writer.(http.Flusher); ok {
					flusher.Flush()
				}
				time.Sleep(100 * time.Millisecond)
				_, _ = writer.Write([]byte(
					`{"status":"success","data":{"resultType":"matrix","result":[]}}`,
				))
			}),
			maxBytes:   1024,
			idle:       20 * time.Millisecond,
			wantReason: reasonIdleTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			serverURL, stop := startIPv4Server(t, test.handler)
			defer stop()
			baseURL, err := url.Parse(serverURL)
			if err != nil {
				t.Fatal(err)
			}
			config := testConfig().WithDefaults()
			config.MaxResponseBytes = test.maxBytes
			config.IdleTimeout = test.idle
			config.RequestTimeout = time.Second
			result := executeRangeQuery(
				context.Background(),
				newHTTPClient(config),
				baseURL,
				BuiltinCatalog().Queries[0],
				config,
			)
			if result.reason != test.wantReason {
				t.Fatalf("reason = %q, want %q", result.reason, test.wantReason)
			}
		})
	}
}

func TestOpenTunnelEnforcesReadinessDeadline(t *testing.T) {
	t.Parallel()
	forwarder := blockingForwarder{}
	start := time.Now()
	tunnel, cancel, err := openTunnel(
		context.Background(),
		20*time.Millisecond,
		forwarder,
		telemetry.Target{Service: "prometheus", Port: 9090},
	)
	cancel()
	if tunnel != nil || !errors.Is(err, telemetry.ErrForwardTimeout) {
		t.Fatalf("tunnel=%v error=%v", tunnel, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("readiness deadline was not enforced")
	}
}

func TestRetainedByteBudgetsTruncateDeterministically(t *testing.T) {
	t.Parallel()
	record := Record{
		SchemaVersion: "1",
		QueryID:       "q",
		Category:      "request_rate",
		Labels:        map[string]string{"namespace": "a"},
	}
	for index := 0; index < 100; index++ {
		record.Samples = append(record.Samples, Sample{
			Timestamp: testConfig().Start.Add(time.Duration(index) * time.Second).
				Format(time.RFC3339Nano),
			Value: float64(index),
		})
	}
	data, samples, truncated := marshalRecordWithin(record, 512)
	if len(data) == 0 || samples <= 0 || samples >= len(record.Samples) || !truncated {
		t.Fatalf("budget result: bytes=%d samples=%d truncated=%t", len(data), samples, truncated)
	}
	again, againSamples, _ := marshalRecordWithin(record, 512)
	if !reflect.DeepEqual(data, again) || samples != againSamples {
		t.Fatal("budget truncation is nondeterministic")
	}

	oneSampleRecord := record
	oneSampleRecord.Samples = record.Samples[:1]
	oneSample, err := json.Marshal(oneSampleRecord)
	if err != nil {
		t.Fatal(err)
	}
	minimumBudget := int64(len(oneSample) + 1)
	tests := []struct {
		name           string
		perQuery       int64
		total          int64
		expectedReason string
	}{
		{
			name:           "per query",
			perQuery:       minimumBudget,
			total:          1 << 20,
			expectedReason: reasonPerQueryBudget,
		},
		{
			name:           "total",
			perQuery:       1 << 20,
			total:          minimumBudget,
			expectedReason: reasonTotalBudget,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var metrics bytes.Buffer
			coverage := Coverage{}
			total := test.total
			retainNormalized(
				&metrics,
				&coverage,
				normalizedQuery{records: []Record{record}, seriesFound: 1, samplesFound: 100},
				test.perQuery,
				&total,
			)
			if coverage.State != CoveragePartial ||
				coverage.Reason != test.expectedReason ||
				!coverage.Truncated {
				t.Fatalf("coverage = %+v", coverage)
			}
		})
	}
}

type blockingForwarder struct{}

func (blockingForwarder) Forward(
	ctx context.Context,
	_ telemetry.Target,
) (*telemetry.Tunnel, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func startIPv4Server(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	return "http://" + listener.Addr().String(), func() {
		_ = server.Close()
		_ = listener.Close()
	}
}

func queryByExpression(
	t *testing.T,
	catalog Catalog,
	config Config,
	expression string,
) Query {
	t.Helper()
	for _, query := range catalog.Queries {
		rendered, err := renderScopedPromQL(query, config)
		if err != nil {
			t.Fatal(err)
		}
		if rendered == expression {
			return query
		}
	}
	t.Fatalf("unknown expression %q", expression)
	return Query{}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
