package workload

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

type collectorCall struct {
	limit     int64
	arguments []string
}

type collectorRunner struct {
	calls []collectorCall
	run   func(context.Context, int64, []string) (kubernetes.CommandResult, error)
}

func (runner *collectorRunner) Run(
	ctx context.Context,
	limit int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	copied := append([]string(nil), arguments...)
	runner.calls = append(runner.calls, collectorCall{limit: limit, arguments: copied})
	return runner.run(ctx, limit, copied)
}

type collectorSink struct {
	files map[string][]byte
	adds  int
}

func (sink *collectorSink) Add(path string, data []byte) error {
	if sink.files == nil {
		sink.files = make(map[string][]byte)
	}
	if _, duplicate := sink.files[path]; duplicate {
		return fmt.Errorf("duplicate path %q", path)
	}
	sink.files[path] = append([]byte(nil), data...)
	sink.adds++
	return nil
}

type positionedFailSink struct {
	failAt   int
	attempts int
	files    map[string][]byte
}

func (sink *positionedFailSink) Add(path string, data []byte) error {
	sink.attempts++
	if sink.attempts == sink.failAt {
		return errors.New("password=raw-staging-secret")
	}
	if sink.files == nil {
		sink.files = make(map[string][]byte)
	}
	sink.files[path] = append([]byte(nil), data...)
	return nil
}

func testCollectorConfig(namespaces ...string) Config {
	return Config{
		Namespaces:       namespaces,
		Context:          "test-context",
		Kubeconfig:       "/tmp/test-kubeconfig",
		Timeout:          time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
		MaxSourceBytes:   DefaultMaxSourceBytes,
		MaxTotalBytes:    DefaultMaxTotalBytes,
	}
}

func TestCollectUsesExactNamespaceScopedAPIRequestsAndDeterministicArtifacts(t *testing.T) {
	t.Parallel()

	collect := func(namespaces []string) (Report, *collectorRunner, *collectorSink) {
		runner := &collectorRunner{
			run: func(
				_ context.Context,
				_ int64,
				arguments []string,
			) (kubernetes.CommandResult, error) {
				apiPath := arguments[len(arguments)-1]
				namespace := namespaceFromAPIPath(t, apiPath)
				return kubernetes.CommandResult{
					Stdout: []byte(responseForAPIPath(t, apiPath, namespace, false)),
				}, nil
			},
		}
		sink := &collectorSink{}
		report, err := Collect(
			context.Background(),
			testCollectorConfig(namespaces...),
			runner,
			sink,
			redact.New(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return report, runner, sink
	}

	firstReport, firstRunner, firstSink := collect([]string{"zeta", "alpha", "alpha"})
	secondReport, _, secondSink := collect([]string{"alpha", "zeta"})

	if !reflect.DeepEqual(firstReport, secondReport) {
		t.Fatalf("reports are not deterministic:\nfirst=%+v\nsecond=%+v", firstReport, secondReport)
	}
	if !reflect.DeepEqual(firstSink.files, secondSink.files) {
		t.Fatal("artifacts changed with namespace request order")
	}
	if !reflect.DeepEqual(firstReport.Namespaces, []string{"alpha", "zeta"}) {
		t.Fatalf("unexpected normalized namespaces: %v", firstReport.Namespaces)
	}
	if len(firstRunner.calls) != 18 || len(firstReport.Coverage) != 18 {
		t.Fatalf("calls=%d coverage=%d", len(firstRunner.calls), len(firstReport.Coverage))
	}

	var expected []string
	for _, namespace := range []string{"alpha", "zeta"} {
		for _, apiPath := range expectedAPIPaths(namespace) {
			expected = append(expected, strings.Join([]string{
				"--kubeconfig", "/tmp/test-kubeconfig",
				"--context", "test-context",
				"get", "--raw", apiPath,
			}, " "))
		}
	}
	for index, call := range firstRunner.calls {
		if call.limit != DefaultMaxResponseBytes {
			t.Fatalf("call %d byte limit=%d", index, call.limit)
		}
		if actual := strings.Join(call.arguments, " "); actual != expected[index] {
			t.Fatalf("call %d:\ngot  %s\nwant %s", index, actual, expected[index])
		}
		if firstReport.Coverage[index].State != CoverageCollected {
			t.Fatalf("coverage %d was not collected: %+v", index, firstReport.Coverage[index])
		}
	}

	wantArtifacts := map[string]int{
		WorkloadsArtifactPath:   10,
		ServicesArtifactPath:    4,
		AutoscalersArtifactPath: 2,
		StorageArtifactPath:     2,
	}
	if len(firstSink.files) != len(wantArtifacts) {
		t.Fatalf("staged paths=%v", sortedMapKeys(firstSink.files))
	}
	for artifactPath, records := range wantArtifacts {
		data, exists := firstSink.files[artifactPath]
		if !exists {
			t.Errorf("missing artifact %q", artifactPath)
			continue
		}
		if count := strings.Count(string(data), "\n"); count != records {
			t.Errorf("%s record count=%d, want %d", artifactPath, count, records)
		}
	}

	allArtifacts := ""
	for _, data := range firstSink.files {
		allArtifacts += string(data)
	}
	for _, forbidden := range []string{
		"raw-secret-value",
		"raw-annotation-value",
		"10.20.30.40",
		`"annotations"`,
		`"addresses"`,
		`"env"`,
		`"command"`,
		`"clusterIP"`,
	} {
		if strings.Contains(allArtifacts, forbidden) {
			t.Fatalf("normalized artifacts retained forbidden value %q", forbidden)
		}
	}
	for _, call := range firstRunner.calls {
		joined := strings.Join(call.arguments, " ")
		if strings.Contains(joined, "secrets") || strings.Contains(joined, "configmaps") {
			t.Fatalf("collector requested forbidden resource: %s", joined)
		}
	}
}

func TestCollectEnforcesResponseLimitBeforeParsingAndContinues(t *testing.T) {
	t.Parallel()

	runner := &collectorRunner{
		run: func(
			_ context.Context,
			limit int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			return kubernetes.CommandResult{
				Stdout:    []byte(`{"kind":`),
				Truncated: true,
			}, nil
		},
	}
	sink := &collectorSink{}
	config := testCollectorConfig("platform")
	config.MaxResponseBytes = 17

	report, err := Collect(context.Background(), config, runner, sink, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 9 || sink.adds != 0 {
		t.Fatalf("calls=%d staged=%d", len(runner.calls), sink.adds)
	}
	for _, call := range runner.calls {
		if call.limit != 17 {
			t.Fatalf("runner limit=%d, want 17", call.limit)
		}
	}
	for _, coverage := range report.Coverage {
		if coverage.State != CoverageFailed ||
			coverage.Reason != reasonResponseLimit ||
			!coverage.Truncated {
			t.Fatalf("unexpected response-limit coverage: %+v", coverage)
		}
	}
}

func TestCollectReportsPartialFailuresAndContinuation(t *testing.T) {
	t.Parallel()

	runner := &collectorRunner{
		run: func(
			_ context.Context,
			_ int64,
			arguments []string,
		) (kubernetes.CommandResult, error) {
			apiPath := arguments[len(arguments)-1]
			switch {
			case strings.Contains(apiPath, "/deployments?"):
				return kubernetes.CommandResult{
					Stderr: []byte("password=raw-secret-value\naccess denied"),
				}, errors.New("request failed")
			case strings.Contains(apiPath, "/services?"):
				return kubernetes.CommandResult{Stdout: []byte(`not-json`)}, nil
			default:
				return kubernetes.CommandResult{
					Stdout: []byte(responseForAPIPath(t, apiPath, "platform", false)),
				}, nil
			}
		},
	}
	sink := &collectorSink{}

	report, err := Collect(
		context.Background(),
		testCollectorConfig("platform"),
		runner,
		sink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 9 {
		t.Fatalf("source-local failures stopped collection after %d calls", len(runner.calls))
	}
	if report.Coverage[0].State != CoverageFailed ||
		report.Coverage[0].Reason != reasonRequestFailed ||
		report.Coverage[0].Diagnostic != "access forbidden" ||
		report.Coverage[5].State != CoverageFailed ||
		report.Coverage[5].Reason != reasonNormalizationFailed {
		t.Fatalf("unexpected failure coverage: %+v", report.Coverage)
	}
	if report.Coverage[8].State != CoverageCollected {
		t.Fatalf("later independent source was not collected: %+v", report.Coverage[8])
	}
	artifacts := ""
	for _, data := range sink.files {
		artifacts += string(data)
	}
	if strings.Contains(artifacts, "raw-secret-value") {
		t.Fatal("runner error text entered a staged artifact")
	}

	continuationRunner := &collectorRunner{
		run: func(
			_ context.Context,
			_ int64,
			arguments []string,
		) (kubernetes.CommandResult, error) {
			apiPath := arguments[len(arguments)-1]
			return kubernetes.CommandResult{
				Stdout: []byte(responseForAPIPath(
					t,
					apiPath,
					"platform",
					strings.Contains(apiPath, "/deployments?"),
				)),
			}, nil
		},
	}
	continued, err := Collect(
		context.Background(),
		testCollectorConfig("platform"),
		continuationRunner,
		&collectorSink{},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if continued.Coverage[0].State != CoveragePartial ||
		continued.Coverage[0].Reason != reasonRecordLimit ||
		!continued.Coverage[0].Truncated {
		t.Fatalf("list continuation was not reported: %+v", continued.Coverage[0])
	}
}

func TestRequestDiagnosticClassifiesFailuresWithoutRetainingIdentities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result kubernetes.CommandResult
		err    error
		want   string
	}{
		{
			name: "malformed forbidden stderr",
			result: kubernetes.CommandResult{
				Stderr: []byte("\xffUser \"Jane Doe\" cannot list deployments: Forbidden"),
			},
			err:  errors.New("fallback must not be used"),
			want: "access forbidden",
		},
		{
			name: "timeout fallback",
			err:  errors.New("context deadline exceeded"),
			want: "request timed out",
		},
		{
			name: "unknown failure",
			result: kubernetes.CommandResult{
				Stderr: []byte("User \"Jane Doe\" encountered an unusual failure"),
			},
			err:  errors.New("fallback must not be used"),
			want: "request failed",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := requestDiagnostic(test.result, test.err); got != test.want ||
				strings.Contains(got, "Jane Doe") {
				t.Fatalf("requestDiagnostic() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCollectEnforcesExactSourceAndTotalArtifactBudgets(t *testing.T) {
	t.Parallel()

	deploymentPath := expectedAPIPaths("aa")[0]
	records, _, _, err := sourceSpecs()[0].normalize(
		[]byte(responseForAPIPath(t, deploymentPath, "aa", false)),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	deploymentBytes := int64(len(records[0].data))

	totalConfig := testCollectorConfig("aa")
	totalConfig.MaxSourceBytes = deploymentBytes
	totalConfig.MaxTotalBytes = deploymentBytes
	totalRunner := successfulCollectorRunner(t)
	totalSink := &collectorSink{}
	totalReport, err := Collect(
		context.Background(),
		totalConfig,
		totalRunner,
		totalSink,
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(totalRunner.calls) != 1 ||
		totalReport.RetainedBytes != deploymentBytes ||
		totalReport.RetainedRecords != 1 {
		t.Fatalf("exact total boundary was not retained: %+v calls=%d", totalReport, len(totalRunner.calls))
	}
	if totalReport.Coverage[0].State != CoverageCollected ||
		totalReport.Coverage[1].State != CoverageSkipped ||
		totalReport.Coverage[1].Reason != reasonTotalBudgetExhausted {
		t.Fatalf("unexpected total-budget coverage: %+v", totalReport.Coverage)
	}

	sourceConfig := testCollectorConfig("bb", "aa")
	sourceConfig.MaxSourceBytes = deploymentBytes
	sourceConfig.MaxTotalBytes = MaximumTotalBytes
	sourceReport, err := Collect(
		context.Background(),
		sourceConfig,
		successfulCollectorRunner(t),
		&collectorSink{},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondNamespaceDeployment := sourceReport.Coverage[9]
	if secondNamespaceDeployment.Namespace != "bb" ||
		secondNamespaceDeployment.Source != "deployments" ||
		secondNamespaceDeployment.State != CoverageSkipped ||
		secondNamespaceDeployment.Reason != reasonSourceBudgetExhausted {
		t.Fatalf("unexpected source-budget coverage: %+v", secondNamespaceDeployment)
	}
}

func TestCollectRejectsUnsafeNamespacesAndDuplicateStagingPaths(t *testing.T) {
	t.Parallel()

	for _, namespace := range []string{"../other", "a/b", "UPPER", "a?x=y", ".hidden", "trailing-"} {
		runner := successfulCollectorRunner(t)
		_, err := Collect(
			context.Background(),
			testCollectorConfig(namespace),
			runner,
			&collectorSink{},
			redact.New(),
		)
		if err == nil || len(runner.calls) != 0 {
			t.Fatalf("namespace %q was not rejected before collection: %v", namespace, err)
		}
	}
	for _, artifactPath := range []string{
		"../workloads.jsonl",
		"/kubernetes/workloads.jsonl",
		`kubernetes\workloads.jsonl`,
		"kubernetes/../workloads.jsonl",
		"other/workloads.jsonl",
	} {
		if err := validateArtifactPath(artifactPath); err == nil {
			t.Errorf("unsafe artifact path %q was accepted", artifactPath)
		}
	}
}

func TestCollectReconcilesArtifactStagingFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		failAt              int
		wantArtifacts       int
		wantRetainedRecords int
		wantPreserved       int
	}{
		{
			name:          "first artifact",
			failAt:        1,
			wantArtifacts: 0,
		},
		{
			name:                "later artifact",
			failAt:              2,
			wantArtifacts:       1,
			wantRetainedRecords: 5,
			wantPreserved:       5,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sink := &positionedFailSink{failAt: test.failAt}
			report, err := Collect(
				context.Background(),
				testCollectorConfig("platform"),
				successfulCollectorRunner(t),
				sink,
				redact.New(),
			)
			if err == nil {
				t.Fatal("expected staging failure")
			}
			if len(report.Artifacts) != test.wantArtifacts ||
				report.RetainedRecords != test.wantRetainedRecords {
				t.Fatalf("staging failure claims unstaged artifacts: %+v", report)
			}
			retainedBytes := int64(0)
			preserved := 0
			unstaged := 0
			for _, coverage := range report.Coverage {
				retainedBytes += coverage.RetainedBytes
				if coverage.RecordsRetained > 0 {
					preserved += coverage.RecordsRetained
					if coverage.State != CoverageCollected ||
						coverage.Truncated ||
						coverage.Reason != "" {
						t.Fatalf("staged coverage was changed: %+v", coverage)
					}
					continue
				}
				if coverage.RecordsFound > 0 {
					unstaged++
					if coverage.State != CoveragePartial ||
						!coverage.Truncated ||
						coverage.Reason != reasonArtifactStaging {
						t.Fatalf("unstaged coverage was not reconciled: %+v", coverage)
					}
				}
			}
			if preserved != test.wantPreserved ||
				report.RetainedBytes != retainedBytes ||
				unstaged != 9-test.wantPreserved ||
				!report.Truncated {
				t.Fatalf("inaccurate reconciled report: %+v", report)
			}
			if strings.Contains(fmt.Sprint(report), "raw-staging-secret") {
				t.Fatalf("report retained sink failure text: %+v", report)
			}
		})
	}
}

func TestCollectCancellationIsFatalAndStagesNothing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	runner := &collectorRunner{
		run: func(
			_ context.Context,
			_ int64,
			_ []string,
		) (kubernetes.CommandResult, error) {
			cancel()
			return kubernetes.CommandResult{}, context.Canceled
		},
	}
	sink := &collectorSink{}

	_, err := Collect(ctx, testCollectorConfig("platform"), runner, sink, redact.New())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if sink.adds != 0 {
		t.Fatalf("canceled collection staged %d artifacts", sink.adds)
	}
}

func TestValidateCompleteCoverageFailsClosed(t *testing.T) {
	t.Parallel()
	valid := completeEmptyWorkloadReport("alpha", "beta")
	if err := ValidateCompleteCoverage(valid); err != nil {
		t.Fatalf("valid empty-resource coverage was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{
			name: "missing pair",
			mutate: func(report *Report) {
				report.Coverage = report.Coverage[:len(report.Coverage)-1]
			},
		},
		{
			name: "duplicate pair",
			mutate: func(report *Report) {
				report.Coverage[len(report.Coverage)-1] = report.Coverage[0]
			},
		},
		{
			name: "unknown namespace",
			mutate: func(report *Report) {
				report.Coverage[0].Namespace = "unknown"
			},
		},
		{
			name: "unknown source",
			mutate: func(report *Report) {
				report.Coverage[0].Source = "secrets"
			},
		},
		{
			name: "partial pair",
			mutate: func(report *Report) {
				report.Coverage[0].State = CoveragePartial
			},
		},
		{
			name: "truncated pair",
			mutate: func(report *Report) {
				report.Coverage[0].Truncated = true
			},
		},
		{
			name: "reason on collected pair",
			mutate: func(report *Report) {
				report.Coverage[0].Reason = reasonRecordLimit
			},
		},
		{
			name: "wrong artifact family",
			mutate: func(report *Report) {
				report.Coverage[0].ArtifactPath = ServicesArtifactPath
			},
		},
		{
			name: "collected pair did not retain every found record",
			mutate: func(report *Report) {
				report.Coverage[0].RecordsFound = 1
			},
		},
		{
			name: "aggregate retained records disagree with coverage",
			mutate: func(report *Report) {
				report.RetainedRecords = 1
			},
		},
		{
			name: "aggregate retained bytes disagree with coverage",
			mutate: func(report *Report) {
				report.RetainedBytes = 1
			},
		},
		{
			name: "empty pair claims retained bytes",
			mutate: func(report *Report) {
				report.Coverage[0].RetainedBytes = 1
				report.RetainedBytes = 1
			},
		},
		{
			name: "report truncated",
			mutate: func(report *Report) {
				report.Truncated = true
			},
		},
		{
			name: "duplicate expected namespace",
			mutate: func(report *Report) {
				report.Namespaces[1] = report.Namespaces[0]
			},
		},
		{
			name: "no namespace",
			mutate: func(report *Report) {
				report.Namespaces = nil
				report.Coverage = nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := completeEmptyWorkloadReport("alpha", "beta")
			test.mutate(&report)
			if err := ValidateCompleteCoverage(report); err == nil {
				t.Fatal("incomplete workload coverage was accepted")
			}
		})
	}
}

func successfulCollectorRunner(t *testing.T) *collectorRunner {
	t.Helper()
	return &collectorRunner{
		run: func(
			_ context.Context,
			_ int64,
			arguments []string,
		) (kubernetes.CommandResult, error) {
			apiPath := arguments[len(arguments)-1]
			namespace := namespaceFromAPIPath(t, apiPath)
			return kubernetes.CommandResult{
				Stdout: []byte(responseForAPIPath(t, apiPath, namespace, false)),
			}, nil
		},
	}
}

func completeEmptyWorkloadReport(namespaces ...string) Report {
	report := Report{Namespaces: append([]string(nil), namespaces...)}
	for _, namespace := range namespaces {
		for _, spec := range sourceSpecs() {
			report.Coverage = append(report.Coverage, Coverage{
				Namespace:    namespace,
				Source:       spec.name,
				State:        CoverageCollected,
				ArtifactPath: spec.artifactPath,
			})
		}
	}
	return report
}

func expectedAPIPaths(namespace string) []string {
	return []string{
		"/apis/apps/v1/namespaces/" + namespace + "/deployments?limit=101",
		"/apis/apps/v1/namespaces/" + namespace + "/statefulsets?limit=101",
		"/apis/apps/v1/namespaces/" + namespace + "/daemonsets?limit=101",
		"/apis/batch/v1/namespaces/" + namespace + "/jobs?limit=101",
		"/apis/batch/v1/namespaces/" + namespace + "/cronjobs?limit=101",
		"/api/v1/namespaces/" + namespace + "/services?limit=101",
		"/apis/discovery.k8s.io/v1/namespaces/" + namespace + "/endpointslices?limit=101",
		"/apis/autoscaling/v2/namespaces/" + namespace + "/horizontalpodautoscalers?limit=101",
		"/api/v1/namespaces/" + namespace + "/persistentvolumeclaims?limit=101",
	}
}

func namespaceFromAPIPath(t *testing.T, apiPath string) string {
	t.Helper()
	const marker = "/namespaces/"
	start := strings.Index(apiPath, marker)
	if start < 0 {
		t.Fatalf("API path is not namespaced: %s", apiPath)
	}
	remainder := apiPath[start+len(marker):]
	end := strings.IndexByte(remainder, '/')
	if end < 1 {
		t.Fatalf("API path has no namespace: %s", apiPath)
	}
	return remainder[:end]
}

func responseForAPIPath(
	t *testing.T,
	apiPath string,
	namespace string,
	continued bool,
) string {
	t.Helper()
	metadata := ""
	if continued {
		metadata = `"metadata":{"continue":"next-page"},`
	}
	objectMetadata := fmt.Sprintf(
		`"metadata":{"name":"record","namespace":%q,"labels":{"app":"api","forbidden-label":"raw-secret-value"},"annotations":{"unsafe":"raw-annotation-value"}}`,
		namespace,
	)
	podTemplate := `"template":{"spec":{"serviceAccountName":"default","containers":[{"name":"api","image":"registry/api:1","env":[{"name":"TOKEN","value":"raw-secret-value"}],"command":["raw-secret-value"]}]}}`

	switch {
	case strings.Contains(apiPath, "/deployments?"):
		return fmt.Sprintf(
			`{"kind":"DeploymentList",%s"items":[{"kind":"Deployment",%s,"spec":{%s},"status":{}}]}`,
			metadata,
			objectMetadata,
			podTemplate,
		)
	case strings.Contains(apiPath, "/statefulsets?"):
		return fmt.Sprintf(
			`{"kind":"StatefulSetList",%s"items":[{"kind":"StatefulSet",%s,"spec":{%s},"status":{}}]}`,
			metadata,
			objectMetadata,
			podTemplate,
		)
	case strings.Contains(apiPath, "/daemonsets?"):
		return fmt.Sprintf(
			`{"kind":"DaemonSetList",%s"items":[{"kind":"DaemonSet",%s,"spec":{%s},"status":{}}]}`,
			metadata,
			objectMetadata,
			podTemplate,
		)
	case strings.Contains(apiPath, "/cronjobs?"):
		return fmt.Sprintf(
			`{"kind":"CronJobList",%s"items":[{"kind":"CronJob",%s,"spec":{"jobTemplate":{"spec":{%s}}},"status":{}}]}`,
			metadata,
			objectMetadata,
			podTemplate,
		)
	case strings.Contains(apiPath, "/jobs?"):
		return fmt.Sprintf(
			`{"kind":"JobList",%s"items":[{"kind":"Job",%s,"spec":{%s},"status":{}}]}`,
			metadata,
			objectMetadata,
			podTemplate,
		)
	case strings.Contains(apiPath, "/services?"):
		return fmt.Sprintf(
			`{"kind":"ServiceList",%s"items":[{"kind":"Service",%s,"spec":{"type":"ClusterIP","selector":{"app":"api"},"ports":[{"port":80}],"clusterIP":"10.20.30.40"}}]}`,
			metadata,
			objectMetadata,
		)
	case strings.Contains(apiPath, "/endpointslices?"):
		return fmt.Sprintf(
			`{"kind":"EndpointSliceList",%s"items":[{"kind":"EndpointSlice",%s,"addressType":"IPv4","endpoints":[{"addresses":["10.20.30.40"],"conditions":{"ready":true}}]}]}`,
			metadata,
			objectMetadata,
		)
	case strings.Contains(apiPath, "/horizontalpodautoscalers?"):
		return fmt.Sprintf(
			`{"kind":"HorizontalPodAutoscalerList",%s"items":[{"kind":"HorizontalPodAutoscaler",%s,"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api"},"minReplicas":1,"maxReplicas":5},"status":{"currentReplicas":2,"desiredReplicas":3}}]}`,
			metadata,
			objectMetadata,
		)
	case strings.Contains(apiPath, "/persistentvolumeclaims?"):
		return fmt.Sprintf(
			`{"kind":"PersistentVolumeClaimList",%s"items":[{"kind":"PersistentVolumeClaim",%s,"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}},"storageClassName":"standard"},"status":{"phase":"Bound","capacity":{"storage":"1Gi"}}}]}`,
			metadata,
			objectMetadata,
		)
	default:
		t.Fatalf("unexpected API path: %s", apiPath)
		return ""
	}
}

func sortedMapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
