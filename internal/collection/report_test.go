package collection

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/workload"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

func TestBuildCustomerContextTrimsRedactsAndOmitsEmpty(t *testing.T) {
	t.Parallel()

	got := BuildCustomerContext(
		"  deploying password=secret  ",
		" user@example.com ",
		redact.New(),
	)
	want := map[string]string{
		"activity": "deploying password=[REDACTED]",
		"problem":  "[REDACTED]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildCustomerContext() = %#v, want %#v", got, want)
	}

	empty := BuildCustomerContext(" \t ", "\n", redact.New())
	if len(empty) != 0 {
		t.Fatalf("BuildCustomerContext() retained empty values: %#v", empty)
	}
}

func TestBuildConnectivityMetadata(t *testing.T) {
	t.Parallel()

	failedReport := &zitadel.Report{
		SchemaVersion: 1,
		Checks: []zitadel.Check{{
			Name:   "discovery",
			Status: zitadel.StatusFailed,
			Reason: zitadel.ReasonTimeout,
		}},
	}
	tests := []struct {
		name    string
		enabled bool
		outcome zitadel.Outcome
		want    map[string]any
	}{
		{
			name: "disabled has exact minimal shape",
			want: map[string]any{"enabled": false},
		},
		{
			name:    "diagnostic failure is complete",
			enabled: true,
			outcome: zitadel.Outcome{Report: failedReport},
			want: map[string]any{
				"enabled":           true,
				"namespace":         "platform",
				"pod":               "platform-0",
				"container":         "app",
				"probe_timeout":     "15s",
				"collection_status": "complete",
				"failed_checks":     1,
			},
		},
		{
			name:    "collection reason is partial",
			enabled: true,
			outcome: zitadel.Outcome{Reason: zitadel.ReasonExecTimeout},
			want: map[string]any{
				"enabled":           true,
				"namespace":         "platform",
				"pod":               "platform-0",
				"container":         "app",
				"probe_timeout":     "15s",
				"collection_status": "partial",
				"reason":            zitadel.ReasonExecTimeout,
			},
		},
		{
			name:    "missing outcome fails conservatively",
			enabled: true,
			want: map[string]any{
				"enabled":           true,
				"namespace":         "platform",
				"pod":               "platform-0",
				"container":         "app",
				"probe_timeout":     "15s",
				"collection_status": "partial",
				"reason":            "missing_report",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := BuildConnectivityMetadata(
				test.enabled,
				"platform",
				"platform-0",
				"app",
				15*time.Second,
				test.outcome,
				redact.New(),
			)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("BuildConnectivityMetadata() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestBuildCollectionManifestExactShape(t *testing.T) {
	t.Parallel()

	report := kubernetes.Report{
		Namespaces:          []string{"discovered-a", "discovered-b"},
		NamespacesRequested: 2,
		Pods:                3,
	}
	connectivity := map[string]any{"enabled": false}
	tests := []struct {
		name          string
		selected      []string
		allNamespaces bool
		wantNamespace string
		wantList      []string
	}{
		{
			name:          "explicit namespaces",
			selected:      []string{"team-a", "team-b"},
			wantNamespace: "team-a,team-b",
			wantList:      []string{"team-a", "team-b"},
		},
		{
			name:          "all namespaces",
			selected:      nil,
			allNamespaces: true,
			wantNamespace: "*",
			wantList:      []string{"discovered-a", "discovered-b"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := BuildCollectionManifest(
				"complete",
				test.selected,
				test.allNamespaces,
				true,
				"app=qodo",
				30*time.Minute,
				1024,
				report,
				connectivity,
				redact.New(),
			)
			want := map[string]any{
				"status":                    "complete",
				"namespace":                 test.wantNamespace,
				"namespaces":                test.wantList,
				"all_namespaces":            test.allNamespaces,
				"exclude_system_namespaces": true,
				"selector":                  "app=qodo",
				"since":                     "30m0s",
				"max_metadata_bytes":        int64(1024),
				"kubernetes":                report,
				"connectivity":              connectivity,
				"coverage":                  InitializeCoverage(nil),
				"prometheus":                map[string]any{"enabled": false},
				"phoenix":                   map[string]any{"enabled": false},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("BuildCollectionManifest() = %#v, want %#v", got, want)
			}
			if _, exists := got["coverages"]; exists {
				t.Fatal("manifest collection unexpectedly contains coverages")
			}
			if len(got) != len(want) {
				t.Fatalf("manifest collection has shape drift: keys=%v", got)
			}
		})
	}
}

func TestBuildSummaryPreservesStatusAndDiagnosticLines(t *testing.T) {
	t.Parallel()

	generatedAt := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		status string
		report *zitadel.Report
		reason string
		lines  []string
	}{
		{
			name:   "complete diagnostic evidence",
			status: "complete",
			report: &zitadel.Report{Checks: []zitadel.Check{{
				Name:   "discovery",
				Status: zitadel.StatusFailed,
				Reason: zitadel.ReasonHTTPError,
			}}},
			lines: []string{
				"- Collection status: complete",
				"- Probe collection: complete",
				"- discovery: failed (http_error)",
				"- Login and token issuance were not tested.",
			},
		},
		{
			name:   "partial unavailable probe",
			status: "partial",
			reason: zitadel.ReasonExecTimeout,
			lines: []string{
				"- Collection status: partial",
				"- Probe collection: unavailable (exec_timeout)",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := BuildSummary(
				generatedAt,
				test.status,
				kubernetes.Report{},
				map[string]string{"activity": "deploying"},
				true,
				test.report,
				test.reason,
			)
			for _, line := range test.lines {
				if !strings.Contains(got, line) {
					t.Errorf("BuildSummary() missing %q:\n%s", line, got)
				}
			}
		})
	}
}

func TestMarshalIssues(t *testing.T) {
	t.Parallel()

	empty, err := MarshalIssues(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty != nil {
		t.Fatalf("MarshalIssues(nil) = %q, want nil", empty)
	}

	issues := []kubernetes.Issue{
		{Operation: "list pods", Message: "safe <detail>"},
		{Operation: "read logs", Resource: "ns/pod", Message: "[REDACTED]"},
	}
	got, err := MarshalIssues(issues)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"operation\":\"list pods\",\"message\":\"safe <detail>\"}\n" +
		"{\"operation\":\"read logs\",\"resource\":\"ns/pod\",\"message\":\"[REDACTED]\"}\n"
	if string(got) != want {
		t.Fatalf("MarshalIssues() = %q, want %q", got, want)
	}
}

func TestMarshalWorkloadReportRedactsCoverageLedger(t *testing.T) {
	t.Parallel()
	const secret = "raw-report-secret"
	report := workload.Report{
		Namespaces: []string{"user@example.com"},
		Coverage: []workload.Coverage{{
			Namespace:       "user@example.com",
			Source:          "deployments",
			State:           workload.CoverageFailed,
			ArtifactPath:    workload.WorkloadsArtifactPath,
			ResponseBytes:   100,
			RecordsFound:    2,
			RecordsRetained: 1,
			RetainedBytes:   20,
			Reason:          "request_failed",
			Diagnostic:      "password=" + secret + "\naccess denied",
		}},
		MaxResponseBytes: 1000,
		MaxSourceBytes:   500,
		MaxTotalBytes:    2000,
		RetainedRecords:  1,
		RetainedBytes:    20,
		Truncated:        true,
	}
	data, err := MarshalWorkloadReport(report, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) ||
		strings.Contains(string(data), "user@example.com") {
		t.Fatalf("workload coverage leaked sensitive data: %s", data)
	}
	var decoded workload.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Coverage) != 1 ||
		decoded.Coverage[0].Namespace != redact.Replacement ||
		decoded.Coverage[0].Diagnostic != "password=[REDACTED] access denied" ||
		decoded.Coverage[0].RecordsRetained != 1 ||
		decoded.MaxTotalBytes != 2000 {
		t.Fatalf("workload coverage ledger was not preserved: %+v", decoded)
	}
	if report.Namespaces[0] != "user@example.com" ||
		report.Coverage[0].Diagnostic != "password="+secret+"\naccess denied" {
		t.Fatal("MarshalWorkloadReport mutated its input")
	}
}
