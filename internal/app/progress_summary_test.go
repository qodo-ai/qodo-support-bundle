package app

import (
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/prometheus"
)

func TestBuildProgressSummaryUsesCompactTopLevelOutcomes(t *testing.T) {
	result := collection.Result{
		Status: collection.CoveragePartial.String(),
		Coverage: map[collection.Source]collection.Coverage{
			collection.SourceKubernetes: {State: collection.CoverageComplete},
			collection.SourceWorkload:   {State: collection.CoverageComplete},
			collection.SourcePrometheus: {State: collection.CoverageUnavailable, Reason: "service_absent"},
			collection.SourcePhoenix:    {State: collection.CoverageNotRequested},
			collection.SourceZitadel:    {State: collection.CoverageNotRequested},
		},
		KubernetesReport: kubernetes.Report{
			Namespaces:          []string{"bundle-alon-google"},
			Pods:                18,
			LogStreamsCollected: 37,
		},
		PrometheusReport: &prometheus.Report{Reason: "service_absent"},
	}

	summary := buildProgressSummary(result, progressSummaryOptions{
		PrometheusNamespace: "bundle-alon-google",
		ArchivePath:         "/tmp/bundle.tar.gz",
		ArchiveSize:         81306,
	})

	if summary.WarningCount != 1 {
		t.Fatalf("warning count = %d, want 1", summary.WarningCount)
	}
	if len(summary.SourceOutcomes) != 3 {
		t.Fatalf("source outcome count = %d, want 3", len(summary.SourceOutcomes))
	}

	got := strings.Join(progressSummaryLines(summary, 38*time.Second+700*time.Millisecond, true), "\n")
	want := "" +
		"Qodo Scout\n" +
		"Bundle created · 1 warning\n" +
		"1 namespace · 18 pods · 37 log sources · 38.7s\n\n" +
		"✓ Read-only Kubernetes data\n" +
		"✓ Workload and service context\n" +
		"! Prometheus not collected\n" +
		"  No Prometheus service found in bundle-alon-google.\n" +
		"✓ Archive prepared with redaction · 79.4 KiB\n\n" +
		"Bundle saved: /tmp/bundle.tar.gz\n" +
		"! Review before sharing"
	if got != want {
		t.Fatalf("summary:\n%s\nwant:\n%s", got, want)
	}
}

func TestProgressSummaryUsesApprovedHumanCopy(t *testing.T) {
	t.Parallel()
	summary := progressSummary{
		ArchivePath: "/Users/alice/qodo-support-bundles/bundle.tar.gz",
		ArchiveSize: 77210,
		Namespaces:  1,
		Pods:        17,
		LogStreams:  35,
		SourceOutcomes: []progressSummaryOutcome{
			{Label: "Read-only Kubernetes data", Status: progressCompleted},
			{Label: "Workload and service context", Status: progressCompleted},
		},
	}
	const want = "" +
		"Qodo Scout\n" +
		"Bundle created\n" +
		"1 namespace · 17 pods · 35 log sources · 36.7s\n\n" +
		"✓ Read-only Kubernetes data\n" +
		"✓ Workload and service context\n" +
		"✓ Archive prepared with redaction · 75.4 KiB\n\n" +
		"Bundle saved: /Users/alice/qodo-support-bundles/bundle.tar.gz\n" +
		"! Review before sharing"
	got := strings.Join(progressSummaryLines(summary, 36*time.Second+700*time.Millisecond, true), "\n")
	if got != want {
		t.Fatalf("summary:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildProgressSummaryNeverRendersRawReasons(t *testing.T) {
	const secret = "Bearer super-secret-token"
	result := collection.Result{
		Status: collection.CoveragePartial.String(),
		Coverage: map[collection.Source]collection.Coverage{
			collection.SourcePrometheus: {
				State:  collection.CoverageUnavailable,
				Reason: secret,
			},
		},
		PrometheusReport: &prometheus.Report{
			Reason:     secret,
			Diagnostic: "https://admin:password@example.invalid",
		},
	}

	summary := buildProgressSummary(result, progressSummaryOptions{
		PrometheusNamespace: "monitoring",
	})
	got := strings.Join(progressSummaryLines(summary, time.Second, false), "\n")

	for _, forbidden := range []string{secret, "admin", "password", "example.invalid"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("summary rendered unsafe diagnostic %q:\n%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "Review collection-issues.jsonl for details.") {
		t.Fatalf("summary did not use safe generic fallback:\n%s", got)
	}
}

func TestBuildProgressSummaryMapsDiscoveryFailureSafely(t *testing.T) {
	result := collection.Result{
		Status: collection.CoveragePartial.String(),
		Coverage: map[collection.Source]collection.Coverage{
			collection.SourcePrometheus: {
				State:  collection.CoverageUnavailable,
				Reason: "discovery_failed",
			},
		},
		PrometheusReport: &prometheus.Report{
			Reason:     "discovery_failed",
			Diagnostic: "token=must-not-render",
		},
	}

	summary := buildProgressSummary(result, progressSummaryOptions{
		PrometheusNamespace: "monitoring",
	})
	got := strings.Join(progressSummaryLines(summary, time.Second, false), "\n")

	if !strings.Contains(got, "Prometheus could not be discovered in monitoring.") {
		t.Fatalf("summary omitted safe discovery explanation:\n%s", got)
	}
	if strings.Contains(got, "must-not-render") {
		t.Fatalf("summary rendered raw discovery diagnostic:\n%s", got)
	}
}

func TestBuildProgressSummaryDoesNotCallIncompleteCoverageALimit(t *testing.T) {
	result := collection.Result{
		Status: collection.CoveragePartial.String(),
		Coverage: map[collection.Source]collection.Coverage{
			collection.SourcePrometheus: {
				State:  collection.CoveragePartial,
				Reason: "query_coverage_incomplete",
			},
		},
	}

	summary := buildProgressSummary(result, progressSummaryOptions{})
	got := strings.Join(progressSummaryLines(summary, time.Second, false), "\n")

	if !strings.Contains(got, "Prometheus coverage is incomplete.") {
		t.Fatalf("summary omitted neutral incomplete-coverage message:\n%s", got)
	}
	if strings.Contains(got, "configured collection limit") {
		t.Fatalf("summary mislabeled incomplete coverage as a limit:\n%s", got)
	}
}

func TestProgressSummaryPlainModeUsesASCII(t *testing.T) {
	summary := progressSummary{
		Namespaces:   2,
		Pods:         3,
		LogStreams:   4,
		WarningCount: 1,
		SourceOutcomes: []progressSummaryOutcome{
			{Label: "Read-only Kubernetes data", Status: progressCompleted},
			{Label: "Prometheus not collected", Status: progressWarning},
		},
	}

	got := strings.Join(progressSummaryLines(summary, time.Second, false), "\n")
	for _, unicode := range []string{"✓", "·"} {
		if strings.Contains(got, unicode) {
			t.Fatalf("plain summary contains %q:\n%s", unicode, got)
		}
	}
	if !strings.Contains(got, "2 namespaces | 3 pods | 4 log sources | 1s") {
		t.Fatalf("plain summary omitted compact counts:\n%s", got)
	}
	for _, expected := range []string{
		"[ok] Read-only Kubernetes data",
		"[ok] Archive prepared with redaction",
		"[!] Review before sharing",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("plain summary missing %q:\n%s", expected, got)
		}
	}
}

func TestProgressSummaryFitsTerminalWidth(t *testing.T) {
	summary := progressSummary{
		ArchivePath: "/tmp/a-very-long-directory-name/a-very-long-bundle-name.tar.gz",
		SourceOutcomes: []progressSummaryOutcome{
			{
				Label:   "Prometheus not collected",
				Status:  progressWarning,
				Message: "Review collection-issues.jsonl for details.",
			},
		},
		WarningCount: 1,
	}

	model := newProgressModel(progressModelOptions{
		Width:   28,
		Started: time.Unix(0, 0),
	})
	model = updateProgressModel(t, model, progressSummaryMsg{
		Summary: summary,
		At:      time.Unix(1, 0),
	})
	view := model.View()
	for _, line := range strings.Split(view, "\n") {
		if strings.HasPrefix(line, "Bundle saved: ") {
			continue
		}
		if len([]rune(line)) > 28 {
			t.Fatalf("line width %d exceeds 28: %q", len([]rune(line)), line)
		}
	}
	if !strings.Contains(view, "Bundle saved: "+summary.ArchivePath) {
		t.Fatalf("narrow summary clipped archive path:\n%s", view)
	}
}
