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
		"Bundle created with 1 warning\n" +
		"1 namespace · 18 pods · 37 log streams · 38.7s\n\n" +
		"✓ Kubernetes diagnostics\n" +
		"✓ Workload context\n" +
		"! Prometheus not collected\n" +
		"  No Prometheus service found in bundle-alon-google.\n" +
		"✓ Archive ready · 79.4 KiB\n\n" +
		"Saved locally:\n" +
		"/tmp/bundle.tar.gz\n" +
		"Review collection-issues.jsonl before sharing."
	if got != want {
		t.Fatalf("summary:\n%s\nwant:\n%s", got, want)
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

func TestProgressSummaryPlainModeUsesASCII(t *testing.T) {
	summary := progressSummary{
		Namespaces:   2,
		Pods:         3,
		LogStreams:   4,
		WarningCount: 1,
		SourceOutcomes: []progressSummaryOutcome{
			{Label: "Kubernetes diagnostics", Status: progressCompleted},
			{Label: "Prometheus not collected", Status: progressWarning},
		},
	}

	got := strings.Join(progressSummaryLines(summary, time.Second, false), "\n")
	for _, unicode := range []string{"✓", "·"} {
		if strings.Contains(got, unicode) {
			t.Fatalf("plain summary contains %q:\n%s", unicode, got)
		}
	}
	if !strings.Contains(got, "2 namespaces | 3 pods | 4 log streams | 1s") {
		t.Fatalf("plain summary omitted compact counts:\n%s", got)
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
	for _, line := range strings.Split(model.View(), "\n") {
		if len([]rune(line)) > 28 {
			t.Fatalf("line width %d exceeds 28: %q", len([]rune(line)), line)
		}
	}
}
