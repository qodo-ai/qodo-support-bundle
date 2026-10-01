package app

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestProgressModelUpdateBuildsDeterministicHierarchy(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	model := newProgressModel(progressModelOptions{
		Unicode: true,
		Width:   80,
		Started: start,
	})

	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "collection", Label: "Qodo Scout collection", Status: progressActive,
		},
		At: start,
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
			Status: progressActive, Current: 1, Total: 2, Unit: "namespaces",
		},
		At: start,
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
			Status: progressCompleted, Current: 2, Total: 2, Unit: "namespaces",
		},
		At: start.Add(1500 * time.Millisecond),
	})

	const want = "" +
		"Qodo Scout interactive display\n" +
		"● Qodo Scout collection\n" +
		"  ✓ Kubernetes diagnostics - 2/2 namespaces (1.5s)\n" +
		"| Qodo Scout is working"
	if got := model.View(); got != want {
		t.Fatalf("view mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestProgressModelTickAndMascotAreExplicit(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{Mascot: true, Width: 80})

	if got := model.View(); !strings.HasSuffix(got, "~(____:> Qodo Scout is working") {
		t.Fatalf("first mascot frame missing: %q", got)
	}
	model = updateProgressModel(t, model, progressTickMsg{})
	if got := model.View(); !strings.HasSuffix(got, "-(____:> Qodo Scout is working") {
		t.Fatalf("second mascot frame missing: %q", got)
	}
}

func TestProgressModelSummaryCompactsSuccessfulNestedStages(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	model := newProgressModel(progressModelOptions{
		Unicode: true,
		Width:   80,
		Started: start,
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressActive,
		},
		At: start,
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressWarning, Detail: "partial",
		},
		At: start.Add(800 * time.Millisecond),
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "workload-scan", Label: "Namespace scan", Level: 2,
			Status: progressCompleted, Current: 3, Total: 3, Unit: "pods",
		},
		At: start.Add(time.Second),
	})
	model = updateProgressModel(t, model, progressSummaryMsg{
		Summary: progressSummary{
			ArchivePath:  "/tmp/bundle.tar.gz",
			ArchiveSize:  2048,
			Namespaces:   1,
			Pods:         18,
			LogStreams:   37,
			WarningCount: 1,
			SourceOutcomes: []progressSummaryOutcome{
				{Label: "Kubernetes diagnostics", Status: progressCompleted},
				{
					Label:   "Workload context incomplete",
					Status:  progressWarning,
					Message: "Review collection-issues.jsonl for details.",
				},
			},
		},
		At: start.Add(2300 * time.Millisecond),
	})

	const want = "" +
		"Qodo Scout\n" +
		"Bundle created with 1 warning\n" +
		"1 namespace · 18 pods · 37 log streams · 2.3s\n\n" +
		"✓ Kubernetes diagnostics\n" +
		"! Workload context incomplete\n" +
		"  Review collection-issues.jsonl for details.\n" +
		"✓ Archive ready · 2.0 KiB\n\n" +
		"Saved locally:\n" +
		"/tmp/bundle.tar.gz\n" +
		"Review collection-issues.jsonl before sharing."
	if got := model.View(); got != want {
		t.Fatalf("summary mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestProgressModelFitsEveryLineAfterWindowResize(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{Width: 80})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "archive", Label: "Archive finalization with a deliberately long label",
			Level: 1, Status: progressActive,
		},
		At: time.Now(),
	})
	model = updateProgressModel(t, model, tea.WindowSizeMsg{Width: 24, Height: 10})

	for _, line := range strings.Split(model.View(), "\n") {
		if terminalDisplayWidth(line) > 24 {
			t.Fatalf("line exceeds resized width: %q", line)
		}
	}
}

func TestProgressModelSanitizesTerminalControls(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{Width: 80})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "unsafe\r\nid", Label: "safe\u202Egnp\x1b[31m", Status: progressActive,
		},
		At: time.Now(),
	})

	got := model.View()
	if strings.ContainsAny(got, "\r\x1b") || strings.ContainsRune(got, '\u202E') {
		t.Fatalf("view retained terminal controls: %q", got)
	}
}

func TestProgressModelQuitMessageReturnsTeaQuit(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{})
	next, command := model.Update(progressQuitMsg{})
	if _, ok := next.(progressModel); !ok {
		t.Fatalf("quit returned model %T", next)
	}
	if command == nil {
		t.Fatal("quit command is nil")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatalf("quit command returned %T", command())
	}
}

func updateProgressModel(t *testing.T, model progressModel, message tea.Msg) progressModel {
	t.Helper()
	next, _ := model.Update(message)
	updated, ok := next.(progressModel)
	if !ok {
		t.Fatalf("update returned model %T", next)
	}
	return updated
}
