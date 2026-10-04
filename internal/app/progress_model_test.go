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
		"  ✓ Kubernetes diagnostics · 2/2 namespaces · 1.5s\n" +
		"[●━        ] Qodo Scout is working"
	if got := model.View(); got != want {
		t.Fatalf("view mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestProgressModelTickCyclesScannerFramesByDefault(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{Width: 80})
	for index, frame := range []string{
		"[>         ]",
		"[-->       ]",
		"[---->     ]",
		"[------>   ]",
		"[--------> ]",
		"[------>   ]",
		"[---->     ]",
		"[-->       ]",
	} {
		if got := model.View(); !strings.HasSuffix(got, frame+" Qodo Scout is working") {
			t.Fatalf("frame %d missing: %q", index, got)
		}
		model = updateProgressModel(t, model, progressTickMsg{})
	}
}

func TestProgressModelCaptionTracksActiveStageAndCount(t *testing.T) {
	t.Parallel()
	now := time.Now()
	model := newProgressModel(progressModelOptions{Unicode: true, Width: 80})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID:      "kubernetes.logs",
			Label:   "Container logs",
			Status:  progressActive,
			Current: 18,
			Total:   35,
			Unit:    "sources",
		},
		At: now,
	})

	const want = "[●━        ]  Scout is collecting container logs · 18/35"
	if got := model.activityLine(); got != want {
		t.Fatalf("scanner activity=%q want=%q", got, want)
	}
}

func TestProgressModelCancellationReplacesActiveLogsWithClearOutcome(t *testing.T) {
	t.Parallel()
	now := time.Now()
	model := newProgressModel(progressModelOptions{Unicode: true, Width: 80})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "kubernetes.logs", Label: "Container logs", Level: 2,
			Status: progressActive, Current: 17, Total: 35, Unit: "sources",
		},
		At: now,
	})
	model = updateProgressModel(t, model, progressCanceledMsg{})

	const want = "" +
		"! Canceled while collecting logs · 17/35 complete\n" +
		"No bundle created."
	if got := model.View(); got != want {
		t.Fatalf("cancellation view:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(model.View(), "partial") {
		t.Fatalf("cancellation mislabeled partial: %q", model.View())
	}
}

func TestProgressModelCancellationAfterLogsUsesGenericOutcome(t *testing.T) {
	t.Parallel()
	model := newProgressModel(progressModelOptions{
		Unicode: true,
		Started: time.Unix(10, 0),
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{
			ID: "kubernetes.logs", Label: "Container logs",
			Status: progressCompleted, Current: 35, Total: 35, Unit: "sources",
		},
		At: time.Unix(11, 0),
	})
	model = updateProgressModel(t, model, progressUpdateMsg{
		Update: progressUpdate{ID: "workload", Label: "Workload and service context", Status: progressActive},
		At:     time.Unix(12, 0),
	})
	model = updateProgressModel(t, model, progressCanceledMsg{})

	const want = "! Canceled\nNo bundle created."
	if got := model.View(); got != want {
		t.Fatalf("late cancellation:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestProgressModelCaptionFollowsLatestActiveStage(t *testing.T) {
	t.Parallel()
	now := time.Now()
	model := newProgressModel(progressModelOptions{Width: 80})
	for _, update := range []progressUpdate{
		{ID: "preflight", Label: "Read-only cluster access", Status: progressActive},
		{ID: "kubernetes.discovery", Label: "Finding namespaces", Status: progressActive},
		{
			ID: "kubernetes.discovery", Label: "Finding namespaces",
			Status: progressCompleted, Current: 2, Total: 2,
		},
		{ID: "archive", Label: "Redaction and archive", Status: progressActive},
	} {
		model = updateProgressModel(t, model, progressUpdateMsg{Update: update, At: now})
	}
	if got := model.activityLine(); got != "[>         ]  Scout is preparing redacted archive" {
		t.Fatalf("latest-stage activity=%q", got)
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
		"Bundle created · 1 warning\n" +
		"1 namespace · 18 pods · 37 log sources · 2.3s\n\n" +
		"✓ Kubernetes diagnostics\n" +
		"! Workload context incomplete\n" +
		"  Review collection-issues.jsonl for details.\n" +
		"✓ Archive prepared with redaction · 2.0 KiB\n\n" +
		"Bundle saved: /tmp/bundle.tar.gz\n" +
		"! Review before sharing"
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
