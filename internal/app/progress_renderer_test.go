package app

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

func TestProgressRendererNonTTYUsesStableLinesOnly(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Close()

	if got := output.String(); got != "Checking cluster access...\n" {
		t.Fatalf("non-TTY output=%q", got)
	}
	if strings.ContainsAny(output.String(), "\r\x1b") {
		t.Fatalf("non-TTY output contains terminal controls: %q", output.String())
	}
}

func TestTerminalWriterRejectsNonTTYCharacterDevice(t *testing.T) {
	t.Parallel()
	device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	if terminalWriter(device) {
		t.Fatalf("%s was treated as an interactive terminal", os.DevNull)
	}
}

func TestProgressRendererDisabledSuppressesRoutineOutput(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     false,
		Interactive: true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Close()

	if output.Len() != 0 {
		t.Fatalf("disabled renderer output=%q", output.String())
	}
}

func TestProgressRendererInteractiveDefaultsToScannerAndClears(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Step()
	renderer.Close()

	got := output.String()
	if !strings.Contains(got, "\r[>         ] Qodo Scout is working") ||
		!strings.Contains(got, "\r[-->       ] Qodo Scout is working") {
		t.Fatalf("default scanner frames missing: %q", got)
	}
	if !strings.HasSuffix(got, "\r                              \r") {
		t.Fatalf("scanner was not cleared on close: %q", got)
	}
}

func TestProgressRendererScannerUsesDeterministicASCIIFrames(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	for range scannerFrameCount {
		renderer.Step()
	}
	renderer.Close()

	got := output.String()
	for _, frame := range []string{
		"[>         ]",
		"[-->       ]",
		"[---->     ]",
		"[------>   ]",
		"[--------> ]",
	} {
		if !strings.Contains(got, "\r"+frame+" Qodo Scout is working") {
			t.Fatalf("scanner frame %q missing from %q", frame, got)
		}
	}
	for _, character := range got {
		if character == '\r' || character == '\n' {
			continue
		}
		if character < 0x20 || character > 0x7e {
			t.Fatalf("scanner output contains non-ASCII character %q", character)
		}
	}
}

func TestProgressRendererScannerUsesActiveStageCaption(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     true,
	})
	renderer.Update(progressUpdate{
		ID:      "kubernetes.logs",
		Label:   "Container logs",
		Status:  progressActive,
		Current: 18,
		Total:   35,
	})
	renderer.Step()

	if !strings.Contains(
		output.String(),
		"\r[●━        ]  Scout is collecting container logs · 18/35",
	) {
		t.Fatalf("scanner did not follow active stage: %q", output.String())
	}
}

func TestProgressRendererStageClearsAnimationBeforeLine(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Stage("cluster_ready", "Cluster access confirmed.")
	renderer.Close()

	got := output.String()
	if !strings.Contains(
		got,
		"\r                              \rCluster access confirmed.\n",
	) {
		t.Fatalf("stage line did not replace animation cleanly: %q", got)
	}
}

func TestProgressRendererCancellationCleanupStopsHeartbeatAndClearsAnimation(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
	})

	renderer.Start()
	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Close()
	renderer.Close()

	if !strings.HasSuffix(output.String(), progressClearLine) {
		t.Fatalf("started heartbeat was not cleared: %q", output.String())
	}
}

func TestProgressRendererNonTTYCancellationIsNotPartial(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
	})
	renderer.Update(progressUpdate{
		ID: "kubernetes.logs", Label: "Container logs", Level: 2,
		Status: progressActive, Current: 17, Total: 35, Unit: "sources",
	})
	renderer.Pending(progressUpdate{
		ID: "kubernetes.logs", Label: "Container logs", Level: 2,
		Status: progressWarning, Current: 17, Total: 35, Unit: "sources",
		Detail: "partial",
	})
	renderer.Cancel()

	const want = "" +
		"    [active] Container logs | 17/35 sources\n" +
		"[!] Canceled while collecting logs | 17/35 complete\n" +
		"No bundle created.\n"
	if output.String() != want {
		t.Fatalf("non-TTY cancellation:\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestProgressRendererResolvesRealPartialLogCollection(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     true,
	})
	renderer.Pending(progressUpdate{
		ID: "kubernetes.logs", Label: "Container logs", Level: 2,
		Status: progressWarning, Current: 17, Total: 35, Unit: "sources",
		Detail: "partial",
	})
	renderer.ResolvePending("kubernetes.logs")

	const want = "    ! Container logs · 17/35 sources · partial\n"
	if output.String() != want {
		t.Fatalf("real partial outcome=%q want=%q", output.String(), want)
	}
}

func TestProgressRendererCancellationAfterCompletedLogsIsGeneric(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     true,
	})
	renderer.Update(progressUpdate{
		ID: "kubernetes.logs", Label: "Container logs", Level: 2,
		Status: progressCompleted, Current: 35, Total: 35, Unit: "sources",
	})
	output.Reset()
	renderer.Update(progressUpdate{
		ID: "workload", Label: "Workload and service context", Level: 1,
		Status: progressActive,
	})
	output.Reset()
	renderer.Cancel()

	const want = "! Canceled\nNo bundle created.\n"
	if output.String() != want {
		t.Fatalf("late cancellation=%q want=%q", output.String(), want)
	}
}

func TestProgressRendererBubbleTeaRunsInlineAndStopsSynchronously(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     true,
		Width:       80,
		Now:         func() time.Time { return now },
		BubbleTea:   true,
	})

	renderer.Start()
	renderer.Update(progressUpdate{
		ID: "collection", Label: "Qodo Scout collection", Status: progressActive,
	})
	now = now.Add(time.Second)
	renderer.Update(progressUpdate{
		ID: "collection", Label: "Qodo Scout collection", Status: progressCompleted,
	})
	renderer.Summary(progressSummary{
		ArchivePath: "/tmp/bundle.tar.gz",
		ArchiveSize: 2048,
	})
	renderer.Close()
	renderer.Close()

	got := output.String()
	if !strings.Contains(got, "Qodo Scout\r\nBundle created") ||
		!strings.Contains(got, "✓ Archive prepared with redaction · 2.0 KiB") ||
		!strings.Contains(got, "Bundle saved: /tmp/bundle.tar.gz") ||
		!strings.Contains(got, "! Review before sharing") {
		t.Fatalf("Bubble Tea final view missing: %q", got)
	}
	if !strings.Contains(got, "\x1b") {
		t.Fatalf("Bubble Tea renderer did not emit inline terminal controls: %q", got)
	}
	if strings.Contains(got, "\x1b[?1049h") || strings.Contains(got, "\x1b[?1049l") {
		t.Fatalf("Bubble Tea used alternate screen controls: %q", got)
	}
	if err := renderer.Err(); err != nil {
		t.Fatalf("Bubble Tea renderer error: %v", err)
	}
}

func TestProgressRendererTTYHierarchyGoldenTranscript(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     true,
		Width:       80,
		Now:         func() time.Time { return now },
	})

	renderer.Update(progressUpdate{
		ID: "collection", Label: "Qodo Scout collection", Status: progressActive,
	})
	renderer.Update(progressUpdate{
		ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1, Status: progressActive,
	})
	now = now.Add(1500 * time.Millisecond)
	renderer.Update(progressUpdate{
		ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
		Status: progressCompleted, Current: 2, Total: 2, Unit: "namespaces",
	})
	renderer.Update(progressUpdate{
		ID: "workload", Label: "Workload context", Level: 1, Status: progressActive,
	})
	now = now.Add(800 * time.Millisecond)
	renderer.Update(progressUpdate{
		ID: "workload", Label: "Workload context", Level: 1,
		Status: progressWarning, Detail: "partial",
	})
	renderer.Summary(progressSummary{
		ArchivePath:  "/tmp/bundle.tar.gz",
		ArchiveSize:  2048,
		Namespaces:   2,
		Pods:         18,
		LogStreams:   37,
		WarningCount: 1,
		SourceOutcomes: []progressSummaryOutcome{
			{Label: "Kubernetes diagnostics", Status: progressCompleted},
			{
				Label:   "Workload context incomplete",
				Status:  progressWarning,
				Message: progressIssueGuidance,
			},
		},
	})

	const want = "" +
		"● Qodo Scout collection\n" +
		"  ● Kubernetes diagnostics\n" +
		"  ✓ Kubernetes diagnostics · 2/2 namespaces · 1.5s\n" +
		"  ● Workload context\n" +
		"  ! Workload context · partial · 800ms\n" +
		"Qodo Scout\n" +
		"Bundle created · 1 warning\n" +
		"2 namespaces · 18 pods · 37 log sources · 2.3s\n\n" +
		"✓ Kubernetes diagnostics\n" +
		"! Workload context incomplete\n" +
		"  Review collection-issues.jsonl for details.\n" +
		"✓ Archive prepared with redaction · 2.0 KiB\n\n" +
		"Bundle saved: /tmp/bundle.tar.gz\n" +
		"! Review before sharing\n"
	if output.String() != want {
		t.Fatalf("TTY transcript mismatch:\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestProgressRendererNonTTYUsesASCIIFallbackGoldenTranscript(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
		Now:     func() time.Time { return now },
	})

	renderer.Update(progressUpdate{
		ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1, Status: progressActive,
	})
	now = now.Add(time.Second)
	renderer.Update(progressUpdate{
		ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
		Status: progressCompleted, Current: 1, Total: 1, Unit: "namespace",
	})
	renderer.Update(progressUpdate{
		ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
		Status: progressFailed, Detail: "unavailable",
	})

	const want = "" +
		"  [active] Kubernetes diagnostics\n" +
		"  [done] Kubernetes diagnostics | 1/1 namespace | 1s\n" +
		"  [failed] Phoenix telemetry | unavailable\n"
	if output.String() != want {
		t.Fatalf("non-TTY transcript mismatch:\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
	if strings.ContainsAny(output.String(), "\r\x1b") {
		t.Fatalf("non-TTY transcript contains controls: %q", output.String())
	}
}

func TestProgressRendererNonTTYFinalSummaryKeepsPlainAbsolutePath(t *testing.T) {
	t.Parallel()
	const archivePath = "/tmp/Qodo cases/bundle #1.tar.gz"
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:  &output,
		Enabled: true,
	})
	renderer.Summary(progressSummary{ArchivePath: archivePath})

	if !strings.Contains(output.String(), "Bundle saved: "+archivePath+"\n") {
		t.Fatalf("plain summary omitted visible archive path: %q", output.String())
	}
	if strings.Contains(output.String(), "\x1b]8;;") {
		t.Fatalf("non-TTY summary emitted OSC 8: %q", output.String())
	}
}

func TestArchivePathLineUsesEscapedOSC8TargetAndVisiblePath(t *testing.T) {
	t.Parallel()
	const archivePath = "/tmp/Qodo cases/bundle #1 [ready].tar.gz"
	got := archivePathLine(archivePath, archivePath, true)
	if !strings.Contains(got, archivePath) {
		t.Fatalf("hyperlink hid visible archive path: %q", got)
	}
	const target = "file:///tmp/Qodo%20cases/bundle%20%231%20%5Bready%5D.tar.gz"
	if !strings.Contains(got, "\x1b]8;;"+target+"\x1b\\") ||
		!strings.HasSuffix(got, "\x1b]8;;\x1b\\") {
		t.Fatalf("OSC 8 target was not safely escaped: %q", got)
	}
}

func TestArchivePathLineLinksActualHomePathWithoutExposingIt(t *testing.T) {
	t.Parallel()
	const (
		displayPath = "~/qodo-support-bundles/bundle #1.tar.gz"
		actualPath  = "/Users/private-account/qodo-support-bundles/bundle #1.tar.gz"
	)
	got := archivePathLine(displayPath, actualPath, true)
	if !strings.Contains(got, displayPath) ||
		strings.Contains(got, "Bundle saved: "+actualPath) {
		t.Fatalf("home path display changed: %q", got)
	}
	const target = "file:///Users/private-account/qodo-support-bundles/bundle%20%231.tar.gz"
	if !strings.Contains(got, "\x1b]8;;"+target+"\x1b\\") {
		t.Fatalf("home archive link did not use actual path: %q", got)
	}
}

func TestProgressRendererInteractiveSummaryUsesClickableVisiblePath(t *testing.T) {
	t.Parallel()
	const archivePath = "/tmp/Qodo cases/bundle #1.tar.gz"
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Hyperlink:   true,
	})
	renderer.Summary(progressSummary{ArchivePath: archivePath})

	if !strings.Contains(output.String(), archivePath) ||
		!strings.Contains(
			output.String(),
			"\x1b]8;;file:///tmp/Qodo%20cases/bundle%20%231.tar.gz\x1b\\",
		) {
		t.Fatalf("interactive summary did not render clickable visible path: %q", output.String())
	}
}

func TestTerminalHyperlinksRequireKnownInteractiveSupport(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("TERM_PROGRAM", "vscode")
	t.Setenv("ACCESSIBLE", "")
	t.Setenv("NO_COLOR", "")
	t.Setenv("WT_SESSION", "")
	if !terminalHyperlinksEnabled(true) {
		t.Fatal("supported interactive terminal did not enable hyperlinks")
	}
	if terminalHyperlinksEnabled(false) {
		t.Fatal("non-TTY output enabled hyperlinks")
	}
	t.Setenv("ACCESSIBLE", "1")
	if terminalHyperlinksEnabled(true) {
		t.Fatal("accessible output enabled hyperlinks")
	}
}

func TestProgressRendererTTYFailureUsesCapabilitySafeMarker(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		unicode bool
		want    string
	}{
		{name: "unicode", unicode: true, want: "  ✗ Phoenix telemetry · unavailable\n"},
		{name: "ASCII", unicode: false, want: "  [x] Phoenix telemetry | unavailable\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			renderer := newProgressRenderer(progressRendererOptions{
				Writer:      &output,
				Enabled:     true,
				Interactive: true,
				Unicode:     test.unicode,
			})
			renderer.Update(progressUpdate{
				ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
				Status: progressFailed, Detail: "unavailable",
			})
			if output.String() != test.want {
				t.Fatalf("failure marker mismatch: got %q want %q", output.String(), test.want)
			}
		})
	}
}

func TestProgressRendererTTYLinesRespectTerminalWidth(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     false,
		Width:       36,
	})

	renderer.Update(progressUpdate{
		ID: "archive", Label: "Archive finalization with a deliberately long label",
		Level: 1, Status: progressActive,
	})
	renderer.Summary(progressSummary{
		ArchivePath: "/a/very/long/customer/path/to/qodo-support-bundle.tar.gz",
		ArchiveSize: 1024,
	})

	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "Bundle saved: ") {
			continue
		}
		if utf8.RuneCountInString(line) > 36 {
			t.Fatalf("line exceeds terminal width (%d): %q", utf8.RuneCountInString(line), line)
		}
	}
	if !strings.Contains(
		output.String(),
		"Bundle saved: /a/very/long/customer/path/to/qodo-support-bundle.tar.gz",
	) {
		t.Fatalf("narrow terminal clipped archive path: %q", output.String())
	}
	if strings.Contains(output.String(), "…") {
		t.Fatalf("ASCII fallback used Unicode ellipsis: %q", output.String())
	}
}

func TestProgressRendererNarrowHeartbeatFitsOneTerminalRow(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Unicode:     false,
		Width:       14,
	})

	renderer.Step()

	frame := strings.TrimPrefix(output.String(), "\r")
	if frame != "[>        ..." {
		t.Fatalf("narrow heartbeat clipping=%q", frame)
	}
	if utf8.RuneCountInString(frame) > 13 {
		t.Fatalf("heartbeat can wrap at terminal edge: %q", frame)
	}
}

func TestFitTerminalLineCountsWideCharactersByDisplayColumns(t *testing.T) {
	t.Parallel()
	got := fitTerminalLine("123456界界", 9, true)
	if terminalDisplayWidth(got) > 9 {
		t.Fatalf("wide line exceeds terminal width: %q (%d columns)", got, terminalDisplayWidth(got))
	}
}

func TestFitTerminalLinePreservesANSISequences(t *testing.T) {
	t.Parallel()
	value := "\x1b[38;5;81mChecking read-only access\x1b[0m"
	got := fitTerminalLine(value, 14, true)
	if ansi.StringWidth(got) > 14 ||
		!strings.HasSuffix(ansi.Strip(got), "…") ||
		!strings.Contains(got, "\x1b[0m") {
		t.Fatalf("ANSI-safe fitted line=%q width=%d", got, ansi.StringWidth(got))
	}
}

func TestTerminalLineRemovesUnicodeFormattingControls(t *testing.T) {
	t.Parallel()
	got := terminalLine("safe\u202Egnp\u0085\u009b.exe")
	for _, unsafe := range []rune{'\u202E', '\u0085', '\u009b'} {
		if strings.ContainsRune(got, unsafe) {
			t.Fatalf("terminal text retained control %U: %q", unsafe, got)
		}
	}
}

func TestTerminalUnicodeUsesEffectiveLocalePrecedence(t *testing.T) {
	t.Setenv("ACCESSIBLE", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LC_ALL", "C")
	if terminalUnicode() {
		t.Fatal("LC_ALL=C did not override UTF-8 LANG")
	}

	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "C.UTF-8")
	if !terminalUnicode() {
		t.Fatal("UTF-8 LC_CTYPE was not detected")
	}

	t.Setenv("ACCESSIBLE", "1")
	if terminalUnicode() {
		t.Fatal("accessible mode did not select ASCII markers")
	}
}
