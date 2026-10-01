package app

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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
		Mascot:      true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Close()

	if output.Len() != 0 {
		t.Fatalf("disabled renderer output=%q", output.String())
	}
}

func TestProgressRendererInteractiveSpinnerIsDeterministicAndClears(t *testing.T) {
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
	if !strings.Contains(got, "\r| Qodo Scout is working") ||
		!strings.Contains(got, "\r/ Qodo Scout is working") {
		t.Fatalf("spinner frames missing: %q", got)
	}
	if !strings.HasSuffix(got, "\r                              \r") {
		t.Fatalf("spinner was not cleared on close: %q", got)
	}
}

func TestProgressRendererMascotReplacesSpinnerWithASCII(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      &output,
		Enabled:     true,
		Interactive: true,
		Mascot:      true,
	})

	renderer.Stage("cluster_access", "Checking cluster access...")
	renderer.Step()
	renderer.Close()

	got := output.String()
	if !strings.Contains(got, "\r~(____:> Qodo Scout is working") {
		t.Fatalf("mascot frame missing: %q", got)
	}
	for _, character := range got {
		if character == '\r' || character == '\n' {
			continue
		}
		if character < 0x20 || character > 0x7e {
			t.Fatalf("mascot output contains non-ASCII character %q", character)
		}
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

func TestProgressRendererCloseStopsStartedHeartbeatAndIsIdempotent(t *testing.T) {
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
	if !strings.Contains(got, "Qodo Scout summary") ||
		!strings.Contains(got, "Archive: /tmp/bundle.tar.gz (2.0 KiB)") {
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
		ArchivePath: "/tmp/bundle.tar.gz",
		ArchiveSize: 2048,
	})

	const want = "" +
		"● Qodo Scout collection\n" +
		"  ● Kubernetes diagnostics\n" +
		"  ✓ Kubernetes diagnostics - 2/2 namespaces (1.5s)\n" +
		"  ● Workload context\n" +
		"  ! Workload context - partial (800ms)\n" +
		"Qodo Scout summary\n" +
		"  ✓ Kubernetes diagnostics - 2/2 namespaces (1.5s)\n" +
		"  ! Workload context - partial (800ms)\n" +
		"Total duration: 2.3s\n" +
		"Archive: /tmp/bundle.tar.gz (2.0 KiB)\n" +
		"Saved locally. Share separately through an approved support channel.\n"
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
		"  [done] Kubernetes diagnostics - 1/1 namespace (1s)\n" +
		"  [failed] Phoenix telemetry - unavailable\n"
	if output.String() != want {
		t.Fatalf("non-TTY transcript mismatch:\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
	if strings.ContainsAny(output.String(), "\r\x1b") {
		t.Fatalf("non-TTY transcript contains controls: %q", output.String())
	}
}

func TestProgressRendererTTYFailureUsesCapabilitySafeMarker(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		unicode bool
		want    string
	}{
		{name: "unicode", unicode: true, want: "  ✗ Phoenix telemetry - unavailable\n"},
		{name: "ASCII", unicode: false, want: "  [x] Phoenix telemetry - unavailable\n"},
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
		if utf8.RuneCountInString(line) > 36 {
			t.Fatalf("line exceeds terminal width (%d): %q", utf8.RuneCountInString(line), line)
		}
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
		Width:       10,
	})

	renderer.Step()

	frame := strings.TrimPrefix(output.String(), "\r")
	if utf8.RuneCountInString(frame) > 9 {
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
}
