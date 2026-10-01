package app

import (
	"bytes"
	"os"
	"strings"
	"testing"
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
