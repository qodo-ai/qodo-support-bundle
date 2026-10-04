package app

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestWizardPreflightTransitionsThroughActualChecks(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: true, Width: 80},
	)
	if got := model.View(); !strings.Contains(got, "✓ kubectl ready") ||
		!strings.Contains(got, "● finding kubeconfig contexts") {
		t.Fatalf("initial preflight=%q", got)
	}

	model = updateWizardPreflight(t, model, wizardContextsMsg{
		Contexts: []string{"development", "customer"},
	})
	if got := model.View(); !strings.Contains(got, "✓ 2 kubeconfig contexts found") ||
		!strings.Contains(got, "● identifying current context") {
		t.Fatalf("contexts transition=%q", got)
	}

	model = updateWizardPreflight(t, model, wizardCurrentContextMsg{
		Context: "development",
	})
	if !model.done || model.catalog.Current != "development" {
		t.Fatalf("final model=%+v", model)
	}
	if got := model.View(); !strings.Contains(got, "✓ current context identified") {
		t.Fatalf("final preflight=%q", got)
	}
}

func TestWizardPreflightKeySkipsDecorationNotValidation(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: true, Entrance: true},
	)
	model = updateWizardPreflight(t, model, tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'s'},
	})
	if !model.skipDecoration || model.done {
		t.Fatalf("skip changed validation state: %+v", model)
	}
	model = updateWizardPreflight(t, model, wizardContextsMsg{
		Contexts: []string{"development"},
	})
	if model.done || len(model.catalog.Names) != 1 {
		t.Fatalf("validation did not continue: %+v", model)
	}
	model = updateWizardPreflight(t, model, wizardCurrentContextMsg{
		Context: "development",
	})
	if !model.done || model.catalog.Current != "development" {
		t.Fatalf("validation did not finish after skip: %+v", model)
	}
}

func TestWizardPreflightSpringOvershootsAndSettlesAfterFastValidation(
	t *testing.T,
) {
	t.Parallel()
	maxDuration := wizardPreflightTickInterval * wizardEntranceMaxFrames
	if maxDuration >= time.Second {
		t.Fatalf("entrance maximum duration=%s, want under 1s", maxDuration)
	}
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: true, Entrance: true, Width: 80},
	)
	if model.x >= wizardEntranceTarget(model.options.Width) {
		t.Fatalf("scanner did not start before target: x=%f", model.x)
	}
	if got := model.View(); strings.Contains(got, "finding kubeconfig contexts") {
		t.Fatalf("initial entrance=%q", got)
	}
	model = updateWizardPreflight(t, model, wizardContextsMsg{
		Contexts: []string{"development"},
	})
	model = updateWizardPreflight(t, model, wizardCurrentContextMsg{
		Context: "development",
	})
	if model.done || !model.validationDone {
		t.Fatalf("fast validation skipped guaranteed entrance: %+v", model)
	}
	frames := 0
	for !model.entranceDone && frames < wizardEntranceMaxFrames {
		model = updateWizardPreflight(t, model, wizardPreflightTickMsg{})
		frames++
		if frames == wizardEntranceMinFrames/2 {
			view := model.View()
			if !strings.Contains(view, "QODO SCOUT") ||
				!strings.Contains(view, "Read-only on-prem diagnostics") {
				t.Fatalf("settling title=%q", view)
			}
		}
	}
	if !model.done || !model.entranceDone {
		t.Fatalf("entrance did not finish at cap: %+v", model)
	}
	if frames < wizardEntranceMinFrames || frames > wizardEntranceMaxFrames {
		t.Fatalf("entrance frames=%d", frames)
	}
	if !model.overshot {
		t.Fatalf("spring never overshot target: x=%f target=%f",
			model.x, wizardEntranceTarget(model.options.Width))
	}
	if distance := math.Abs(
		model.x - wizardEntranceTarget(model.options.Width),
	); distance > 3 {
		t.Fatalf("spring did not settle near target: distance=%f", distance)
	}
}

func TestWizardPreflightEntranceRunsConcurrentlyWithSlowValidation(
	t *testing.T,
) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: true, Entrance: true},
	)
	for !model.entranceDone {
		model = updateWizardPreflight(t, model, wizardPreflightTickMsg{})
	}
	if model.done || !model.entranceDone {
		t.Fatalf("entrance should wait for validation after its cap: %+v", model)
	}
	if got := model.View(); !strings.Contains(got, "finding kubeconfig contexts") ||
		strings.Contains(got, "QODO SCOUT") {
		t.Fatalf("slow validation transition=%q", got)
	}
	model = updateWizardPreflight(t, model, wizardContextsMsg{
		Contexts: []string{"development"},
	})
	model = updateWizardPreflight(t, model, wizardCurrentContextMsg{
		Context: "development",
	})
	if !model.done {
		t.Fatalf("slow validation added a second entrance delay: %+v", model)
	}
}

func TestWizardPreflightEntranceUsesNarrowFallback(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{
			Unicode:  true,
			Entrance: true,
			Width:    28,
		},
	)
	for range wizardEntranceMinFrames / 2 {
		model = updateWizardPreflight(t, model, wizardPreflightTickMsg{})
	}
	view := model.View()
	if !strings.Contains(view, "Checking environment…") ||
		!strings.Contains(view, "QODO SCOUT") ||
		strings.Contains(view, "[") ||
		strings.Contains(view, "●") {
		t.Fatalf("narrow entrance=%q", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if terminalDisplayWidth(line) > 28 {
			t.Fatalf("narrow line exceeds width: %q", line)
		}
	}
}

func TestWizardPreflightScannerHasUnicodeAndASCIIFallbacks(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		unicode    bool
		want, deny string
	}{
		{"unicode", true, "━●━", ">"},
		{"ASCII", false, "---->", "●"},
	} {
		model := newWizardPreflightModel(
			context.Background(),
			&wizardDiscoveryStub{},
			wizardPreflightOptions{
				Unicode:  test.unicode,
				Entrance: true,
				Width:    80,
			},
		)
		for range wizardEntranceMinFrames / 2 {
			model = updateWizardPreflight(t, model, wizardPreflightTickMsg{})
		}
		view := model.View()
		if !strings.Contains(view, test.want) ||
			strings.Contains(view, test.deny) {
			t.Errorf("%s scanner=%q", test.name, view)
		}
	}
}

func TestWizardPreflightEntranceColorPreservesPlainCopy(t *testing.T) {
	t.Parallel()
	plain := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: true, Entrance: true, Width: 80},
	)
	color := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{
			Unicode:  true,
			Color:    true,
			Entrance: true,
			Width:    80,
		},
	)
	for range wizardEntranceMinFrames / 2 {
		plain = updateWizardPreflight(t, plain, wizardPreflightTickMsg{})
		color = updateWizardPreflight(t, color, wizardPreflightTickMsg{})
	}
	styled := color.View()
	if got, want := ansi.Strip(styled), plain.View(); got != want {
		t.Fatalf("strip-ANSI copy mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestWizardPreflightEntranceCancellationStopsChildContext(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Entrance: true},
	)
	model = updateWizardPreflight(t, model, tea.KeyMsg{Type: tea.KeyCtrlC})
	if !errors.Is(model.err, context.Canceled) || !model.done {
		t.Fatalf("Ctrl+C did not stop entrance: %+v", model)
	}
	select {
	case <-model.ctx.Done():
	default:
		t.Fatal("Ctrl+C left the validation context running")
	}
}

func TestWizardEntranceOnlyRunsInDecoratedInteractiveTTY(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                             string
		visible, accessible, noColor     bool
		inputTTY, outputTTY, wantEnabled bool
		term                             string
	}{
		{"interactive", true, false, false, true, true, true, "xterm-256color"},
		{"no progress", false, false, false, true, true, false, "xterm"},
		{"accessible", true, true, false, true, true, false, "xterm"},
		{"no color", true, false, true, true, true, false, "xterm"},
		{"redirected input", true, false, false, false, true, false, "xterm"},
		{"redirected output", true, false, false, true, false, false, "xterm"},
		{"dumb terminal", true, false, false, true, true, false, "dumb"},
		{"unknown terminal", true, false, false, true, true, false, ""},
	}
	for _, test := range tests {
		if got := wizardEntranceEnabled(
			test.visible,
			test.accessible,
			test.noColor,
			test.inputTTY,
			test.outputTTY,
			test.term,
		); got != test.wantEnabled {
			t.Errorf("%s enabled=%t want %t", test.name, got, test.wantEnabled)
		}
	}
}

func TestWizardPreflightEntranceUsesInjectedTick(t *testing.T) {
	t.Parallel()
	tickCalls := 0
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{
			Entrance: true,
			Tick: func() tea.Cmd {
				tickCalls++
				return func() tea.Msg { return wizardPreflightTickMsg{} }
			},
		},
	)
	message := model.tickCommand()()
	if _, ok := message.(wizardPreflightTickMsg); !ok || tickCalls != 1 {
		t.Fatalf("injected tick message=%T calls=%d", message, tickCalls)
	}
}

func TestWizardPreflightCancellationAndFailureAreConcise(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: false},
	)
	canceled := updateWizardPreflight(t, model, tea.KeyMsg{Type: tea.KeyCtrlC})
	if !errors.Is(canceled.err, context.Canceled) || !canceled.done {
		t.Fatalf("Ctrl+C did not cancel: %+v", canceled)
	}

	const secretReason = "credential=/Users/private/.kube/config"
	failed := updateWizardPreflight(t, model, wizardContextsMsg{
		Err: errors.New(secretReason),
	})
	if failed.err == nil || !failed.done {
		t.Fatalf("failure not retained: %+v", failed)
	}
	view := failed.View()
	if strings.Contains(view, secretReason) ||
		!strings.Contains(view, "[x] kubeconfig contexts unavailable") {
		t.Fatalf("unsafe or unclear failure=%q", view)
	}
}

func TestWizardPreflightPlainTranscriptHasNoANSI(t *testing.T) {
	t.Parallel()
	model := newWizardPreflightModel(
		context.Background(),
		&wizardDiscoveryStub{},
		wizardPreflightOptions{Unicode: false, Width: 34},
	)
	model = updateWizardPreflight(t, model, wizardContextsMsg{
		Contexts: []string{"development"},
	})
	model = updateWizardPreflight(t, model, wizardCurrentContextMsg{})
	view := model.View()
	if strings.Contains(view, "\x1b") {
		t.Fatalf("plain preflight contains ANSI: %q", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if terminalDisplayWidth(line) > 34 {
			t.Fatalf("preflight line exceeds width: %q", line)
		}
	}
}

func TestWizardPreflightStaticPathHasNoAnimationOrANSI(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	catalog, err := runWizardPreflight(
		context.Background(),
		&wizardDiscoveryStub{
			contexts:       []string{"development"},
			currentContext: "development",
		},
		strings.NewReader(""),
		&output,
		wizardPreflightOptions{Visible: true},
	)
	if err != nil || catalog.Current != "development" {
		t.Fatalf("static preflight catalog=%+v err=%v", catalog, err)
	}
	got := output.String()
	if strings.Contains(got, "\x1b") ||
		strings.Contains(got, "QODO SCOUT") ||
		!strings.Contains(got, "[ok] current context identified") {
		t.Fatalf("static preflight=%q", got)
	}
}

func TestNamespaceDiscoveryProgressUsesRealCallAndNoProgressStaysQuiet(t *testing.T) {
	t.Parallel()
	for _, visible := range []bool{true, false} {
		discovery := &wizardDiscoveryStub{namespaces: []string{"qodo"}}
		var output strings.Builder
		namespaces, err := runWizardNamespaceDiscovery(
			context.Background(),
			discovery,
			"customer",
			&output,
			visible,
		)
		if err != nil || len(namespaces) != 1 ||
			len(discovery.namespaceCalls) != 1 {
			t.Fatalf(
				"visible=%t namespaces=%v calls=%v err=%v",
				visible,
				namespaces,
				discovery.namespaceCalls,
				err,
			)
		}
		if visible {
			if !strings.Contains(output.String(), "Checking read-only access") ||
				!strings.Contains(output.String(), "Read-only access confirmed") {
				t.Fatalf("plain namespace progress=%q", output.String())
			}
		} else if output.Len() != 0 {
			t.Fatalf("--no-progress emitted namespace status %q", output.String())
		}
	}
}

func updateWizardPreflight(
	t *testing.T,
	model wizardPreflightModel,
	message tea.Msg,
) wizardPreflightModel {
	t.Helper()
	updated, _ := model.Update(message)
	result, ok := updated.(wizardPreflightModel)
	if !ok {
		t.Fatalf("updated model type %T", updated)
	}
	return result
}
