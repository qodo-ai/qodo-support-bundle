package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/harmonica"
)

const (
	wizardPreflightTickInterval = 50 * time.Millisecond
	wizardEntranceMinFrames     = 8
	wizardEntranceMaxFrames     = 16
	wizardScannerMaxTrackWidth  = 18
	wizardScannerMinTrackWidth  = 8
	wizardScannerStaticWidth    = 32
)

type wizardPreflightOptions struct {
	Interactive bool
	Visible     bool
	Unicode     bool
	Color       bool
	Width       int
	Entrance    bool
	Tick        func() tea.Cmd
}

type wizardContextsMsg struct {
	Contexts []string
	Err      error
}

type wizardCurrentContextMsg struct {
	Context string
	Err     error
}

type wizardPreflightTickMsg struct{}

type wizardPreflightModel struct {
	ctx            context.Context
	cancel         context.CancelFunc
	discovery      interactiveDiscovery
	options        wizardPreflightOptions
	catalog        interactiveContextCatalog
	stage          int
	frame          int
	x              float64
	xVelocity      float64
	spring         harmonica.Spring
	overshot       bool
	done           bool
	validationDone bool
	entranceDone   bool
	skipDecoration bool
	err            error
	currentWarning bool
}

func newWizardPreflightModel(
	ctx context.Context,
	discovery interactiveDiscovery,
	options wizardPreflightOptions,
) wizardPreflightModel {
	taskContext, cancel := context.WithCancel(ctx)
	return wizardPreflightModel{
		ctx:       taskContext,
		cancel:    cancel,
		discovery: discovery,
		options:   options,
		x:         0,
		spring:    harmonica.NewSpring(harmonica.FPS(20), 12, 0.55),
	}
}

func (model wizardPreflightModel) Init() tea.Cmd {
	if !model.options.Entrance {
		return model.contextsCommand()
	}
	return tea.Batch(model.contextsCommand(), model.tickCommand())
}

func (model wizardPreflightModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case wizardContextsMsg:
		if message.Err != nil {
			model.cancel()
			model.err = concisePreflightError(message.Err)
			model.done = true
			return model, tea.Quit
		}
		if len(message.Contexts) == 0 {
			model.cancel()
			model.err = errors.New("no kubeconfig contexts found")
			model.done = true
			return model, tea.Quit
		}
		model.catalog.Names = append([]string(nil), message.Contexts...)
		model.stage = 1
		return model, model.currentContextCommand()
	case wizardCurrentContextMsg:
		if message.Err == nil &&
			containsString(model.catalog.Names, terminalLine(message.Context)) {
			model.catalog.Current = terminalLine(message.Context)
		} else {
			model.currentWarning = true
		}
		model.stage = 2
		model.validationDone = true
		if model.entranceDone || model.skipDecoration || !model.options.Entrance {
			model.done = true
			model.cancel()
			return model, tea.Quit
		}
		return model, nil
	case wizardPreflightTickMsg:
		if model.done || model.skipDecoration || model.entranceDone {
			return model, nil
		}
		target := wizardEntranceTarget(model.options.Width)
		model.x, model.xVelocity = model.spring.Update(
			model.x,
			model.xVelocity,
			target,
		)
		if model.x > target {
			model.overshot = true
		}
		model.frame++
		settled := math.Abs(model.x-target) < 0.5 &&
			math.Abs(model.xVelocity) < 1
		if model.frame >= wizardEntranceMaxFrames ||
			(model.frame >= wizardEntranceMinFrames && settled) {
			model.entranceDone = true
			if model.validationDone {
				model.done = true
				model.cancel()
				return model, tea.Quit
			}
			return model, nil
		}
		return model, model.tickCommand()
	case tea.KeyMsg:
		if message.Type == tea.KeyCtrlC {
			model.cancel()
			model.err = context.Canceled
			model.done = true
			return model, tea.Quit
		}
		model.skipDecoration = true
		model.entranceDone = true
		if model.validationDone {
			model.done = true
			model.cancel()
			return model, tea.Quit
		}
		return model, nil
	default:
		return model, nil
	}
}

func (model wizardPreflightModel) View() string {
	if model.options.Entrance && !model.entranceDone && !model.skipDecoration &&
		model.err == nil {
		return model.entranceView()
	}
	lines := []string{
		model.checkLine(progressCompleted, "kubectl ready"),
	}
	switch model.stage {
	case 0:
		lines = append(lines,
			model.checkLine(progressActive, "finding kubeconfig contexts"),
			model.checkLine(progressStatus("future"), "current context"),
		)
	case 1:
		lines = append(lines,
			model.checkLine(
				progressCompleted,
				fmt.Sprintf(
					"%d %s found",
					len(model.catalog.Names),
					plural(len(model.catalog.Names), "kubeconfig context", "kubeconfig contexts"),
				),
			),
			model.checkLine(progressActive, "identifying current context"),
		)
	default:
		lines = append(lines,
			model.checkLine(
				progressCompleted,
				fmt.Sprintf(
					"%d %s found",
					len(model.catalog.Names),
					plural(len(model.catalog.Names), "kubeconfig context", "kubeconfig contexts"),
				),
			),
		)
		if model.currentWarning {
			lines = append(lines, model.checkLine(
				progressWarning,
				"current context not identified",
			))
		} else {
			lines = append(lines, model.checkLine(
				progressCompleted,
				"current context identified",
			))
		}
	}
	if model.err != nil && !errors.Is(model.err, context.Canceled) {
		lines[len(lines)-1] = model.checkLine(
			progressFailed,
			"kubeconfig contexts unavailable",
		)
	}
	if !model.done && !model.skipDecoration {
		lines = append(
			lines,
			scannerFrame(model.frame, model.options.Unicode)+"  Scout is checking setup",
		)
	}
	for index, line := range lines {
		if model.options.Width > 0 {
			lines[index] = fitTerminalLine(
				line,
				model.options.Width,
				model.options.Unicode,
			)
		}
	}
	return strings.Join(lines, "\n")
}

func (model wizardPreflightModel) entranceView() string {
	title := centerEntranceLine(
		semanticWizardText(
			wizardTitleAccent,
			"QODO SCOUT",
			model.options.Color,
		),
		model.options.Width,
	)
	subtitle := centerEntranceLine(
		semanticWizardText(
			wizardSecondary,
			"Read-only on-prem diagnostics",
			model.options.Color,
		),
		model.options.Width,
	)
	if model.options.Width > 0 &&
		model.options.Width < wizardScannerStaticWidth {
		status := "Checking environment..."
		if model.options.Unicode {
			status = "Checking environment…"
		}
		return strings.Join([]string{
			fitTerminalLine(
				title,
				model.options.Width,
				model.options.Unicode,
			),
			fitTerminalLine(
				subtitle,
				model.options.Width,
				model.options.Unicode,
			),
			"",
			fitTerminalLine(
				status,
				model.options.Width,
				model.options.Unicode,
			),
		}, "\n")
	}
	status := "Checking environment..."
	if model.options.Unicode {
		status = "Checking environment…"
	}
	scanner := model.scannerTrack()
	line := scanner + "  " + status
	if model.options.Width > 0 &&
		terminalDisplayWidth(line) > model.options.Width {
		line = scanner + "\n" + status
	}
	return strings.Join([]string{title, subtitle, "", line}, "\n")
}

func (model wizardPreflightModel) scannerTrack() string {
	width := wizardScannerTrackWidth(
		model.options.Width,
		model.options.Unicode,
	)
	point := min(width-1, max(0, int(math.Round(model.x))))
	if model.options.Unicode {
		cells := make([]string, width)
		for index := range cells {
			cells[index] = " "
		}
		beam := "━"
		if model.frame >= wizardEntranceMinFrames &&
			model.frame%2 == 0 {
			beam = "─"
		}
		for offset := -1; offset <= 1; offset++ {
			index := point + offset
			if index < 0 || index >= width {
				continue
			}
			if offset == 0 {
				cells[index] = "●"
			} else {
				cells[index] = beam
			}
		}
		return semanticWizardText(
			wizardSecondary,
			"[",
			model.options.Color,
		) +
			semanticWizardText(
				wizardActive,
				strings.Join(cells, ""),
				model.options.Color,
			) +
			semanticWizardText(
				wizardSecondary,
				"]",
				model.options.Color,
			)
	}
	cells := make([]byte, width)
	for index := range cells {
		cells[index] = ' '
	}
	for index := 0; index < point; index++ {
		cells[index] = '-'
	}
	cells[point] = '>'
	return semanticWizardText(
		wizardSecondary,
		"[",
		model.options.Color,
	) +
		semanticWizardText(
			wizardActive,
			string(cells),
			model.options.Color,
		) +
		semanticWizardText(
			wizardSecondary,
			"]",
			model.options.Color,
		)
}

func wizardEntranceTarget(width int) float64 {
	return float64(wizardScannerTrackWidth(width, true) - 4)
}

func wizardScannerTrackWidth(width int, unicode bool) int {
	status := "Checking environment..."
	if unicode {
		status = "Checking environment…"
	}
	if width <= 0 {
		return wizardScannerMaxTrackWidth
	}
	available := width - terminalDisplayWidth(status) - 4
	return min(
		wizardScannerMaxTrackWidth,
		max(wizardScannerMinTrackWidth, available),
	)
}

func centerEntranceLine(line string, width int) string {
	if width <= 0 {
		return line
	}
	return strings.Repeat(
		" ",
		max(0, (width-terminalDisplayWidth(line))/2),
	) + line
}

func (model wizardPreflightModel) checkLine(
	status progressStatus,
	label string,
) string {
	marker := "[ ]"
	semantic := wizardSecondary
	switch status {
	case progressCompleted:
		marker, semantic = "[ok]", wizardSafe
	case progressActive:
		marker, semantic = "[>]", wizardActive
	case progressWarning:
		marker, semantic = "[!]", wizardWarning
	case progressFailed:
		marker, semantic = "[x]", wizardFailure
	}
	if model.options.Unicode {
		switch status {
		case progressCompleted:
			marker = "✓"
		case progressActive:
			marker = "●"
		case progressWarning:
			marker = "!"
		case progressFailed:
			marker = "✗"
		default:
			marker = "○"
		}
	}
	return semanticWizardText(
		semantic,
		marker+" "+label,
		model.options.Color,
	)
}

func (model wizardPreflightModel) contextsCommand() tea.Cmd {
	return func() tea.Msg {
		contexts, err := model.discovery.Contexts(model.ctx)
		return wizardContextsMsg{Contexts: contexts, Err: err}
	}
}

func (model wizardPreflightModel) currentContextCommand() tea.Cmd {
	return func() tea.Msg {
		current, err := model.discovery.CurrentContext(model.ctx)
		return wizardCurrentContextMsg{Context: current, Err: err}
	}
}

func wizardPreflightTick() tea.Cmd {
	return tea.Tick(wizardPreflightTickInterval, func(time.Time) tea.Msg {
		return wizardPreflightTickMsg{}
	})
}

func wizardEntranceEnabled(
	visible bool,
	accessible bool,
	noColor bool,
	inputTTY bool,
	outputTTY bool,
	term string,
) bool {
	return visible &&
		!accessible &&
		!noColor &&
		inputTTY &&
		outputTTY &&
		term != "" &&
		!strings.EqualFold(term, "dumb")
}

func (model wizardPreflightModel) tickCommand() tea.Cmd {
	if model.options.Tick != nil {
		return model.options.Tick()
	}
	return wizardPreflightTick()
}

func runWizardPreflight(
	ctx context.Context,
	discovery interactiveDiscovery,
	stdin io.Reader,
	stderr io.Writer,
	options wizardPreflightOptions,
) (interactiveContextCatalog, error) {
	if discovery == nil {
		return interactiveContextCatalog{}, errors.New("interactive setup is unavailable")
	}
	if !options.Interactive {
		contexts, err := discovery.Contexts(ctx)
		if err != nil {
			return interactiveContextCatalog{}, concisePreflightError(err)
		}
		if len(contexts) == 0 {
			return interactiveContextCatalog{}, errors.New("no kubeconfig contexts found")
		}
		current, currentErr := discovery.CurrentContext(ctx)
		catalog := interactiveContextCatalog{Names: contexts}
		if currentErr == nil && containsString(contexts, terminalLine(current)) {
			catalog.Current = terminalLine(current)
		}
		if options.Visible {
			_, _ = fmt.Fprintln(stderr, "[ok] kubectl ready")
			_, _ = fmt.Fprintf(
				stderr,
				"[ok] %d %s found\n",
				len(contexts),
				plural(len(contexts), "kubeconfig context", "kubeconfig contexts"),
			)
			if catalog.Current != "" {
				_, _ = fmt.Fprintln(stderr, "[ok] current context identified")
			} else {
				_, _ = fmt.Fprintln(stderr, "[!] current context not identified")
			}
		}
		return catalog, nil
	}
	model := newWizardPreflightModel(ctx, discovery, options)
	program := tea.NewProgram(
		model,
		tea.WithInput(stdin),
		tea.WithOutput(stderr),
		tea.WithoutSignalHandler(),
	)
	result, err := program.Run()
	if err != nil {
		return interactiveContextCatalog{}, errors.New("setup display failed")
	}
	finalModel, ok := result.(wizardPreflightModel)
	if !ok {
		return interactiveContextCatalog{}, errors.New("setup display failed")
	}
	if finalModel.err != nil {
		return interactiveContextCatalog{}, finalModel.err
	}
	return finalModel.catalog, nil
}

func concisePreflightError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return errors.New("unable to read kubeconfig contexts; check kubectl and kubeconfig settings")
}

func runWizardNamespaceDiscovery(
	ctx context.Context,
	discovery interactiveDiscovery,
	kubeContext string,
	stderr io.Writer,
	visible bool,
	explicitNamespaceCount int,
) ([]string, error) {
	if !visible {
		return discovery.Namespaces(ctx, kubeContext)
	}
	accessible := os.Getenv("ACCESSIBLE") != ""
	if accessible || !terminalWriter(stderr) {
		_, _ = fmt.Fprintln(stderr, "[>] Checking read-only access...")
		namespaces, err := discovery.Namespaces(ctx, kubeContext)
		if err != nil {
			if errors.Is(err, errNamespaceDiscoveryForbidden) &&
				explicitNamespaceCount > 0 {
				_, _ = fmt.Fprintf(
					stderr,
					"[!] Read-only access available through the provided %s.\n",
					plural(
						explicitNamespaceCount,
						"namespace",
						"namespaces",
					),
				)
				return nil, err
			}
			_, _ = fmt.Fprintln(stderr, "[x] Read-only access check failed.")
			return nil, err
		}
		_, _ = fmt.Fprintln(stderr, "[ok] Read-only access confirmed.")
		return namespaces, nil
	}
	renderer := newCLIProgressRenderer(stderr, true)
	renderer.Update(progressUpdate{
		ID: "wizard.namespaces", Label: "Checking read-only access", Status: progressActive,
	})
	namespaces, err := discovery.Namespaces(ctx, kubeContext)
	if err != nil {
		if errors.Is(err, errNamespaceDiscoveryForbidden) &&
			explicitNamespaceCount > 0 {
			renderer.Update(progressUpdate{
				ID: "wizard.namespaces",
				Label: fmt.Sprintf(
					"Read-only access available through the provided %s",
					plural(
						explicitNamespaceCount,
						"namespace",
						"namespaces",
					),
				),
				Status: progressWarning,
			})
			closeProgress(renderer, stderr)
			return nil, err
		}
		renderer.Update(progressUpdate{
			ID: "wizard.namespaces", Label: "Read-only access", Status: progressFailed,
		})
		closeProgress(renderer, stderr)
		return nil, err
	}
	renderer.Update(progressUpdate{
		ID: "wizard.namespaces", Label: "Read-only access confirmed", Status: progressCompleted,
	})
	closeProgress(renderer, stderr)
	return namespaces, nil
}
