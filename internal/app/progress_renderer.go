package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const (
	progressHeartbeatInterval = 250 * time.Millisecond
	progressClearLine         = "\r                              \r"
)

var (
	spinnerFrames = []string{"|", "/", "-", `\`}
	mascotFrames  = []string{`~(____:>`, `-(____:>`}
)

type progressRendererOptions struct {
	Writer      io.Writer
	Enabled     bool
	Interactive bool
	Mascot      bool
	Unicode     bool
	Width       int
	Now         func() time.Time
	BubbleTea   bool
}

type progressStatus string

const (
	progressActive    progressStatus = "active"
	progressCompleted progressStatus = "completed"
	progressWarning   progressStatus = "warning"
	progressFailed    progressStatus = "failed"
)

type progressUpdate struct {
	ID      string
	Label   string
	Detail  string
	Unit    string
	Level   int
	Current int
	Total   int
	Status  progressStatus
}

type progressSummary struct {
	ArchivePath string
	ArchiveSize int64
}

type progressStageState struct {
	update    progressUpdate
	startedAt time.Time
	elapsed   time.Duration
}

// progressRenderer owns serialized routine progress and its optional heartbeat.
type progressRenderer struct {
	mu          sync.Mutex
	writer      io.Writer
	enabled     bool
	interactive bool
	mascot      bool
	unicode     bool
	width       int
	now         func() time.Time
	startedAt   time.Time
	stages      map[string]progressStageState
	stageOrder  []string
	frame       int
	animated    bool
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	bubbleTea   bool
	program     *tea.Program
	programDone chan struct{}
	programErr  error
}

func newProgressRenderer(options progressRendererOptions) *progressRenderer {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &progressRenderer{
		writer:      options.Writer,
		enabled:     options.Enabled && options.Writer != nil,
		interactive: options.Enabled && options.Interactive && options.Writer != nil,
		mascot:      options.Enabled && options.Interactive && options.Mascot,
		unicode:     options.Enabled && options.Interactive && options.Unicode,
		width:       max(options.Width, 0),
		now:         now,
		startedAt:   now(),
		stages:      make(map[string]progressStageState),
		bubbleTea:   options.BubbleTea,
	}
}

func newCLIProgressRenderer(
	writer io.Writer,
	enabled bool,
	mascot bool,
) *progressRenderer {
	interactive := terminalWriter(writer)
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      writer,
		Enabled:     enabled,
		Interactive: interactive,
		Mascot:      mascot,
		Unicode:     interactive && terminalUnicode(),
		Width:       terminalWidth(writer),
		BubbleTea:   interactive,
	})
	renderer.Start()
	return renderer
}

// Start begins the interactive heartbeat. Non-interactive renderers remain synchronous.
func (renderer *progressRenderer) Start() {
	if renderer == nil ||
		!renderer.interactive ||
		renderer.stop != nil ||
		renderer.program != nil {
		return
	}
	if renderer.bubbleTea {
		renderer.program = tea.NewProgram(
			newProgressModel(progressModelOptions{
				Mascot:  renderer.mascot,
				Unicode: renderer.unicode,
				Width:   renderer.width,
				Started: renderer.startedAt,
			}),
			tea.WithInput(nil),
			tea.WithOutput(renderer.writer),
			tea.WithoutSignalHandler(),
		)
		renderer.programDone = make(chan struct{})
		go func() {
			defer close(renderer.programDone)
			_, err := renderer.program.Run()
			renderer.mu.Lock()
			renderer.programErr = err
			renderer.mu.Unlock()
		}()
		return
	}
	renderer.stop = make(chan struct{})
	renderer.done = make(chan struct{})
	ticker := time.NewTicker(progressHeartbeatInterval)
	go func() {
		defer close(renderer.done)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				renderer.Step()
			case <-renderer.stop:
				return
			}
		}
	}()
}

// Update records one canonical stage and renders its latest state.
func (renderer *progressRenderer) Update(update progressUpdate) {
	if renderer == nil || !renderer.enabled {
		return
	}
	update.ID = terminalLine(update.ID)
	update.Label = terminalLine(update.Label)
	update.Detail = terminalLine(update.Detail)
	update.Unit = terminalLine(update.Unit)
	if update.ID == "" || update.Label == "" {
		return
	}
	if renderer.bubbleTea {
		renderer.program.Send(progressUpdateMsg{Update: update, At: renderer.now()})
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.clearLocked()

	now := renderer.now()
	state, exists := renderer.stages[update.ID]
	if !exists {
		renderer.stageOrder = append(renderer.stageOrder, update.ID)
	}
	if update.Status == progressActive && state.startedAt.IsZero() {
		state.startedAt = now
	}
	if update.Status != progressActive && !state.startedAt.IsZero() {
		state.elapsed = max(now.Sub(state.startedAt), 0)
	}
	state.update = update
	renderer.stages[update.ID] = state
	renderer.writeLineLocked(renderer.formatUpdate(update, state.elapsed))
}

// Summary renders outcomes retained by the renderer plus local archive details.
func (renderer *progressRenderer) Summary(summary progressSummary) {
	if renderer == nil || !renderer.enabled {
		return
	}
	summary.ArchivePath = terminalLine(summary.ArchivePath)
	if renderer.bubbleTea {
		renderer.program.Send(progressSummaryMsg{Summary: summary, At: renderer.now()})
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.clearLocked()
	renderer.writeLineLocked("Qodo Scout summary")
	for _, id := range renderer.stageOrder {
		state := renderer.stages[id]
		if state.update.Level != 1 {
			continue
		}
		renderer.writeLineLocked(renderer.formatUpdate(state.update, state.elapsed))
	}
	renderer.writeLineLocked(
		"Total duration: " + formatProgressDuration(max(renderer.now().Sub(renderer.startedAt), 0)),
	)
	if summary.ArchivePath != "" {
		archive := "Archive: " + summary.ArchivePath
		if summary.ArchiveSize >= 0 {
			archive += " (" + formatProgressBytes(summary.ArchiveSize) + ")"
		}
		renderer.writeLineLocked(archive)
	}
	renderer.writeLineLocked(
		"Saved locally. Share separately through an approved support channel.",
	)
}

// Stage sanitizes messages and replaces any active frame before presenting them.
func (renderer *progressRenderer) Stage(_ string, message string) {
	if renderer == nil || !renderer.enabled {
		return
	}
	message = terminalLine(message)
	if message == "" {
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.clearLocked()
	renderer.writeLineLocked(message)
}

// Step renders exactly one interactive frame and is deterministic for tests.
func (renderer *progressRenderer) Step() {
	if renderer == nil || !renderer.interactive {
		return
	}
	if renderer.bubbleTea {
		renderer.program.Send(progressTickMsg{})
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	frames := spinnerFrames
	if renderer.mascot {
		frames = mascotFrames
	}
	frame := frames[renderer.frame%len(frames)]
	renderer.frame++
	line := frame + " Qodo Scout is working"
	if renderer.width > 0 {
		if renderer.width <= 1 {
			return
		}
		line = fitTerminalLine(line, renderer.width-1, renderer.unicode)
	}
	_, _ = fmt.Fprintf(renderer.writer, "\r%s", line)
	renderer.animated = true
}

// Close synchronously stops and clears the heartbeat. It is safe to call repeatedly.
func (renderer *progressRenderer) Close() error {
	if renderer == nil {
		return nil
	}
	renderer.closeOnce.Do(func() {
		if renderer.bubbleTea && renderer.program != nil {
			renderer.program.Send(progressQuitMsg{})
			<-renderer.programDone
			return
		}
		if renderer.stop != nil {
			close(renderer.stop)
			<-renderer.done
		}
		renderer.mu.Lock()
		defer renderer.mu.Unlock()
		renderer.clearLocked()
	})
	return renderer.Err()
}

func (renderer *progressRenderer) Err() error {
	if renderer == nil {
		return nil
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	return renderer.programErr
}

func closeProgress(renderer *progressRenderer, stderr io.Writer) {
	if err := renderer.Close(); err != nil {
		_, _ = fmt.Fprintln(stderr, "Qodo Scout interactive display stopped unexpectedly.")
	}
}

func (renderer *progressRenderer) clearLocked() {
	if renderer.interactive && renderer.animated {
		clearLine := progressClearLine
		if renderer.width > 0 {
			clearLine = "\r" + strings.Repeat(" ", max(renderer.width-1, 0)) + "\r"
		}
		_, _ = io.WriteString(renderer.writer, clearLine)
		renderer.animated = false
	}
}

func (renderer *progressRenderer) writeLineLocked(line string) {
	if renderer.interactive && renderer.width > 0 {
		line = fitTerminalLine(line, renderer.width, renderer.unicode)
	}
	_, _ = fmt.Fprintln(renderer.writer, line)
}

func (renderer *progressRenderer) formatUpdate(
	update progressUpdate,
	elapsed time.Duration,
) string {
	line := strings.Repeat("  ", max(update.Level, 0)) +
		renderer.statusMarker(update.Status) + " " + update.Label
	details := make([]string, 0, 2)
	if update.Total > 0 && update.Current >= 0 {
		count := fmt.Sprintf("%d/%d", update.Current, update.Total)
		if update.Unit != "" {
			count += " " + update.Unit
		}
		details = append(details, count)
	}
	if update.Detail != "" {
		details = append(details, update.Detail)
	}
	if len(details) > 0 {
		line += " - " + strings.Join(details, ", ")
	}
	if update.Status != progressActive && elapsed >= 100*time.Millisecond {
		line += " (" + formatProgressDuration(elapsed) + ")"
	}
	return line
}

func (renderer *progressRenderer) statusMarker(status progressStatus) string {
	if !renderer.interactive {
		switch status {
		case progressCompleted:
			return "[done]"
		case progressWarning:
			return "[warning]"
		case progressFailed:
			return "[failed]"
		default:
			return "[active]"
		}
	}
	if renderer.unicode {
		switch status {
		case progressCompleted:
			return "✓"
		case progressWarning:
			return "!"
		case progressFailed:
			return "✗"
		default:
			return "●"
		}
	}
	switch status {
	case progressCompleted:
		return "[ok]"
	case progressWarning:
		return "[!]"
	case progressFailed:
		return "[x]"
	default:
		return "[>]"
	}
}

func terminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func terminalWidth(writer io.Writer) int {
	file, ok := writer.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return 0
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return 0
	}
	return width
}

func terminalUnicode() bool {
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	locale := os.Getenv("LC_ALL")
	if locale == "" {
		locale = os.Getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	locale = strings.ToLower(locale)
	return strings.Contains(locale, "utf-8") || strings.Contains(locale, "utf8")
}

func fitTerminalLine(value string, width int, unicode bool) string {
	if width <= 0 || terminalDisplayWidth(value) <= width {
		return value
	}
	suffix := "..."
	if unicode {
		suffix = "…"
	}
	suffixWidth := terminalDisplayWidth(suffix)
	if width <= suffixWidth {
		return strings.Repeat(".", width)
	}
	target := width - suffixWidth
	var fitted strings.Builder
	used := 0
	for _, character := range value {
		characterWidth := terminalRuneWidth(character)
		if used+characterWidth > target {
			break
		}
		fitted.WriteRune(character)
		used += characterWidth
	}
	return fitted.String() + suffix
}

func terminalDisplayWidth(value string) int {
	width := 0
	for _, character := range value {
		width += terminalRuneWidth(character)
	}
	return width
}

func terminalRuneWidth(character rune) int {
	if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) {
		return 0
	}
	if character >= 0x1100 &&
		(character <= 0x115f ||
			character == 0x2329 ||
			character == 0x232a ||
			(character >= 0x2e80 && character <= 0xa4cf) ||
			(character >= 0xac00 && character <= 0xd7a3) ||
			(character >= 0xf900 && character <= 0xfaff) ||
			(character >= 0xfe10 && character <= 0xfe19) ||
			(character >= 0xfe30 && character <= 0xfe6f) ||
			(character >= 0xff00 && character <= 0xff60) ||
			(character >= 0xffe0 && character <= 0xffe6) ||
			(character >= 0x1f300 && character <= 0x1faff) ||
			(character >= 0x20000 && character <= 0x3fffd)) {
		return 2
	}
	return 1
}

func formatProgressDuration(duration time.Duration) string {
	if duration <= 0 {
		return "0s"
	}
	return duration.Round(100 * time.Millisecond).String()
}

func formatProgressBytes(size int64) string {
	const (
		kib = 1 << 10
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case size >= gib:
		return fmt.Sprintf("%.1f GiB", float64(size)/gib)
	case size >= mib:
		return fmt.Sprintf("%.1f MiB", float64(size)/mib)
	case size >= kib:
		return fmt.Sprintf("%.1f KiB", float64(size)/kib)
	default:
		return fmt.Sprintf("%d B", size)
	}
}

func terminalLine(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Cs, character) ||
			unicode.Is(unicode.Zl, character) ||
			unicode.Is(unicode.Zp, character) {
			return ' '
		}
		return character
	}, value)
	return strings.TrimSpace(value)
}
