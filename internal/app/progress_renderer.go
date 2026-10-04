package app

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

const (
	progressHeartbeatInterval = 250 * time.Millisecond
	progressClearLine         = "\r                              \r"
	scannerFrameCount         = 8
	scannerTrackWidth         = 10
)

type progressRendererOptions struct {
	Writer      io.Writer
	Enabled     bool
	Interactive bool
	Unicode     bool
	Hyperlink   bool
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
	ArchivePath    string
	ArchiveSize    int64
	Namespaces     int
	Pods           int
	LogStreams     int
	WarningCount   int
	SourceOutcomes []progressSummaryOutcome
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
	unicode     bool
	hyperlink   bool
	width       int
	now         func() time.Time
	startedAt   time.Time
	stages      map[string]progressStageState
	pending     map[string]progressUpdate
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
		unicode:     options.Enabled && options.Interactive && options.Unicode,
		hyperlink:   options.Enabled && options.Interactive && options.Hyperlink,
		width:       max(options.Width, 0),
		now:         now,
		startedAt:   now(),
		stages:      make(map[string]progressStageState),
		pending:     make(map[string]progressUpdate),
		bubbleTea:   options.BubbleTea,
	}
}

// Pending holds an ambiguous terminal update until its final outcome is known.
func (renderer *progressRenderer) Pending(update progressUpdate) {
	if renderer == nil || !renderer.enabled {
		return
	}
	update = sanitizeProgressUpdate(update)
	if update.ID == "" || update.Label == "" {
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.pending[update.ID] = update
}

func (renderer *progressRenderer) ResolvePending(id string) {
	if renderer == nil || !renderer.enabled {
		return
	}
	renderer.mu.Lock()
	update, exists := renderer.pending[id]
	delete(renderer.pending, id)
	renderer.mu.Unlock()
	if exists {
		renderer.Update(update)
	}
}

// Cancel replaces an ambiguous log outcome with an explicit no-bundle result.
func (renderer *progressRenderer) Cancel() {
	if renderer == nil || renderer.writer == nil {
		return
	}
	if renderer.bubbleTea && renderer.program != nil {
		renderer.program.Send(progressCanceledMsg{})
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.clearLocked()
	update, exists := renderer.pending["kubernetes.logs"]
	logCancellation := exists
	if !exists {
		if state, ok := renderer.stages["kubernetes.logs"]; ok {
			update = state.update
			exists = true
			logCancellation = update.Status == progressActive
		}
	}
	delete(renderer.pending, "kubernetes.logs")
	marker, separator := "[!]", " | "
	if renderer.interactive && renderer.unicode {
		marker, separator = "!", " · "
	}
	line := marker + " Canceled"
	if logCancellation && exists && update.Total > 0 {
		line = fmt.Sprintf(
			"%s Canceled while collecting logs%s%d/%d complete",
			marker,
			separator,
			update.Current,
			update.Total,
		)
	}
	renderer.writeLineLocked(line)
	renderer.writeLineLocked("No bundle created.")
}

func newCLIProgressRenderer(
	writer io.Writer,
	enabled bool,
) *progressRenderer {
	interactive := terminalWriter(writer)
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      writer,
		Enabled:     enabled,
		Interactive: interactive,
		Unicode:     interactive && terminalUnicode(),
		Hyperlink:   terminalHyperlinksEnabled(interactive),
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
				Unicode:   renderer.unicode,
				Hyperlink: renderer.hyperlink,
				Width:     renderer.width,
				Started:   renderer.startedAt,
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
	summary = sanitizeProgressSummary(summary)
	if renderer.bubbleTea {
		renderer.program.Send(progressSummaryMsg{Summary: summary, At: renderer.now()})
		return
	}
	renderer.mu.Lock()
	defer renderer.mu.Unlock()
	renderer.clearLocked()
	for _, line := range progressSummaryLines(
		summary,
		max(renderer.now().Sub(renderer.startedAt), 0),
		renderer.unicode,
	) {
		if renderer.hyperlink && isProgressArchivePathLine(line) {
			line = archivePathLine(summary.ArchivePath, true)
		}
		renderer.writeLineLocked(line)
	}
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
	frame := scannerFrame(renderer.frame, renderer.unicode)
	renderer.frame++
	line := frame + " Qodo Scout is working"
	for index := len(renderer.stageOrder) - 1; index >= 0; index-- {
		id := renderer.stageOrder[index]
		if id == "collection" {
			continue
		}
		state := renderer.stages[id]
		if state.update.Status == progressActive {
			line = progressActivityLine(frame, state.update, renderer.unicode)
			break
		}
	}
	if renderer.width > 0 {
		if renderer.width <= 1 {
			return
		}
		line = fitTerminalLine(line, renderer.width-1, renderer.unicode)
	}
	_, _ = fmt.Fprintf(renderer.writer, "\r%s", line)
	renderer.animated = true
}

func scannerFrame(index int, unicode bool) string {
	positions := [...]int{0, 2, 4, 6, 8, 6, 4, 2}
	point := positions[index%scannerFrameCount]
	if !unicode {
		cells := make([]byte, scannerTrackWidth)
		for cell := range cells {
			cells[cell] = ' '
		}
		for cell := 0; cell < point; cell++ {
			cells[cell] = '-'
		}
		cells[point] = '>'
		return "[" + string(cells) + "]"
	}
	cells := make([]string, scannerTrackWidth)
	for cell := range cells {
		cells[cell] = " "
	}
	for offset := -1; offset <= 1; offset++ {
		cell := point + offset
		if cell < 0 || cell >= len(cells) {
			continue
		}
		if offset == 0 {
			cells[cell] = "●"
		} else {
			cells[cell] = "━"
		}
	}
	return "[" + strings.Join(cells, "") + "]"
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
	if renderer.interactive &&
		renderer.width > 0 &&
		!isProgressArchivePathLine(line) {
		line = fitTerminalLine(line, renderer.width, renderer.unicode)
	}
	_, _ = fmt.Fprintln(renderer.writer, line)
}

func isProgressArchivePathLine(line string) bool {
	return strings.HasPrefix(line, "Bundle saved: ")
}

func archivePathLine(path string, hyperlink bool) string {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		absolutePath = path
	}
	visible := terminalLine(absolutePath)
	if !hyperlink || visible == "" {
		return "Bundle saved: " + visible
	}
	target := (&url.URL{Scheme: "file", Path: visible}).String()
	return "Bundle saved: \x1b]8;;" + target + "\x1b\\" +
		visible + "\x1b]8;;\x1b\\"
}

func terminalHyperlinksEnabled(interactive bool) bool {
	if !interactive ||
		os.Getenv("ACCESSIBLE") != "" ||
		os.Getenv("NO_COLOR") != "" ||
		strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	switch strings.ToLower(os.Getenv("TERM_PROGRAM")) {
	case "vscode", "iterm.app", "wezterm", "ghostty":
		return true
	}
	return strings.HasPrefix(strings.ToLower(os.Getenv("TERM")), "xterm-kitty") ||
		os.Getenv("WT_SESSION") != ""
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
	separator := " | "
	if renderer.interactive && renderer.unicode {
		separator = " · "
	}
	if len(details) > 0 {
		line += separator + strings.Join(details, separator)
	}
	if update.Status != progressActive && elapsed >= 100*time.Millisecond {
		line += separator + formatProgressDuration(elapsed)
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
	if os.Getenv("ACCESSIBLE") != "" {
		return false
	}
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
	return ansi.Truncate(value, target, "") + suffix
}

func terminalDisplayWidth(value string) int {
	return ansi.StringWidth(value)
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
