package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type progressModelOptions struct {
	Unicode   bool
	Hyperlink bool
	Width     int
	Started   time.Time
}

type progressUpdateMsg struct {
	Update progressUpdate
	At     time.Time
}

type progressSummaryMsg struct {
	Summary progressSummary
	At      time.Time
}

type progressTickMsg struct{}
type progressQuitMsg struct{}
type progressCanceledMsg struct{}

type progressModel struct {
	unicode    bool
	hyperlink  bool
	width      int
	startedAt  time.Time
	stages     map[string]progressStageState
	stageOrder []string
	frame      int
	summary    *progressSummary
	canceled   bool
	finishedAt time.Time
}

func newProgressModel(options progressModelOptions) progressModel {
	started := options.Started
	if started.IsZero() {
		started = time.Now()
	}
	return progressModel{
		unicode:   options.Unicode,
		hyperlink: options.Hyperlink,
		width:     max(options.Width, 0),
		startedAt: started,
		stages:    make(map[string]progressStageState),
	}
}

func (model progressModel) Init() tea.Cmd {
	return progressTick()
}

func (model progressModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case progressUpdateMsg:
		update := sanitizeProgressUpdate(message.Update)
		if update.ID == "" || update.Label == "" {
			return model, nil
		}
		at := message.At
		if at.IsZero() {
			at = time.Now()
		}
		state, exists := model.stages[update.ID]
		if !exists {
			model.stageOrder = append(model.stageOrder, update.ID)
		}
		if update.Status == progressActive && state.startedAt.IsZero() {
			state.startedAt = at
		}
		if update.Status != progressActive && !state.startedAt.IsZero() {
			state.elapsed = max(at.Sub(state.startedAt), 0)
		}
		state.update = update
		model.stages[update.ID] = state
		return model, nil
	case progressSummaryMsg:
		summary := sanitizeProgressSummary(message.Summary)
		model.summary = &summary
		model.finishedAt = message.At
		if model.finishedAt.IsZero() {
			model.finishedAt = time.Now()
		}
		return model, nil
	case progressCanceledMsg:
		model.canceled = true
		return model, nil
	case progressTickMsg:
		model.frame++
		return model, progressTick()
	case tea.WindowSizeMsg:
		model.width = max(message.Width, 0)
		return model, nil
	case progressQuitMsg:
		return model, tea.Quit
	default:
		return model, nil
	}
}

func (model progressModel) View() string {
	lines := make([]string, 0, len(model.stageOrder)+2)
	if model.canceled {
		marker, separator := "[!]", " | "
		if model.unicode {
			marker, separator = "!", " · "
		}
		line := marker + " Canceled"
		if state, ok := model.stages["kubernetes.logs"]; ok &&
			state.update.Status == progressActive &&
			state.update.Total > 0 {
			line = fmt.Sprintf(
				"%s Canceled while collecting logs%s%d/%d complete",
				marker,
				separator,
				state.update.Current,
				state.update.Total,
			)
		}
		lines = append(lines, line, "No bundle created.")
	} else if model.summary != nil {
		lines = append(
			lines,
			progressSummaryLines(
				*model.summary,
				max(model.finishedAt.Sub(model.startedAt), 0),
				model.unicode,
			)...,
		)
		if model.hyperlink && model.summary.ArchivePath != "" {
			for index, line := range lines {
				if isProgressArchivePathLine(line) {
					lines[index] = archivePathLine(model.summary.ArchivePath, true)
				}
			}
		}
	} else {
		lines = append(lines, "Qodo Scout interactive display")
		for _, id := range model.stageOrder {
			state := model.stages[id]
			lines = append(lines, model.formatUpdate(state.update, state.elapsed))
		}
		lines = append(lines, model.activityLine())
	}
	for index, line := range lines {
		if model.width > 0 && !isProgressArchivePathLine(line) {
			lines[index] = fitTerminalLine(line, model.width, model.unicode)
		}
	}
	return strings.Join(lines, "\n")
}

func (model progressModel) formatUpdate(
	update progressUpdate,
	elapsed time.Duration,
) string {
	line := strings.Repeat("  ", max(update.Level, 0)) +
		interactiveStatusMarker(update.Status, model.unicode) + " " + update.Label
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
	if model.unicode {
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

func (model progressModel) activityLine() string {
	frame := scannerFrame(model.frame, model.unicode)
	for index := len(model.stageOrder) - 1; index >= 0; index-- {
		id := model.stageOrder[index]
		if id == "collection" {
			continue
		}
		state := model.stages[id]
		if state.update.Status == progressActive {
			return progressActivityLine(frame, state.update, model.unicode)
		}
	}
	return frame + " Qodo Scout is working"
}

func progressActivityLine(frame string, update progressUpdate, unicode bool) string {
	line := frame + "  Scout is " + progressActivityDescription(update)
	if update.Total > 0 && update.Current >= 0 {
		separator := " | "
		if unicode {
			separator = " · "
		}
		line += separator + fmt.Sprintf("%d/%d", update.Current, update.Total)
	}
	return line
}

func progressActivityDescription(update progressUpdate) string {
	switch update.ID {
	case "preflight":
		return "checking read-only cluster access"
	case "kubernetes":
		return "collecting read-only Kubernetes data"
	case "kubernetes.discovery":
		return "finding namespaces"
	case "kubernetes.scan":
		return "reading namespace resources"
	case "kubernetes.logs":
		return "collecting container logs"
	case "workload":
		return "collecting workload and service context"
	case "prometheus":
		return "collecting Prometheus metrics"
	case "phoenix":
		return "collecting Phoenix traces"
	case "zitadel":
		return "checking Zitadel connectivity"
	case "archive":
		return "preparing redacted archive"
	}
	label := update.Label
	if label == "" {
		return "working"
	}
	characters := []rune(label)
	characters[0] = []rune(strings.ToLower(string(characters[0])))[0]
	return string(characters)
}

func progressTick() tea.Cmd {
	return tea.Tick(progressHeartbeatInterval, func(time.Time) tea.Msg {
		return progressTickMsg{}
	})
}

func sanitizeProgressUpdate(update progressUpdate) progressUpdate {
	update.ID = terminalLine(update.ID)
	update.Label = terminalLine(update.Label)
	update.Detail = terminalLine(update.Detail)
	update.Unit = terminalLine(update.Unit)
	return update
}

func interactiveStatusMarker(status progressStatus, unicode bool) string {
	if unicode {
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
