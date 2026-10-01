package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type progressModelOptions struct {
	Mascot  bool
	Unicode bool
	Width   int
	Started time.Time
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

type progressModel struct {
	mascot     bool
	unicode    bool
	width      int
	startedAt  time.Time
	stages     map[string]progressStageState
	stageOrder []string
	frame      int
	summary    *progressSummary
	finishedAt time.Time
}

func newProgressModel(options progressModelOptions) progressModel {
	started := options.Started
	if started.IsZero() {
		started = time.Now()
	}
	return progressModel{
		mascot:    options.Mascot,
		unicode:   options.Unicode,
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
		summary := message.Summary
		summary.ArchivePath = terminalLine(summary.ArchivePath)
		model.summary = &summary
		model.finishedAt = message.At
		if model.finishedAt.IsZero() {
			model.finishedAt = time.Now()
		}
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
	if model.summary != nil {
		lines = append(lines, "Qodo Scout summary")
		for _, id := range model.stageOrder {
			state := model.stages[id]
			lines = append(lines, model.formatUpdate(state.update, state.elapsed))
		}
		lines = append(
			lines,
			"Total duration: "+
				formatProgressDuration(max(model.finishedAt.Sub(model.startedAt), 0)),
		)
		if model.summary.ArchivePath != "" {
			archive := "Archive: " + model.summary.ArchivePath
			if model.summary.ArchiveSize >= 0 {
				archive += " (" + formatProgressBytes(model.summary.ArchiveSize) + ")"
			}
			lines = append(lines, archive)
		}
		lines = append(
			lines,
			"Saved locally. Share separately through an approved support channel.",
		)
	} else {
		lines = append(lines, "Qodo Scout interactive display")
		for _, id := range model.stageOrder {
			state := model.stages[id]
			lines = append(lines, model.formatUpdate(state.update, state.elapsed))
		}
		lines = append(lines, model.activityLine())
	}
	for index, line := range lines {
		if model.width > 0 {
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
	if len(details) > 0 {
		line += " - " + strings.Join(details, ", ")
	}
	if update.Status != progressActive && elapsed >= 100*time.Millisecond {
		line += " (" + formatProgressDuration(elapsed) + ")"
	}
	return line
}

func (model progressModel) activityLine() string {
	frames := spinnerFrames
	if model.mascot {
		frames = mascotFrames
	}
	return frames[model.frame%len(frames)] + " Qodo Scout is working"
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
