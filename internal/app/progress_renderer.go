package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

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
}

// progressRenderer owns serialized routine progress and its optional heartbeat.
type progressRenderer struct {
	mu          sync.Mutex
	writer      io.Writer
	enabled     bool
	interactive bool
	mascot      bool
	frame       int
	animated    bool
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
}

func newProgressRenderer(options progressRendererOptions) *progressRenderer {
	return &progressRenderer{
		writer:      options.Writer,
		enabled:     options.Enabled && options.Writer != nil,
		interactive: options.Enabled && options.Interactive && options.Writer != nil,
		mascot:      options.Enabled && options.Interactive && options.Mascot,
	}
}

func newCLIProgressRenderer(
	writer io.Writer,
	enabled bool,
	mascot bool,
) *progressRenderer {
	renderer := newProgressRenderer(progressRendererOptions{
		Writer:      writer,
		Enabled:     enabled,
		Interactive: terminalWriter(writer),
		Mascot:      mascot,
	})
	renderer.Start()
	return renderer
}

// Start begins the interactive heartbeat. Non-interactive renderers remain synchronous.
func (renderer *progressRenderer) Start() {
	if renderer == nil || !renderer.interactive || renderer.stop != nil {
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
	_, _ = fmt.Fprintln(renderer.writer, message)
}

// Step renders exactly one interactive frame and is deterministic for tests.
func (renderer *progressRenderer) Step() {
	if renderer == nil || !renderer.interactive {
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
	_, _ = fmt.Fprintf(renderer.writer, "\r%s Qodo Scout is working", frame)
	renderer.animated = true
}

// Close synchronously stops and clears the heartbeat. It is safe to call repeatedly.
func (renderer *progressRenderer) Close() {
	if renderer == nil {
		return
	}
	renderer.closeOnce.Do(func() {
		if renderer.stop != nil {
			close(renderer.stop)
			<-renderer.done
		}
		renderer.mu.Lock()
		defer renderer.mu.Unlock()
		renderer.clearLocked()
	})
}

func (renderer *progressRenderer) clearLocked() {
	if renderer.interactive && renderer.animated {
		_, _ = io.WriteString(renderer.writer, progressClearLine)
		renderer.animated = false
	}
}

func terminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func terminalLine(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	return strings.TrimSpace(value)
}
