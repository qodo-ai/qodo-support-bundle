package kubernetes

import (
	"bytes"
	"strings"
	"time"
)

func filterLog(
	input []byte,
	correlationIDs []string,
	since time.Time,
	until time.Time,
	contextLines int,
) ([]byte, int) {
	lines := bytes.Split(input, []byte("\n"))
	eligible := make([]bool, len(lines))
	for index, line := range lines {
		eligible[index] = logLineInWindow(line, since, until)
	}
	if len(correlationIDs) == 0 {
		return joinSelectedLogLines(lines, eligible), 0
	}
	if contextLines < 0 {
		contextLines = 0
	}
	selected := make([]bool, len(lines))
	matchedLines := 0
	for index, line := range lines {
		if !eligible[index] || !containsCorrelationID(line, correlationIDs) {
			continue
		}
		matchedLines++
		start := max(0, index-contextLines)
		end := min(len(lines)-1, index+contextLines)
		for contextIndex := start; contextIndex <= end; contextIndex++ {
			if eligible[contextIndex] {
				selected[contextIndex] = true
			}
		}
	}
	return joinSelectedLogLines(lines, selected), matchedLines
}

func logLineInWindow(line []byte, since time.Time, until time.Time) bool {
	fields := bytes.Fields(line)
	if len(fields) == 0 {
		return true
	}
	timestamp, err := time.Parse(time.RFC3339Nano, string(fields[0]))
	if err != nil {
		return true
	}
	if !since.IsZero() && timestamp.Before(since) {
		return false
	}
	return until.IsZero() || !timestamp.After(until)
}

func containsCorrelationID(line []byte, correlationIDs []string) bool {
	text := string(line)
	for _, correlationID := range correlationIDs {
		if correlationID != "" && strings.Contains(text, correlationID) {
			return true
		}
	}
	return false
}

func joinSelectedLogLines(lines [][]byte, selected []bool) []byte {
	var output bytes.Buffer
	for index, line := range lines {
		if !selected[index] || (index == len(lines)-1 && len(line) == 0) {
			continue
		}
		output.Write(line)
		output.WriteByte('\n')
	}
	return output.Bytes()
}
