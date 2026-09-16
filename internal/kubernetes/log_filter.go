package kubernetes

import (
	"bytes"
	"strings"
	"time"
)

type indexedLogLine struct {
	index    int
	line     []byte
	eligible bool
}

func filterLog(
	input []byte,
	correlationIDs []string,
	since time.Time,
	until time.Time,
	contextLines int,
) ([]byte, int) {
	if contextLines < 0 {
		contextLines = 0
	}
	var output bytes.Buffer
	previous := make([]indexedLogLine, 0, contextLines)
	remainingAfter := 0
	lastWritten := -1
	matchedLines := 0
	forEachLogLine(input, func(index int, line []byte) {
		eligible := logLineInWindow(line, since, until)
		if len(correlationIDs) == 0 {
			if eligible {
				writeLogLine(&output, line)
			}
			return
		}
		matched := eligible && containsCorrelationID(line, correlationIDs)
		if matched {
			matchedLines++
			for _, candidate := range previous {
				if candidate.eligible && candidate.index > lastWritten {
					writeLogLine(&output, candidate.line)
					lastWritten = candidate.index
				}
			}
			if index > lastWritten {
				writeLogLine(&output, line)
				lastWritten = index
			}
			remainingAfter = contextLines
		} else if remainingAfter > 0 {
			if eligible && index > lastWritten {
				writeLogLine(&output, line)
				lastWritten = index
			}
			remainingAfter--
		}
		if contextLines > 0 {
			if len(previous) == contextLines {
				copy(previous, previous[1:])
				previous = previous[:contextLines-1]
			}
			previous = append(previous, indexedLogLine{
				index:    index,
				line:     line,
				eligible: eligible,
			})
		}
	})
	return output.Bytes(), matchedLines
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

func writeLogLine(output *bytes.Buffer, line []byte) {
	if len(line) > 0 {
		output.Write(line)
	}
	output.WriteByte('\n')
}

func forEachLogLine(input []byte, visit func(index int, line []byte)) {
	index := 0
	for len(input) > 0 {
		lineEnd := bytes.IndexByte(input, '\n')
		if lineEnd < 0 {
			visit(index, input)
			return
		}
		visit(index, input[:lineEnd])
		index++
		input = input[lineEnd+1:]
	}
}
