package kubernetes

import (
	"strings"
	"testing"
	"time"
)

func TestFilterLogKeepsCorrelationMatchesWithBoundedContext(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"2026-09-15T06:00:00Z before-window",
		"2026-09-15T06:01:00Z unrelated-before",
		"2026-09-15T06:01:01Z request_id=request-1234 failed",
		"2026-09-15T06:01:02Z related-after",
		"2026-09-15T06:04:00Z after-window",
		"",
	}, "\n")
	since := time.Date(2026, 9, 15, 6, 0, 30, 0, time.UTC)
	until := time.Date(2026, 9, 15, 6, 2, 0, 0, time.UTC)

	output, matched := filterLog(
		[]byte(input),
		[]string{"request-1234"},
		since,
		until,
		1,
	)

	if matched != 1 {
		t.Fatalf("unexpected match count: %d", matched)
	}
	text := string(output)
	for _, expected := range []string{
		"unrelated-before",
		"request_id=request-1234 failed",
		"related-after",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing correlated context %q: %s", expected, text)
		}
	}
	for _, omitted := range []string{"before-window", "after-window"} {
		if strings.Contains(text, omitted) {
			t.Fatalf("retained out-of-window line %q: %s", omitted, text)
		}
	}
}

func TestFilterLogWithoutCorrelationIDsOnlyAppliesTimeWindow(t *testing.T) {
	t.Parallel()
	input := "2026-09-15T06:00:00Z old\n2026-09-15T06:02:00Z current\n"
	since := time.Date(2026, 9, 15, 6, 1, 0, 0, time.UTC)

	output, matched := filterLog([]byte(input), nil, since, time.Time{}, 3)

	if matched != 0 || string(output) != "2026-09-15T06:02:00Z current\n" {
		t.Fatalf("unexpected filtered log: matched=%d output=%q", matched, output)
	}
}
