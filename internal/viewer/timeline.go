package viewer

import (
	"bufio"
	"container/heap"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	defaultTimelineLimit    = 1_500
	maxTimelineLimit        = 3_000
	maxTimelineScannedBytes = int64(512 << 20)
)

// TimelineRecord is a lightweight record positioned in the swimlane view.
type TimelineRecord struct {
	Line       int     `json:"line"`
	Path       string  `json:"path"`
	Timestamp  string  `json:"timestamp"`
	Source     string  `json:"source"`
	Lane       string  `json:"lane"`
	Group      string  `json:"group"`
	Kind       string  `json:"kind"`
	Severity   string  `json:"severity"`
	Summary    string  `json:"summary"`
	Status     int     `json:"status,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
}

// TimelineLane summarizes matching events in one diagnostic layer.
type TimelineLane struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TimelineResponse contains a bounded, time-ordered cross-source view.
type TimelineResponse struct {
	Records               []TimelineRecord `json:"records"`
	Lanes                 []TimelineLane   `json:"lanes"`
	Earliest              string           `json:"earliest,omitempty"`
	Latest                string           `json:"latest,omitempty"`
	TotalMatches          int              `json:"total_matches"`
	SkippedWithoutTime    int              `json:"skipped_without_time"`
	SkippedOversizedFiles int              `json:"skipped_oversized_files"`
	Truncated             bool             `json:"truncated"`
}

func readTimeline(
	bundle *ExtractedBundle,
	query string,
	filter string,
	limit int,
) (TimelineResponse, error) {
	response := TimelineResponse{
		Records: make([]TimelineRecord, 0, limit),
	}
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	normalizedFilter := strings.ToLower(strings.TrimSpace(filter))
	candidatesByGroup := make(map[string]*timelineRecordHeap)
	laneCounts := make(map[string]int)
	var earliest time.Time
	var latest time.Time
	var scannedBytes int64

	for _, bundleFile := range bundle.Files {
		if !timelineFile(bundleFile.Path) {
			continue
		}
		if scannedBytes >= maxTimelineScannedBytes {
			response.Truncated = true
			break
		}
		localPath, exists := bundle.Resolve(bundleFile.Path)
		if !exists {
			continue
		}
		file, err := os.Open(localPath)
		if err != nil {
			return TimelineResponse{}, fmt.Errorf("open timeline source: %w", err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), maxScannedLineBytes)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			scannedBytes += int64(len(line)) + 1
			if scannedBytes > maxTimelineScannedBytes {
				response.Truncated = true
				break
			}
			if normalizedQuery != "" &&
				!strings.Contains(strings.ToLower(line), normalizedQuery) {
				continue
			}
			record := normalizeRecord(bundleFile.Path, lineNumber, line)
			if !matchesFilter(record, line, normalizedFilter) {
				continue
			}
			timestamp, ok := parseRecordTimestamp(record.Timestamp)
			if !ok {
				response.SkippedWithoutTime++
				continue
			}
			response.TotalMatches++
			laneCounts[record.Lane]++
			if earliest.IsZero() || timestamp.Before(earliest) {
				earliest = timestamp
			}
			if latest.IsZero() || timestamp.After(latest) {
				latest = timestamp
			}
			candidate := timelineCandidate{
				record: TimelineRecord{
					Line:       record.Line,
					Path:       record.Path,
					Timestamp:  record.Timestamp,
					Source:     record.Source,
					Lane:       record.Lane,
					Group:      record.Group,
					Kind:       record.Kind,
					Severity:   record.Severity,
					Summary:    record.Summary,
					Status:     record.Status,
					DurationMS: record.DurationMS,
				},
				timestamp: timestamp,
			}
			addTimelineCandidate(candidatesByGroup, candidate, limit)
		}
		scanErr := scanner.Err()
		if closeErr := file.Close(); closeErr != nil {
			return TimelineResponse{}, fmt.Errorf("close timeline source: %w", closeErr)
		}
		if scanErr != nil {
			response.SkippedOversizedFiles++
			response.Truncated = true
		}
		if scannedBytes > maxTimelineScannedBytes {
			break
		}
	}

	sortedCandidates := selectFairTimelineCandidates(candidatesByGroup, limit)
	sort.Slice(sortedCandidates, func(left int, right int) bool {
		if sortedCandidates[left].timestamp.Equal(sortedCandidates[right].timestamp) {
			if sortedCandidates[left].record.Path == sortedCandidates[right].record.Path {
				return sortedCandidates[left].record.Line < sortedCandidates[right].record.Line
			}
			return sortedCandidates[left].record.Path < sortedCandidates[right].record.Path
		}
		return sortedCandidates[left].timestamp.Before(sortedCandidates[right].timestamp)
	})
	for _, candidate := range sortedCandidates {
		response.Records = append(response.Records, candidate.record)
	}
	response.Lanes = orderedTimelineLanes(laneCounts)
	if !earliest.IsZero() {
		response.Earliest = earliest.Format(time.RFC3339Nano)
		response.Latest = latest.Format(time.RFC3339Nano)
	}
	if response.TotalMatches > len(response.Records) {
		response.Truncated = true
	}
	return response, nil
}

func addTimelineCandidate(
	candidatesByGroup map[string]*timelineRecordHeap,
	candidate timelineCandidate,
	limit int,
) {
	groupKey := candidate.record.Lane + "\x00" + candidate.record.Group
	candidates := candidatesByGroup[groupKey]
	if candidates == nil {
		groupLimit := min(limit, 500)
		groupHeap := make(timelineRecordHeap, 0, groupLimit)
		heap.Init(&groupHeap)
		candidates = &groupHeap
		candidatesByGroup[groupKey] = candidates
	}
	if candidates.Len() < cap(*candidates) {
		heap.Push(candidates, candidate)
		return
	}
	if (*candidates)[0].timestamp.Before(candidate.timestamp) {
		heap.Pop(candidates)
		heap.Push(candidates, candidate)
	}
}

func selectFairTimelineCandidates(
	candidatesByGroup map[string]*timelineRecordHeap,
	limit int,
) []timelineCandidate {
	groupKeys := orderedTimelineCandidateGroups(candidatesByGroup)
	targets := make(map[string]int, len(groupKeys))
	remaining := limit
	for remaining > 0 {
		added := false
		for _, groupKey := range groupKeys {
			if remaining == 0 {
				break
			}
			if targets[groupKey] >= candidatesByGroup[groupKey].Len() {
				continue
			}
			targets[groupKey]++
			remaining--
			added = true
		}
		if !added {
			break
		}
	}

	selected := make([]timelineCandidate, 0, limit-remaining)
	for _, groupKey := range groupKeys {
		candidates := *candidatesByGroup[groupKey]
		sort.Slice(candidates, func(left int, right int) bool {
			return candidates[left].timestamp.Before(candidates[right].timestamp)
		})
		start := len(candidates) - targets[groupKey]
		selected = append(selected, candidates[start:]...)
	}
	return selected
}

func orderedTimelineCandidateGroups(
	candidatesByGroup map[string]*timelineRecordHeap,
) []string {
	order := []string{
		"Browser",
		"Backend logs",
		"Kubernetes events",
		"Kubernetes pods",
		"Diagnostics",
	}
	groupKeys := make([]string, 0, len(candidatesByGroup))
	for _, lane := range order {
		prefix := lane + "\x00"
		laneGroups := make([]string, 0)
		for groupKey := range candidatesByGroup {
			if strings.HasPrefix(groupKey, prefix) {
				laneGroups = append(laneGroups, groupKey)
			}
		}
		sort.Strings(laneGroups)
		groupKeys = append(groupKeys, laneGroups...)
	}
	return groupKeys
}

func timelineFile(path string) bool {
	return strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".log")
}

func parseRecordTimestamp(value string) (time.Time, bool) {
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return timestamp, true
}

func orderedTimelineLanes(counts map[string]int) []TimelineLane {
	order := []string{
		"Browser",
		"Backend logs",
		"Kubernetes events",
		"Kubernetes pods",
		"Diagnostics",
	}
	lanes := make([]TimelineLane, 0, len(counts))
	for _, name := range order {
		if count := counts[name]; count > 0 {
			lanes = append(lanes, TimelineLane{Name: name, Count: count})
		}
	}
	return lanes
}

type timelineCandidate struct {
	record    TimelineRecord
	timestamp time.Time
}

type timelineRecordHeap []timelineCandidate

func (records timelineRecordHeap) Len() int {
	return len(records)
}

func (records timelineRecordHeap) Less(left int, right int) bool {
	if records[left].timestamp.Equal(records[right].timestamp) {
		if records[left].record.Path == records[right].record.Path {
			return records[left].record.Line < records[right].record.Line
		}
		return records[left].record.Path < records[right].record.Path
	}
	return records[left].timestamp.Before(records[right].timestamp)
}

func (records timelineRecordHeap) Swap(left int, right int) {
	records[left], records[right] = records[right], records[left]
}

func (records *timelineRecordHeap) Push(value any) {
	*records = append(*records, value.(timelineCandidate))
}

func (records *timelineRecordHeap) Pop() any {
	current := *records
	lastIndex := len(current) - 1
	value := current[lastIndex]
	*records = current[:lastIndex]
	return value
}
