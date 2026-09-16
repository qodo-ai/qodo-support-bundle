package viewer

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxScannedLineBytes = 4 << 20
	maxDetailBytes      = 64 << 10
	maxRecordLimit      = 500
)

// Record is one normalized row shown by the local viewer.
type Record struct {
	Line       int     `json:"line"`
	Path       string  `json:"path"`
	Timestamp  string  `json:"timestamp,omitempty"`
	Source     string  `json:"source"`
	Lane       string  `json:"lane"`
	Group      string  `json:"group"`
	Kind       string  `json:"kind"`
	Severity   string  `json:"severity"`
	Summary    string  `json:"summary"`
	Status     int     `json:"status,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
	Details    any     `json:"details"`
}

// RecordsResponse is a filtered page from one bundle file.
type RecordsResponse struct {
	Path       string   `json:"path"`
	Records    []Record `json:"records"`
	Offset     int      `json:"offset"`
	NextOffset int      `json:"next_offset"`
	HasMore    bool     `json:"has_more"`
}

func readRecords(
	bundle *ExtractedBundle,
	path string,
	query string,
	filter string,
	offset int,
	limit int,
) (RecordsResponse, error) {
	localPath, exists := bundle.Resolve(path)
	if !exists {
		return RecordsResponse{}, fmt.Errorf("unknown bundle file %q", path)
	}
	file, err := os.Open(localPath)
	if err != nil {
		return RecordsResponse{}, fmt.Errorf("open bundle file: %w", err)
	}
	defer file.Close()

	response := RecordsResponse{
		Path:    path,
		Records: make([]Record, 0, limit),
		Offset:  offset,
	}
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	normalizedFilter := strings.ToLower(strings.TrimSpace(filter))
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxScannedLineBytes)
	matched := 0
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if normalizedQuery != "" &&
			!strings.Contains(strings.ToLower(line), normalizedQuery) {
			continue
		}
		record := normalizeRecord(path, lineNumber, line)
		if !matchesFilter(record, line, normalizedFilter) {
			continue
		}
		if matched < offset {
			matched++
			continue
		}
		if len(response.Records) >= limit {
			response.HasMore = true
			break
		}
		response.Records = append(response.Records, record)
		matched++
	}
	if err := scanner.Err(); err != nil {
		return RecordsResponse{}, fmt.Errorf(
			"scan bundle file; a line may exceed %d bytes: %w",
			maxScannedLineBytes,
			err,
		)
	}
	response.NextOffset = offset + len(response.Records)
	return response, nil
}

func readRecordAtLine(
	bundle *ExtractedBundle,
	path string,
	targetLine int,
) (Record, error) {
	if targetLine <= 0 {
		return Record{}, errors.New("line must be positive")
	}
	localPath, exists := bundle.Resolve(path)
	if !exists {
		return Record{}, fmt.Errorf("unknown bundle file %q", path)
	}
	file, err := os.Open(localPath)
	if err != nil {
		return Record{}, fmt.Errorf("open bundle file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxScannedLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber == targetLine {
			return normalizeRecord(path, lineNumber, scanner.Text()), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return Record{}, fmt.Errorf("scan bundle file: %w", err)
	}
	return Record{}, fmt.Errorf("line %d does not exist", targetLine)
}

func normalizeRecord(path string, lineNumber int, line string) Record {
	record := Record{
		Line:     lineNumber,
		Path:     path,
		Source:   sourceForPath(path),
		Lane:     laneForPath(path),
		Group:    groupForPath(path),
		Kind:     kindForPath(path),
		Severity: "info",
		Summary:  truncateDetail(strings.TrimSpace(line), 500),
		Details:  truncateDetail(line, maxDetailBytes),
	}
	jsonText := strings.TrimSpace(line)
	if fields := strings.Fields(jsonText); len(fields) > 0 {
		if _, valid := parseRecordTimestamp(fields[0]); valid {
			record.Timestamp = fields[0]
		}
	}
	if start := strings.IndexAny(jsonText, "{["); start > 0 {
		prefix := strings.TrimSpace(jsonText[:start])
		if fields := strings.Fields(prefix); len(fields) > 0 {
			record.Timestamp = fields[0]
		}
		jsonText = jsonText[start:]
	}
	if len(jsonText) > maxDetailBytes {
		return record
	}
	var value any
	if err := json.Unmarshal([]byte(jsonText), &value); err != nil {
		record.Severity = severityFromText(line)
		return record
	}
	record.Details = value
	object, ok := value.(map[string]any)
	if !ok {
		return record
	}
	if timestamp := stringValue(object["@timestamp"]); timestamp != "" {
		record.Timestamp = timestamp
	} else if timestamp := nestedString(object, "time", "repr"); timestamp != "" {
		record.Timestamp = timestamp
	}

	switch {
	case hasObject(object, "request") && hasObject(object, "response"):
		normalizeBrowserRecord(&record, object)
	case nestedString(object, "source", "type") == "kubernetes_event":
		normalizeEventRecord(&record, object)
	case nestedString(object, "source", "type") == "kubernetes_container":
		normalizeContainerEventRecord(&record, object)
	case nestedString(object, "source", "type") == "kubernetes":
		normalizePodRecord(&record, object)
	default:
		normalizeLogRecord(&record, object, line)
	}
	return record
}

func normalizeContainerEventRecord(record *Record, object map[string]any) {
	kind := stringValue(object["kind"])
	namespace := stringValue(object["namespace"])
	pod := stringValue(object["pod"])
	container := stringValue(object["container"])
	restarts := intValue(object["restart_count"])
	reason := stringValue(object["reason"])
	record.Kind = strings.ToLower(kind)
	record.Group = strings.Trim(strings.Join([]string{namespace, pod, container}, " / "), " /")
	record.Severity = normalizeSeverity(stringValue(object["severity"]))
	record.Summary = strings.TrimSpace(
		fmt.Sprintf("%s: %s (%d restarts) — %s", kind, record.Group, restarts, reason),
	)
}

func normalizeBrowserRecord(record *Record, object map[string]any) {
	request := objectValue(object["request"])
	response := objectValue(object["response"])
	method := stringValue(request["method"])
	requestURL := stringValue(request["url"])
	status := intValue(response["status"])
	record.Kind = "request"
	record.Status = status
	record.DurationMS = floatValue(object["duration_ms"])
	record.Severity = severityFromStatus(status)
	if parsedURL, err := url.Parse(requestURL); err == nil && parsedURL.Hostname() != "" {
		record.Group = parsedURL.Hostname()
	}
	record.Summary = strings.TrimSpace(
		fmt.Sprintf("%s %d %s", method, status, requestURL),
	)
}

func normalizeEventRecord(record *Record, object map[string]any) {
	eventType := stringValue(object["type"])
	reason := stringValue(object["reason"])
	kind := stringValue(object["kind"])
	namespace := stringValue(object["namespace"])
	name := stringValue(object["name"])
	message := stringValue(object["message"])
	record.Kind = "event"
	record.Group = strings.Trim(strings.Join([]string{namespace, kind}, " / "), " /")
	if strings.EqualFold(eventType, "warning") {
		record.Severity = "warning"
	}
	record.Summary = strings.TrimSpace(
		fmt.Sprintf("%s %s/%s: %s — %s", reason, kind, name, eventType, message),
	)
}

func normalizePodRecord(record *Record, object map[string]any) {
	name := stringValue(object["name"])
	namespace := stringValue(object["namespace"])
	phase := stringValue(object["phase"])
	record.Kind = "pod"
	record.Group = firstNonEmpty(namespace, "unknown namespace")
	record.Summary = strings.TrimSpace(fmt.Sprintf("Pod %s — %s", name, phase))
	if !strings.EqualFold(phase, "running") && !strings.EqualFold(phase, "succeeded") {
		record.Severity = "warning"
	}
}

func normalizeLogRecord(record *Record, object map[string]any, line string) {
	record.Kind = "log"
	severity := firstNonEmpty(
		stringValue(object["severity"]),
		nestedString(object, "level", "name"),
		nestedString(object, "record", "level", "name"),
	)
	if severity != "" {
		record.Severity = normalizeSeverity(severity)
	} else {
		record.Severity = severityFromText(line)
	}
	summary := firstNonEmpty(
		stringValue(object["text"]),
		stringValue(object["message"]),
		nestedString(object, "record", "message"),
	)
	if summary != "" {
		record.Summary = truncateDetail(summary, 500)
	}
}

func matchesFilter(record Record, _ string, filter string) bool {
	switch filter {
	case "", "all":
		return true
	case "errors":
		return record.Severity == "error" || record.Severity == "warning"
	case "auth":
		lower := authenticationSearchText(record)
		for _, term := range []string{
			"/auth/",
			"/token",
			`"access_token"`,
			`"id_token"`,
			`"refresh_token"`,
			"authorize",
			"bearer",
			"authentication failed",
			"invalid authentication",
			"login",
			"microsoftonline",
			"oauth",
			"oidc",
			"userinfo",
			"zitadel",
		} {
			if strings.Contains(lower, term) {
				return true
			}
		}
		return containsASCIIWord(lower, "token")
	default:
		return true
	}
}

func authenticationSearchText(record Record) string {
	values := []string{record.Summary}
	object, ok := record.Details.(map[string]any)
	if ok {
		values = append(
			values,
			stringValue(object["url"]),
			stringValue(object["route"]),
			stringValue(object["endpoint"]),
			stringValue(object["provider"]),
			nestedString(object, "request", "url"),
			nestedString(object, "record", "extra", "entry_point"),
			nestedString(object, "record", "extra", "route"),
		)
	}
	return strings.ToLower(strings.Join(values, " "))
}

func containsASCIIWord(value string, word string) bool {
	searchStart := 0
	for searchStart < len(value) {
		index := strings.Index(value[searchStart:], word)
		if index < 0 {
			return false
		}
		index += searchStart
		leftBoundary := index == 0 || !isASCIIWordCharacter(value[index-1])
		rightIndex := index + len(word)
		rightBoundary := rightIndex == len(value) ||
			!isASCIIWordCharacter(value[rightIndex])
		if leftBoundary && rightBoundary {
			return true
		}
		searchStart = index + len(word)
	}
	return false
}

func isASCIIWordCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '_'
}

func severityFromStatus(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "warning"
	default:
		return "info"
	}
}

func severityFromText(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, `"severity":"error"`),
		strings.Contains(lower, `"level":"error"`),
		strings.Contains(lower, " exception"),
		strings.Contains(lower, " traceback"),
		strings.Contains(lower, " error:"):
		return "error"
	case strings.Contains(lower, `"severity":"warning"`),
		strings.Contains(lower, `"severity":"warn"`),
		strings.Contains(lower, `"level":"warning"`),
		strings.Contains(lower, `"level":"warn"`):
		return "warning"
	default:
		return "info"
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(value) {
	case "error", "fatal", "critical":
		return "error"
	case "warn", "warning":
		return "warning"
	default:
		return "info"
	}
}

func sourceForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "browser/"):
		return "browser"
	case strings.HasPrefix(path, "kubernetes/logs/"):
		return "backend"
	case path == "kubernetes/container_events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/container_events/"):
		return "kubernetes-container"
	case path == "kubernetes/events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/events/"):
		return "kubernetes-event"
	case path == "kubernetes/pods.jsonl" ||
		strings.HasPrefix(path, "kubernetes/pods/"):
		return "kubernetes-pod"
	default:
		return filepath.Base(path)
	}
}

func laneForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "browser/"):
		return "Browser"
	case strings.HasPrefix(path, "kubernetes/logs/"):
		return "Backend logs"
	case path == "kubernetes/container_events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/container_events/"):
		return "Container failures"
	case path == "kubernetes/events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/events/"):
		return "Kubernetes events"
	case path == "kubernetes/pods.jsonl" ||
		strings.HasPrefix(path, "kubernetes/pods/"):
		return "Kubernetes pods"
	default:
		return "Diagnostics"
	}
}

func kindForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "browser/"):
		return "request"
	case strings.HasPrefix(path, "kubernetes/logs/"):
		return "log"
	case path == "kubernetes/container_events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/container_events/"):
		return "container-event"
	case path == "kubernetes/events.jsonl" ||
		strings.HasPrefix(path, "kubernetes/events/"):
		return "event"
	case path == "kubernetes/pods.jsonl" ||
		strings.HasPrefix(path, "kubernetes/pods/"):
		return "pod"
	default:
		return "record"
	}
}

func groupForPath(path string) string {
	if !strings.HasPrefix(path, "kubernetes/logs/") {
		return filepath.Base(path)
	}
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return filepath.Base(path)
	}
	podName := parts[len(parts)-2]
	containerName := strings.TrimSuffix(parts[len(parts)-1], ".log")
	containerName = strings.TrimSuffix(containerName, "-previous")
	if len(parts) >= 5 {
		return strings.Join(
			[]string{parts[2], podName, containerName},
			" / ",
		)
	}
	return podName + " / " + containerName
}

func objectValue(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func hasObject(object map[string]any, key string) bool {
	_, ok := object[key].(map[string]any)
	return ok
}

func nestedString(object map[string]any, path ...string) string {
	var current any = object
	for _, key := range path {
		currentObject, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = currentObject[key]
	}
	return stringValue(current)
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	default:
		return 0
	}
}

func floatValue(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case json.Number:
		parsed, _ := strconv.ParseFloat(typed.String(), 64)
		return parsed
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func truncateDetail(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "[TRUNCATED]"
}
