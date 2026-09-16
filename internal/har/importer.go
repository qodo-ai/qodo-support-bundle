package har

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

const (
	maxFieldLength    = 4096
	MaximumInputBytes = int64(256 << 20)
)

var correlationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$`)

type entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Time            float64 `json:"time"`
	PageRef         string  `json:"pageref"`
	Request         struct {
		Method      string      `json:"method"`
		URL         string      `json:"url"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []nameValue `json:"headers"`
		QueryString []nameValue `json:"queryString"`
		BodySize    int64       `json:"bodySize"`
	} `json:"request"`
	Response struct {
		Status      int         `json:"status"`
		StatusText  string      `json:"statusText"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []nameValue `json:"headers"`
		BodySize    int64       `json:"bodySize"`
		Content     struct {
			Size     int64  `json:"size"`
			MimeType string `json:"mimeType"`
		} `json:"content"`
	} `json:"response"`
	Timings map[string]any `json:"timings"`
	Error   string         `json:"_error"`
}

type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type outputEntry struct {
	SchemaVersion  string              `json:"schema_version"`
	Timestamp      string              `json:"@timestamp,omitempty"`
	DurationMS     float64             `json:"duration_ms"`
	PageRef        string              `json:"page_ref,omitempty"`
	CorrelationIDs map[string][]string `json:"correlation_ids,omitempty"`
	Request        outputRequest       `json:"request"`
	Response       outputResponse      `json:"response"`
	Timings        map[string]any      `json:"timings,omitempty"`
	Error          string              `json:"error,omitempty"`
	Source         map[string]string   `json:"source"`
}

type outputRequest struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	HTTPVersion string              `json:"http_version,omitempty"`
	Headers     map[string]string   `json:"headers,omitempty"`
	Query       map[string][]string `json:"query,omitempty"`
	BodySize    int64               `json:"body_size"`
}

type outputResponse struct {
	Status      int               `json:"status"`
	StatusText  string            `json:"status_text,omitempty"`
	HTTPVersion string            `json:"http_version,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodySize    int64             `json:"body_size"`
	ContentSize int64             `json:"content_size"`
	ContentType string            `json:"content_type,omitempty"`
}

// Stats summarizes the sanitized records written from an imported HAR.
type Stats struct {
	EntriesWritten        int      `json:"entries_written"`
	HTTPFailures          int      `json:"http_failures"`
	Truncated             bool     `json:"truncated"`
	CorrelationIDCount    int      `json:"correlation_id_count"`
	CaptureStartedAt      string   `json:"capture_started_at,omitempty"`
	CaptureEndedAt        string   `json:"capture_ended_at,omitempty"`
	AdjustedStartedAt     string   `json:"adjusted_started_at,omitempty"`
	AdjustedEndedAt       string   `json:"adjusted_ended_at,omitempty"`
	ClockSkewMilliseconds int64    `json:"clock_skew_milliseconds"`
	ClockSkewSamples      int      `json:"clock_skew_samples"`
	CorrelationIDs        []string `json:"-"`
	startedAt             time.Time
	endedAt               time.Time
	clockSkewSamples      []float64
	correlationSet        map[string]struct{}
}

// Import writes safe HAR metadata as newline-delimited JSON.
func Import(
	path string,
	writer io.Writer,
	maxInputBytes int64,
	maxEntries int,
	redactor *redact.Redactor,
) (Stats, error) {
	return ImportContext(
		context.Background(),
		path,
		writer,
		maxInputBytes,
		maxEntries,
		redactor,
	)
}

// ImportContext writes safe HAR metadata while honoring cancellation.
func ImportContext(
	ctx context.Context,
	path string,
	writer io.Writer,
	maxInputBytes int64,
	maxEntries int,
	redactor *redact.Redactor,
) (Stats, error) {
	if maxInputBytes <= 0 || maxInputBytes > MaximumInputBytes {
		return Stats{}, fmt.Errorf(
			"maximum HAR input bytes must be between 1 and %d",
			MaximumInputBytes,
		)
	}
	if maxEntries <= 0 {
		return Stats{}, errors.New("maximum HAR entries must be positive")
	}
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}

	file, err := openHARFile(path)
	if err != nil {
		return Stats{}, fmt.Errorf("open HAR: %w", err)
	}
	defer file.Close()

	openedFileInfo, err := file.Stat()
	if err != nil {
		return Stats{}, fmt.Errorf("inspect opened HAR: %w", err)
	}
	if !openedFileInfo.Mode().IsRegular() {
		return Stats{}, errors.New("opened HAR input must be a regular file")
	}
	if openedFileInfo.Size() > maxInputBytes {
		return Stats{}, inputLimitError(openedFileInfo.Size(), maxInputBytes)
	}

	limitedReader := &io.LimitedReader{
		R: contextReader{ctx: ctx, reader: file},
		N: maxInputBytes + 1,
	}
	decoder := json.NewDecoder(limitedReader)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	stats, decodeErr := importArchive(decoder, encoder, maxEntries, redactor)
	if decodeErr == nil {
		decodeErr = requireEOF(decoder)
	}
	if limitedReader.N == 0 {
		return stats, inputLimitError(maxInputBytes+1, maxInputBytes)
	}
	if decodeErr != nil {
		return stats, fmt.Errorf("decode HAR: %w", decodeErr)
	}
	finalizeStats(&stats)
	return stats, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func importArchive(
	decoder *json.Decoder,
	encoder *json.Encoder,
	maxEntries int,
	redactor *redact.Redactor,
) (Stats, error) {
	token, err := decoder.Token()
	if err != nil {
		return Stats{}, err
	}
	if err := requireDelimiter(token, '{', "HAR root"); err != nil {
		return Stats{}, err
	}

	stats := Stats{}
	foundLog := false
	for decoder.More() {
		field, err := objectField(decoder)
		if err != nil {
			return stats, err
		}
		if field == "log" {
			if foundLog {
				return stats, errors.New("HAR root contains duplicate log fields")
			}
			foundLog = true
			if err := importLog(decoder, encoder, maxEntries, redactor, &stats); err != nil {
				return stats, err
			}
		} else if err := skipValue(decoder); err != nil {
			return stats, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return stats, err
	}
	if !foundLog {
		return stats, errors.New("HAR root must contain a log object")
	}
	return stats, nil
}

func importLog(
	decoder *json.Decoder,
	encoder *json.Encoder,
	maxEntries int,
	redactor *redact.Redactor,
	stats *Stats,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("HAR log must not be null")
	}
	if err := requireDelimiter(token, '{', "HAR log"); err != nil {
		return err
	}
	foundEntries := false
	for decoder.More() {
		field, err := objectField(decoder)
		if err != nil {
			return err
		}
		if field == "entries" {
			if foundEntries {
				return errors.New("HAR log contains duplicate entries fields")
			}
			foundEntries = true
			if err := importEntries(decoder, encoder, maxEntries, redactor, stats); err != nil {
				return err
			}
		} else if err := skipValue(decoder); err != nil {
			return err
		}
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	if !foundEntries {
		return errors.New("HAR log must contain an entries array")
	}
	return nil
}

func importEntries(
	decoder *json.Decoder,
	encoder *json.Encoder,
	maxEntries int,
	redactor *redact.Redactor,
	stats *Stats,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("HAR entries must not be null")
	}
	if err := requireDelimiter(token, '[', "HAR entries"); err != nil {
		return err
	}
	for decoder.More() {
		if stats.EntriesWritten >= maxEntries {
			stats.Truncated = true
			if err := skipEntry(decoder); err != nil {
				return err
			}
			continue
		}
		var inputEntry *entry
		if err := decoder.Decode(&inputEntry); err != nil {
			return err
		}
		if inputEntry == nil {
			return errors.New("HAR entries must not contain null elements")
		}
		outputEntry := sanitizeEntry(*inputEntry, redactor)
		observeEntry(stats, *inputEntry, outputEntry)
		if err := encoder.Encode(outputEntry); err != nil {
			return fmt.Errorf("write HAR record: %w", err)
		}
		stats.EntriesWritten++
	}
	_, err = decoder.Token()
	return err
}

func skipEntry(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("HAR entries must not contain null elements")
	}
	return skipValueFromToken(decoder, token)
}

func sanitizeEntry(inputEntry entry, redactor *redact.Redactor) outputEntry {
	return outputEntry{
		SchemaVersion: "1",
		Timestamp:     truncate(redactor.Text(inputEntry.StartedDateTime)),
		DurationMS:    inputEntry.Time,
		PageRef:       truncate(redactor.Text(inputEntry.PageRef)),
		CorrelationIDs: mergeCorrelationIDs(
			extractCorrelationIDs(inputEntry.Request.Headers, redactor),
			extractCorrelationIDs(inputEntry.Response.Headers, redactor),
		),
		Request: outputRequest{
			Method:      truncate(redactor.Text(inputEntry.Request.Method)),
			URL:         truncate(redactor.URL(inputEntry.Request.URL)),
			HTTPVersion: truncate(redactor.Text(inputEntry.Request.HTTPVersion)),
			Headers:     sanitizeHeaders(inputEntry.Request.Headers, redactor),
			Query:       sanitizeQuery(inputEntry.Request.QueryString, redactor),
			BodySize:    inputEntry.Request.BodySize,
		},
		Response: outputResponse{
			Status:      inputEntry.Response.Status,
			StatusText:  truncate(redactor.Text(inputEntry.Response.StatusText)),
			HTTPVersion: truncate(redactor.Text(inputEntry.Response.HTTPVersion)),
			Headers:     sanitizeHeaders(inputEntry.Response.Headers, redactor),
			BodySize:    inputEntry.Response.BodySize,
			ContentSize: inputEntry.Response.Content.Size,
			ContentType: truncate(redactor.Text(inputEntry.Response.Content.MimeType)),
		},
		Timings: sanitizeTimings(inputEntry.Timings),
		Error:   truncate(redactor.Text(inputEntry.Error)),
		Source:  map[string]string{"type": "browser_har"},
	}
}

func extractCorrelationIDs(
	headers []nameValue,
	redactor *redact.Redactor,
) map[string][]string {
	correlationIDs := make(map[string][]string)
	for _, header := range headers {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		switch name {
		case "request-id", "x-request-id", "x-correlation-id", "traceparent":
		default:
			continue
		}
		value := strings.TrimSpace(redactor.Header(header.Name, header.Value))
		if !correlationIDPattern.MatchString(value) {
			continue
		}
		correlationIDs[name] = append(correlationIDs[name], truncate(value))
	}
	return correlationIDs
}

func mergeCorrelationIDs(
	sources ...map[string][]string,
) map[string][]string {
	merged := make(map[string][]string)
	for _, source := range sources {
		for name, values := range source {
			for _, value := range values {
				if !containsString(merged[name], value) {
					merged[name] = append(merged[name], value)
				}
			}
		}
	}
	return merged
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func observeEntry(stats *Stats, inputEntry entry, output outputEntry) {
	if output.Response.Status >= http.StatusBadRequest {
		stats.HTTPFailures++
	}
	startedAt, err := time.Parse(time.RFC3339Nano, inputEntry.StartedDateTime)
	if err == nil {
		duration := time.Duration(0)
		if inputEntry.Time > 0 && !math.IsNaN(inputEntry.Time) &&
			!math.IsInf(inputEntry.Time, 0) &&
			inputEntry.Time <= float64(math.MaxInt64)/float64(time.Millisecond) {
			duration = time.Duration(inputEntry.Time * float64(time.Millisecond))
		}
		endedAt := startedAt.Add(duration)
		if stats.startedAt.IsZero() || startedAt.Before(stats.startedAt) {
			stats.startedAt = startedAt
		}
		if stats.endedAt.IsZero() || endedAt.After(stats.endedAt) {
			stats.endedAt = endedAt
		}
		if dateValue := headerValue(inputEntry.Response.Headers, "date"); dateValue != "" {
			if serverTime, parseErr := http.ParseTime(dateValue); parseErr == nil {
				offset := serverTime.Sub(responseTimestamp(startedAt, endedAt, inputEntry.Timings))
				if offset >= -24*time.Hour && offset <= 24*time.Hour {
					stats.clockSkewSamples = append(
						stats.clockSkewSamples,
						float64(offset)/float64(time.Millisecond),
					)
				}
			}
		}
	}
	if stats.correlationSet == nil {
		stats.correlationSet = make(map[string]struct{})
	}
	for name, values := range output.CorrelationIDs {
		for _, value := range values {
			stats.correlationSet[value] = struct{}{}
			if name == "traceparent" {
				parts := strings.Split(value, "-")
				if len(parts) >= 4 && len(parts[1]) == 32 {
					stats.correlationSet[parts[1]] = struct{}{}
				}
			}
		}
	}
}

func responseTimestamp(
	startedAt time.Time,
	fallback time.Time,
	timings map[string]any,
) time.Time {
	var responseDelayMilliseconds float64
	foundTiming := false
	for _, name := range []string{"blocked", "dns", "connect", "send", "wait"} {
		value, ok := timings[name].(float64)
		if !ok || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		foundTiming = true
		responseDelayMilliseconds += value
	}
	if !foundTiming ||
		responseDelayMilliseconds > float64(math.MaxInt64)/float64(time.Millisecond) {
		return fallback
	}
	return startedAt.Add(
		time.Duration(responseDelayMilliseconds * float64(time.Millisecond)),
	)
}

func finalizeStats(stats *Stats) {
	if !stats.startedAt.IsZero() {
		stats.CaptureStartedAt = stats.startedAt.Format(time.RFC3339Nano)
		stats.CaptureEndedAt = stats.endedAt.Format(time.RFC3339Nano)
	}
	if len(stats.clockSkewSamples) > 0 {
		sort.Float64s(stats.clockSkewSamples)
		middle := len(stats.clockSkewSamples) / 2
		median := stats.clockSkewSamples[middle]
		if len(stats.clockSkewSamples)%2 == 0 {
			median = (stats.clockSkewSamples[middle-1] + median) / 2
		}
		stats.ClockSkewMilliseconds = int64(math.Round(median))
		stats.ClockSkewSamples = len(stats.clockSkewSamples)
	}
	offset := time.Duration(stats.ClockSkewMilliseconds) * time.Millisecond
	if !stats.startedAt.IsZero() {
		stats.AdjustedStartedAt = stats.startedAt.Add(offset).Format(time.RFC3339Nano)
		stats.AdjustedEndedAt = stats.endedAt.Add(offset).Format(time.RFC3339Nano)
	}
	stats.CorrelationIDs = make([]string, 0, len(stats.correlationSet))
	for value := range stats.correlationSet {
		stats.CorrelationIDs = append(stats.CorrelationIDs, value)
	}
	sort.Strings(stats.CorrelationIDs)
	stats.CorrelationIDCount = len(stats.CorrelationIDs)
	stats.clockSkewSamples = nil
	stats.correlationSet = nil
}

func headerValue(headers []nameValue, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return strings.TrimSpace(header.Value)
		}
	}
	return ""
}

func skipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	return skipValueFromToken(decoder, token)
}

func skipValueFromToken(decoder *json.Decoder, token json.Token) error {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := objectField(decoder); err != nil {
				return err
			}
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	_, err := decoder.Token()
	return err
}

func objectField(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	field, ok := token.(string)
	if !ok {
		return "", errors.New("JSON object field name must be a string")
	}
	return field, nil
}

func requireDelimiter(token json.Token, expected json.Delim, context string) error {
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return fmt.Errorf("%s must be a JSON %q", context, expected)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("trailing HAR data: %w", err)
	}
	return errors.New("trailing HAR data after root object")
}

func inputLimitError(size int64, maximum int64) error {
	return fmt.Errorf("HAR is at least %d bytes; maximum is %d bytes", size, maximum)
}

func sanitizeHeaders(headers []nameValue, redactor *redact.Redactor) map[string]string {
	sanitized := make(map[string]string, len(headers))
	for _, header := range headers {
		name := strings.ToLower(truncate(redactor.Text(header.Name)))
		if name == "" {
			continue
		}
		value := truncate(redactor.Header(header.Name, header.Value))
		if existing, exists := sanitized[name]; exists {
			sanitized[name] = truncate(existing + ", " + value)
		} else {
			sanitized[name] = value
		}
	}
	return sanitized
}

func sanitizeQuery(query []nameValue, redactor *redact.Redactor) map[string][]string {
	sanitized := make(map[string][]string, len(query))
	for _, parameter := range query {
		name := truncate(redactor.Text(parameter.Name))
		if name == "" {
			continue
		}
		value := parameter.Value
		if redact.IsSensitiveKey(parameter.Name) ||
			strings.EqualFold(parameter.Name, "code") ||
			strings.EqualFold(parameter.Name, "state") {
			value = redact.Replacement
		} else {
			value = redactor.Text(value)
		}
		sanitized[name] = append(sanitized[name], truncate(value))
	}
	return sanitized
}

func sanitizeTimings(timings map[string]any) map[string]any {
	sanitized := make(map[string]any, len(timings))
	for key, value := range timings {
		switch key {
		case "blocked", "dns", "connect", "send", "wait", "receive", "ssl":
		default:
			continue
		}
		switch value.(type) {
		case float64, int64, int:
			sanitized[key] = value
		}
	}
	return sanitized
}

func truncate(value string) string {
	if len(value) <= maxFieldLength {
		return value
	}
	return value[:maxFieldLength] + "[TRUNCATED]"
}
