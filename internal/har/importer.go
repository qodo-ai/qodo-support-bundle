package har

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

const maxFieldLength = 4096

type archive struct {
	Log struct {
		Version string  `json:"version"`
		Entries []entry `json:"entries"`
	} `json:"log"`
}

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
	SchemaVersion string            `json:"schema_version"`
	Timestamp     string            `json:"@timestamp,omitempty"`
	DurationMS    float64           `json:"duration_ms"`
	PageRef       string            `json:"page_ref,omitempty"`
	Request       outputRequest     `json:"request"`
	Response      outputResponse    `json:"response"`
	Timings       map[string]any    `json:"timings,omitempty"`
	Error         string            `json:"error,omitempty"`
	Source        map[string]string `json:"source"`
}

type outputRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	HTTPVersion string            `json:"http_version,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Query       map[string]string `json:"query,omitempty"`
	BodySize    int64             `json:"body_size"`
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
	EntriesWritten int  `json:"entries_written"`
	Truncated      bool `json:"truncated"`
}

// Import writes safe HAR metadata as newline-delimited JSON.
func Import(
	path string,
	writer io.Writer,
	maxInputBytes int64,
	maxEntries int,
	redactor *redact.Redactor,
) (Stats, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return Stats{}, fmt.Errorf("inspect HAR: %w", err)
	}
	if fileInfo.Size() > maxInputBytes {
		return Stats{}, fmt.Errorf(
			"HAR is %d bytes; maximum is %d bytes",
			fileInfo.Size(),
			maxInputBytes,
		)
	}

	file, err := os.Open(path)
	if err != nil {
		return Stats{}, fmt.Errorf("open HAR: %w", err)
	}
	defer file.Close()

	var input archive
	decoder := json.NewDecoder(io.LimitReader(file, maxInputBytes+1))
	if err := decoder.Decode(&input); err != nil {
		return Stats{}, fmt.Errorf("decode HAR: %w", err)
	}

	limit := len(input.Log.Entries)
	stats := Stats{}
	if limit > maxEntries {
		limit = maxEntries
		stats.Truncated = true
	}

	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, inputEntry := range input.Log.Entries[:limit] {
		output := outputEntry{
			SchemaVersion: "1",
			Timestamp:     truncate(redactor.Text(inputEntry.StartedDateTime)),
			DurationMS:    inputEntry.Time,
			PageRef:       truncate(redactor.Text(inputEntry.PageRef)),
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
		if err := encoder.Encode(output); err != nil {
			return stats, fmt.Errorf("write HAR record: %w", err)
		}
		stats.EntriesWritten++
	}
	return stats, nil
}

func sanitizeHeaders(headers []nameValue, redactor *redact.Redactor) map[string]string {
	sanitized := make(map[string]string, len(headers))
	for _, header := range headers {
		name := strings.ToLower(truncate(redactor.Text(header.Name)))
		if name == "" {
			continue
		}
		value := truncate(redactor.Header(name, header.Value))
		if existing, exists := sanitized[name]; exists {
			sanitized[name] = truncate(existing + ", " + value)
		} else {
			sanitized[name] = value
		}
	}
	return sanitized
}

func sanitizeQuery(query []nameValue, redactor *redact.Redactor) map[string]string {
	sanitized := make(map[string]string, len(query))
	for _, parameter := range query {
		name := truncate(redactor.Text(parameter.Name))
		if name == "" {
			continue
		}
		value := parameter.Value
		if redact.IsSensitiveKey(name) ||
			strings.EqualFold(name, "code") ||
			strings.EqualFold(name, "state") {
			value = redact.Replacement
		} else {
			value = redactor.Text(value)
		}
		sanitized[name] = truncate(value)
	}
	return sanitized
}

func sanitizeTimings(timings map[string]any) map[string]any {
	sanitized := make(map[string]any, len(timings))
	for key, value := range timings {
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
