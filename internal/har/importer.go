package har

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

const maxFieldLength = 4096

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
	if !fileInfo.Mode().IsRegular() {
		return Stats{}, errors.New("HAR input must be a regular file")
	}
	if fileInfo.Size() > maxInputBytes {
		return Stats{}, inputLimitError(fileInfo.Size(), maxInputBytes)
	}

	file, err := os.Open(path)
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

	limitedReader := &io.LimitedReader{R: file, N: maxInputBytes + 1}
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
	return stats, nil
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
	for decoder.More() {
		field, err := objectField(decoder)
		if err != nil {
			return stats, err
		}
		if field == "log" {
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
		return nil
	}
	if err := requireDelimiter(token, '{', "HAR log"); err != nil {
		return err
	}
	for decoder.More() {
		field, err := objectField(decoder)
		if err != nil {
			return err
		}
		if field == "entries" {
			if err := importEntries(decoder, encoder, maxEntries, redactor, stats); err != nil {
				return err
			}
		} else if err := skipValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
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
		return nil
	}
	if err := requireDelimiter(token, '[', "HAR entries"); err != nil {
		return err
	}
	for decoder.More() {
		if stats.EntriesWritten >= maxEntries {
			stats.Truncated = true
			if err := skipValue(decoder); err != nil {
				return err
			}
			continue
		}
		var inputEntry entry
		if err := decoder.Decode(&inputEntry); err != nil {
			return err
		}
		if err := encoder.Encode(sanitizeEntry(inputEntry, redactor)); err != nil {
			return fmt.Errorf("write HAR record: %w", err)
		}
		stats.EntriesWritten++
	}
	_, err = decoder.Token()
	return err
}

func sanitizeEntry(inputEntry entry, redactor *redact.Redactor) outputEntry {
	return outputEntry{
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
}

func skipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
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
	_, err = decoder.Token()
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

func sanitizeQuery(query []nameValue, redactor *redact.Redactor) map[string]string {
	sanitized := make(map[string]string, len(query))
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
