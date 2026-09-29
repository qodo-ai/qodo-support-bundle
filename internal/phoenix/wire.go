package phoenix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

var errInvalidResponse = errors.New("invalid Phoenix response")

var retainedAttributeKeys = map[string]struct{}{
	"service.name":           {},
	"service.version":        {},
	"deployment.environment": {},
	"domain_module":          {},
	"qodo.workflow.type":     {},
	"vcs.provider":           {},
	"vcs.event.type":         {},
}

type projectEnvelope struct {
	Data       []wireProject `json:"data"`
	NextCursor *string       `json:"next_cursor,omitempty"`
}

type wireProject struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description discardedNullableString `json:"description,omitempty"`
}

type spansEnvelope struct {
	Data       []wireSpan `json:"data"`
	NextCursor *string    `json:"next_cursor,omitempty"`
}

type wireSpan struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	Context       wireSpanContext         `json:"context"`
	SpanKind      string                  `json:"span_kind"`
	ParentID      *string                 `json:"parent_id,omitempty"`
	StartTime     string                  `json:"start_time"`
	EndTime       string                  `json:"end_time"`
	StatusCode    string                  `json:"status_code"`
	StatusMessage discardedNullableString `json:"status_message"`
	Attributes    safeAttributes          `json:"attributes"`
	Events        discardedJSONArray      `json:"events"`
}

type wireSpanContext struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
}

type normalizedSpan struct {
	traceID string
	span    Span
	start   time.Time
	end     time.Time
}

func decodeProjects(data []byte) ([]Project, string, error) {
	var envelope projectEnvelope
	if err := decodeStrict(data, &envelope); err != nil {
		return nil, "", errInvalidResponse
	}
	projects := make([]Project, 0, len(envelope.Data))
	seen := make(map[string]struct{}, len(envelope.Data))
	for _, project := range envelope.Data {
		if !validBoundedText(project.ID, 1024) || !validBoundedText(project.Name, 1024) {
			return nil, "", errInvalidResponse
		}
		if _, duplicate := seen[project.ID]; duplicate {
			return nil, "", errInvalidResponse
		}
		seen[project.ID] = struct{}{}
		projects = append(projects, Project{ID: project.ID, Name: project.Name})
	}
	cursor, err := validatedCursor(envelope.NextCursor)
	if err != nil {
		return nil, "", errInvalidResponse
	}
	return projects, cursor, nil
}

func decodeSpans(
	data []byte,
	config Config,
	redactor *redact.Redactor,
) ([]normalizedSpan, string, int, error) {
	var envelope spansEnvelope
	if err := decodeStrict(data, &envelope); err != nil {
		return nil, "", 0, errInvalidResponse
	}
	spans := make([]normalizedSpan, 0, len(envelope.Data))
	for _, raw := range envelope.Data {
		span, keep, err := normalizeSpan(raw, config, redactor)
		if err != nil {
			return nil, "", 0, errInvalidResponse
		}
		if keep {
			spans = append(spans, span)
		}
	}
	cursor, err := validatedCursor(envelope.NextCursor)
	if err != nil {
		return nil, "", 0, errInvalidResponse
	}
	return spans, cursor, len(envelope.Data), nil
}

func normalizeSpan(
	raw wireSpan,
	config Config,
	redactor *redact.Redactor,
) (normalizedSpan, bool, error) {
	if !validBoundedText(raw.Context.TraceID, 32) ||
		!validBoundedText(raw.Context.SpanID, 16) ||
		!validBoundedText(raw.ID, 1024) ||
		!validBoundedText(raw.Name, 1024) ||
		!validBoundedText(raw.SpanKind, 128) ||
		!validBoundedText(raw.StatusCode, 128) ||
		raw.StartTime == "" ||
		raw.EndTime == "" ||
		!raw.StatusMessage.present ||
		!raw.Attributes.present ||
		!raw.Events.present {
		return normalizedSpan{}, false, errInvalidResponse
	}
	traceID := strings.ToLower(raw.Context.TraceID)
	spanID := strings.ToLower(raw.Context.SpanID)
	if !validTraceID(traceID) ||
		!validSpanID(spanID) {
		return normalizedSpan{}, false, errInvalidResponse
	}
	start, err := time.Parse(time.RFC3339Nano, raw.StartTime)
	if err != nil {
		return normalizedSpan{}, false, errInvalidResponse
	}
	end, err := time.Parse(time.RFC3339Nano, raw.EndTime)
	if err != nil || end.Before(start) {
		return normalizedSpan{}, false, errInvalidResponse
	}
	start = start.UTC()
	end = end.UTC()
	if config.TraceID != "" && traceID != config.TraceID {
		return normalizedSpan{}, false, errInvalidResponse
	}
	if config.TraceID == "" &&
		(start.Before(config.Start) ||
			!start.Before(config.End)) {
		return normalizedSpan{}, false, nil
	}
	parentID := ""
	if raw.ParentID != nil && *raw.ParentID != "" {
		parentID = strings.ToLower(*raw.ParentID)
		if !validSpanID(parentID) {
			return normalizedSpan{}, false, errInvalidResponse
		}
	}
	attributes := make(map[string]string)
	for key, value := range raw.Attributes.values {
		if _, approved := retainedAttributeKeys[key]; !approved || redact.IsSensitiveKey(key) {
			continue
		}
		attributes[key] = redactor.Text(value)
	}
	if len(attributes) == 0 {
		attributes = nil
	}
	return normalizedSpan{
		traceID: traceID,
		start:   start,
		end:     end,
		span: Span{
			SpanID:     spanID,
			ParentID:   parentID,
			Name:       redactor.Text(raw.Name),
			SpanKind:   redactor.Text(raw.SpanKind),
			StatusCode: redactor.Text(raw.StatusCode),
			Start:      start.Format(time.RFC3339Nano),
			End:        end.Format(time.RFC3339Nano),
			Attributes: attributes,
		},
	}, true, nil
}

func validatedCursor(cursor *string) (string, error) {
	if cursor == nil {
		return "", nil
	}
	if *cursor == "" || !utf8.ValidString(*cursor) || len(*cursor) > 4096 ||
		strings.ContainsAny(*cursor, "\r\n") {
		return "", errInvalidResponse
	}
	return *cursor, nil
}

type discardedString struct{}

func (*discardedString) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errInvalidResponse
	}
	return nil
}

type discardedNullableString struct {
	present bool
}

func (value *discardedNullableString) UnmarshalJSON(data []byte) error {
	value.present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var discarded string
	if err := json.Unmarshal(data, &discarded); err != nil {
		return errInvalidResponse
	}
	return nil
}

type discardedJSONArray struct {
	present bool
}

func (value *discardedJSONArray) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return errInvalidResponse
	}
	for decoder.More() {
		if err := consumeJSONValue(decoder, 0); err != nil {
			return errInvalidResponse
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') || requireJSONEOF(decoder) != nil {
		return errInvalidResponse
	}
	value.present = true
	return nil
}

type safeAttributes struct {
	present bool
	values  map[string]string
}

func (attributes *safeAttributes) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errInvalidResponse
	}
	values := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return errInvalidResponse
		}
		key, ok := keyToken.(string)
		if !ok {
			return errInvalidResponse
		}
		valueToken, err := decoder.Token()
		if err != nil {
			return errInvalidResponse
		}
		if _, retained := retainedAttributeKeys[key]; retained {
			if text, ok := valueToken.(string); ok {
				values[key] = text
				continue
			}
		}
		if delimiter, structured := valueToken.(json.Delim); structured {
			if err := consumeJSONContainer(decoder, delimiter, 0); err != nil {
				return errInvalidResponse
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || requireJSONEOF(decoder) != nil {
		return errInvalidResponse
	}
	attributes.present = true
	attributes.values = values
	return nil
}

func validBoundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value)
}

func decodeStrict(data []byte, destination any) error {
	if len(data) == 0 || !utf8.Valid(data) {
		return errInvalidResponse
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	return consumeJSONContainer(decoder, delimiter, depth)
}

func consumeJSONContainer(
	decoder *json.Decoder,
	delimiter json.Delim,
	depth int,
) error {
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate object key")
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object close")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array close")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func sortRecord(record *Record) {
	sort.Slice(record.Spans, func(left, right int) bool {
		if record.Spans[left].Start != record.Spans[right].Start {
			return record.Spans[left].Start < record.Spans[right].Start
		}
		return record.Spans[left].SpanID < record.Spans[right].SpanID
	})
}
