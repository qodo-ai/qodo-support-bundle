package prometheus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

var errInvalidResponse = errors.New("invalid Prometheus response")

type rangeEnvelope struct {
	Status string     `json:"status"`
	Data   *rangeData `json:"data"`
}

type rangeData struct {
	ResultType string
	Result     []matrixSeries
}

type matrixSeries struct {
	Metric map[string]string
	Values []json.RawMessage
}

type normalizedQuery struct {
	records       []Record
	seriesFound   int
	samplesFound  int
	sampleLimited bool
	seriesLimited bool
}

func normalizeRangeResponse(
	data []byte,
	query Query,
	config Config,
	redactor *redact.Redactor,
) (normalizedQuery, error) {
	if !utf8.Valid(data) {
		return normalizedQuery{}, errInvalidResponse
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return normalizedQuery{}, errInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope rangeEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return normalizedQuery{}, errInvalidResponse
	}
	if err := requireJSONEOF(decoder); err != nil {
		return normalizedQuery{}, errInvalidResponse
	}
	if envelope.Status != "success" ||
		envelope.Data == nil ||
		envelope.Data.ResultType != "matrix" {
		return normalizedQuery{}, errInvalidResponse
	}

	result := normalizedQuery{seriesFound: len(envelope.Data.Result)}
	if len(envelope.Data.Result) > config.MaxSeriesPerQuery {
		result.seriesLimited = true
	}
	allowlist := labelAllowlist(query)
	rawIdentities := make(map[string]struct{}, len(envelope.Data.Result))
	retainedIdentities := make(map[string]struct{}, len(envelope.Data.Result))
	records := make([]Record, 0, min(len(envelope.Data.Result), config.MaxSeriesPerQuery))
	for _, series := range envelope.Data.Result {
		if len(series.Metric) > 128 {
			return normalizedQuery{}, errInvalidResponse
		}
		rawIdentity := sortedLabelIdentity(series.Metric)
		if _, duplicate := rawIdentities[rawIdentity]; duplicate {
			return normalizedQuery{}, errInvalidResponse
		}
		rawIdentities[rawIdentity] = struct{}{}

		labels := make(map[string]string, len(allowlist))
		for key, value := range series.Metric {
			if _, approved := allowlist[key]; !approved || redact.IsSensitiveKey(key) {
				continue
			}
			if !utf8.ValidString(value) {
				return normalizedQuery{}, errInvalidResponse
			}
			labels[key] = redactor.Text(value)
		}
		retainedIdentity := sortedLabelIdentity(labels)
		if _, duplicate := retainedIdentities[retainedIdentity]; duplicate {
			return normalizedQuery{}, errInvalidResponse
		}
		retainedIdentities[retainedIdentity] = struct{}{}

		samples := make([]Sample, 0, min(len(series.Values), config.MaxSamplesPerSeries))
		if len(series.Values) > config.MaxSamplesPerSeries {
			result.sampleLimited = true
		}
		for _, rawSample := range series.Values {
			result.samplesFound++
			sample, inWindow, err := decodeSample(rawSample, config.Start, config.End)
			if err != nil {
				return normalizedQuery{}, errInvalidResponse
			}
			if inWindow {
				samples = append(samples, sample)
			}
		}
		sort.Slice(samples, func(left int, right int) bool {
			return sampleTime(samples[left]).Before(sampleTime(samples[right]))
		})
		for index := 1; index < len(samples); index++ {
			if samples[index-1].Timestamp == samples[index].Timestamp {
				return normalizedQuery{}, errInvalidResponse
			}
		}
		if len(samples) > config.MaxSamplesPerSeries {
			samples = samples[:config.MaxSamplesPerSeries]
			result.sampleLimited = true
		}
		if len(samples) == 0 {
			continue
		}
		records = append(records, Record{
			SchemaVersion: recordSchemaVersion,
			QueryID:       query.ID,
			Category:      query.Category,
			Labels:        labels,
			Samples:       samples,
		})
	}
	sort.Slice(records, func(left int, right int) bool {
		return sortedLabelIdentity(records[left].Labels) <
			sortedLabelIdentity(records[right].Labels)
	})
	if len(records) > config.MaxSeriesPerQuery {
		records = records[:config.MaxSeriesPerQuery]
		result.seriesLimited = true
	}
	result.records = records
	return result, nil
}

func (data *rangeData) UnmarshalJSON(raw []byte) error {
	var wire struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if len(wire.Result) == 0 ||
		bytes.Equal(bytes.TrimSpace(wire.Result), []byte("null")) {
		return errInvalidResponse
	}
	var result []matrixSeries
	if err := json.Unmarshal(wire.Result, &result); err != nil {
		return err
	}
	data.ResultType = wire.ResultType
	data.Result = result
	return nil
}

func (series *matrixSeries) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Metric json.RawMessage `json:"metric"`
		Values json.RawMessage `json:"values"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if len(wire.Metric) == 0 ||
		len(wire.Values) == 0 ||
		bytes.Equal(bytes.TrimSpace(wire.Metric), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(wire.Values), []byte("null")) {
		return errInvalidResponse
	}
	var metric map[string]string
	if err := json.Unmarshal(wire.Metric, &metric); err != nil {
		return err
	}
	var values []json.RawMessage
	if err := json.Unmarshal(wire.Values, &values); err != nil {
		return err
	}
	series.Metric = metric
	series.Values = values
	return nil
}

func sampleTime(sample Sample) time.Time {
	value, err := time.Parse(time.RFC3339Nano, sample.Timestamp)
	if err != nil {
		panic("normalized sample has invalid timestamp")
	}
	return value
}

func decodeSample(raw json.RawMessage, start time.Time, end time.Time) (Sample, bool, error) {
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
		return Sample{}, false, errInvalidResponse
	}
	rawTimestamp := bytes.TrimSpace(pair[0])
	if len(rawTimestamp) == 0 ||
		(rawTimestamp[0] != '-' &&
			(rawTimestamp[0] < '0' || rawTimestamp[0] > '9')) {
		return Sample{}, false, errInvalidResponse
	}
	var timestamp json.Number
	timestampDecoder := json.NewDecoder(bytes.NewReader(rawTimestamp))
	timestampDecoder.UseNumber()
	if err := timestampDecoder.Decode(&timestamp); err != nil {
		return Sample{}, false, errInvalidResponse
	}
	if err := requireJSONEOF(timestampDecoder); err != nil {
		return Sample{}, false, errInvalidResponse
	}
	seconds, err := strconv.ParseFloat(timestamp.String(), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return Sample{}, false, errInvalidResponse
	}
	whole, fraction := math.Modf(seconds)
	if whole < math.MinInt64 || whole > math.MaxInt64 {
		return Sample{}, false, errInvalidResponse
	}
	timestampValue := time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC()
	if timestampValue.Year() < 1 || timestampValue.Year() > 9999 {
		return Sample{}, false, errInvalidResponse
	}

	var encodedValue string
	if err := json.Unmarshal(pair[1], &encodedValue); err != nil {
		return Sample{}, false, errInvalidResponse
	}
	value, err := strconv.ParseFloat(encodedValue, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return Sample{}, false, errInvalidResponse
	}
	if timestampValue.Before(start) || !timestampValue.Before(end) {
		return Sample{}, false, nil
	}
	return Sample{
		Timestamp: timestampValue.Format(time.RFC3339Nano),
		Value:     value,
	}, true, nil
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
