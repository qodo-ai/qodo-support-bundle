package prometheus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func TestNormalizeRangeResponseRedactsFiltersAndSorts(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	config.MaxSamplesPerSeries = 10
	query := Query{
		ID:           "test_query",
		Category:     "request_rate",
		RetainLabels: []string{"namespace", "service"},
	}
	response := `{
		"status":"success",
		"data":{"resultType":"matrix","result":[
			{"metric":{"namespace":"z","service":"token=very-secret","unknown":"drop-me"},"values":[
				[1790676120,"2"],[1790676000,"0"],[1790676060,"1"],[1790679600,"999"]
			]},
			{"metric":{"namespace":"a","service":"api","credential":"drop-me"},"values":[
				[1790676000,"3"]
			]}
		]}
	}`
	result, err := normalizeRangeResponse(
		[]byte(response),
		query,
		config,
		redact.New(),
	)
	if err != nil {
		t.Fatalf("normalizeRangeResponse() error = %v", err)
	}
	if len(result.records) != 2 {
		t.Fatalf("records = %d", len(result.records))
	}
	if result.records[0].Labels["namespace"] != "a" {
		t.Fatalf("records are not sorted: %+v", result.records)
	}
	second := result.records[1]
	if second.Labels["service"] != "token=[REDACTED]" {
		t.Fatalf("service was not redacted: %q", second.Labels["service"])
	}
	if _, exists := second.Labels["unknown"]; exists {
		t.Fatal("unknown label retained")
	}
	if len(second.Samples) != 3 ||
		second.Samples[0].Value != 0 ||
		second.Samples[1].Value != 1 ||
		second.Samples[2].Value != 2 {
		t.Fatalf("samples not filtered/sorted: %+v", second.Samples)
	}
	encoded, err := json.Marshal(result.records)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"very-secret", "drop-me", "unknown", "credential", "promql", "url",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("output contains forbidden value %q: %s", forbidden, encoded)
		}
	}
}

func TestNormalizeRangeResponseRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	query := Query{
		ID:           "test_query",
		Category:     "request_rate",
		RetainLabels: []string{"namespace"},
	}
	tests := map[string]string{
		"failure status": `{"status":"error","data":{"resultType":"matrix","result":[]}}`,
		"vector":         `{"status":"success","data":{"resultType":"vector","result":[]}}`,
		"duplicate key":  `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a","namespace":"b"},"values":[]}]}}`,
		"nan":            `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a"},"values":[[1790676000,"NaN"]]}]}}`,
		"inf":            `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a"},"values":[[1790676000,"+Inf"]]}]}}`,
		"string time":    `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a"},"values":[["1790676000","1"]]}]}}`,
		"duplicate series": `{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"namespace":"a"},"values":[]},
			{"metric":{"namespace":"a"},"values":[]}
		]}}`,
		"unknown field": `{"status":"success","warnings":["secret"],"data":{"resultType":"matrix","result":[]}}`,
		"null result":   `{"status":"success","data":{"resultType":"matrix","result":null}}`,
		"null metric":   `{"status":"success","data":{"resultType":"matrix","result":[{"metric":null,"values":[]}]}}`,
		"null values":   `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":null}]}}`,
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeRangeResponse(
				[]byte(response),
				query,
				config,
				redact.New(),
			); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestNormalizeRangeResponseAppliesSeriesAndSampleLimits(t *testing.T) {
	t.Parallel()
	config := testConfig().WithDefaults()
	config.MaxSeriesPerQuery = 1
	config.MaxSamplesPerSeries = 1
	query := Query{
		ID:           "test_query",
		Category:     "request_rate",
		RetainLabels: []string{"namespace"},
	}
	response := `{"status":"success","data":{"resultType":"matrix","result":[
		{"metric":{"namespace":"b"},"values":[[1790676000,"1"],[1790676060,"2"]]},
		{"metric":{"namespace":"a"},"values":[[1790676000,"3"]]}
	]}}`
	result, err := normalizeRangeResponse([]byte(response), query, config, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !result.seriesLimited || !result.sampleLimited ||
		len(result.records) != 1 ||
		result.records[0].Labels["namespace"] != "a" ||
		len(result.records[0].Samples) != 1 {
		t.Fatalf("limits not applied deterministically: %+v", result)
	}
}

func testConfig() Config {
	start := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	return Config{
		Namespace:  "observability",
		Namespaces: []string{"team-a"},
		Start:      start,
		End:        start.Add(time.Hour),
	}
}
