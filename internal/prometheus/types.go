// Package prometheus collects a bounded, built-in set of Prometheus range
// queries through a loopback-only telemetry tunnel.
package prometheus

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	MetricsArtifactPath  = "prometheus/metrics.jsonl"
	CoverageArtifactPath = "prometheus/coverage.json"

	DefaultMaxResponseBytes         int64 = 8 << 20
	DefaultMaxRetainedBytesPerQuery int64 = 4 << 20
	DefaultMaxTotalRetainedBytes    int64 = 16 << 20
	DefaultMaxQueries                     = 32
	DefaultMaxSeriesPerQuery              = 200
	DefaultMaxSamplesPerSeries            = 1000
	DefaultStep                           = time.Minute
	DefaultOverallTimeout                 = 5 * time.Minute
	DefaultMaxWindow                      = 24 * time.Hour

	MinimumStep = 15 * time.Second
	MaximumStep = 15 * time.Minute

	MaximumResponseBytes         int64 = 64 << 20
	MaximumRetainedBytesPerQuery int64 = 64 << 20
	MaximumTotalRetainedBytes    int64 = 256 << 20
	MaximumQueries                     = 32
	MaximumSeriesPerQuery              = 1000
	MaximumSamplesPerSeries            = 10000
	MaximumNamespaces                  = 100
	MaximumCommandTimeout              = 5 * time.Minute
	MaximumDiscoveryTimeout            = 5 * time.Minute
	MaximumReadinessTimeout            = 5 * time.Minute
	MaximumConnectTimeout              = time.Minute
	MaximumRequestTimeout              = 5 * time.Minute
	MaximumIdleTimeout                 = time.Minute
	MaximumOverallTimeout              = 30 * time.Minute
	MaximumWindow                      = 24 * time.Hour
)

const (
	DefaultCommandTimeout   = 30 * time.Second
	DefaultDiscoveryTimeout = 45 * time.Second
	DefaultReadinessTimeout = 30 * time.Second
	DefaultConnectTimeout   = 10 * time.Second
	DefaultRequestTimeout   = 30 * time.Second
	DefaultIdleTimeout      = 15 * time.Second
)

var (
	ErrInvalidConfig   = errors.New("prometheus: invalid configuration")
	ErrInvalidCatalog  = errors.New("prometheus: invalid embedded catalog")
	ErrCoverageInvalid = errors.New("prometheus: incomplete coverage")
)

// Config controls one bounded collection. Start is inclusive and End is
// exclusive. Both must be UTC and the interval may not exceed MaximumWindow.
type Config struct {
	Namespace     string
	Namespaces    []string
	AllNamespaces bool
	Context       string
	Kubeconfig    string
	Start         time.Time
	End           time.Time

	CommandTimeout   time.Duration
	DiscoveryTimeout time.Duration
	ReadinessTimeout time.Duration
	ConnectTimeout   time.Duration
	RequestTimeout   time.Duration
	IdleTimeout      time.Duration
	OverallTimeout   time.Duration

	MaxResponseBytes         int64
	MaxRetainedBytesPerQuery int64
	MaxTotalRetainedBytes    int64
	MaxQueries               int
	MaxSeriesPerQuery        int
	MaxSamplesPerSeries      int
	Step                     time.Duration
	MaxWindow                time.Duration
}

// DefaultConfig returns the immutable package defaults. Namespace and bounds
// remain unset because callers must choose them explicitly.
func DefaultConfig() Config {
	return Config{
		CommandTimeout:           DefaultCommandTimeout,
		DiscoveryTimeout:         DefaultDiscoveryTimeout,
		ReadinessTimeout:         DefaultReadinessTimeout,
		ConnectTimeout:           DefaultConnectTimeout,
		RequestTimeout:           DefaultRequestTimeout,
		IdleTimeout:              DefaultIdleTimeout,
		OverallTimeout:           DefaultOverallTimeout,
		MaxResponseBytes:         DefaultMaxResponseBytes,
		MaxRetainedBytesPerQuery: DefaultMaxRetainedBytesPerQuery,
		MaxTotalRetainedBytes:    DefaultMaxTotalRetainedBytes,
		MaxQueries:               DefaultMaxQueries,
		MaxSeriesPerQuery:        DefaultMaxSeriesPerQuery,
		MaxSamplesPerSeries:      DefaultMaxSamplesPerSeries,
		Step:                     DefaultStep,
		MaxWindow:                DefaultMaxWindow,
	}
}

// WithDefaults fills zero-valued limit and deadline fields. It never changes
// identity or time-bound fields.
func (config Config) WithDefaults() Config {
	config.Namespaces = append([]string(nil), config.Namespaces...)
	sort.Strings(config.Namespaces)
	defaults := DefaultConfig()
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaults.CommandTimeout
	}
	if config.DiscoveryTimeout == 0 {
		config.DiscoveryTimeout = defaults.DiscoveryTimeout
	}
	if config.ReadinessTimeout == 0 {
		config.ReadinessTimeout = defaults.ReadinessTimeout
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaults.ConnectTimeout
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaults.RequestTimeout
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = defaults.IdleTimeout
	}
	if config.OverallTimeout == 0 {
		config.OverallTimeout = defaults.OverallTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaults.MaxResponseBytes
	}
	if config.MaxRetainedBytesPerQuery == 0 {
		config.MaxRetainedBytesPerQuery = defaults.MaxRetainedBytesPerQuery
	}
	if config.MaxTotalRetainedBytes == 0 {
		config.MaxTotalRetainedBytes = defaults.MaxTotalRetainedBytes
	}
	if config.MaxQueries == 0 {
		config.MaxQueries = defaults.MaxQueries
	}
	if config.MaxSeriesPerQuery == 0 {
		config.MaxSeriesPerQuery = defaults.MaxSeriesPerQuery
	}
	if config.MaxSamplesPerSeries == 0 {
		config.MaxSamplesPerSeries = defaults.MaxSamplesPerSeries
	}
	if config.Step == 0 {
		config.Step = defaults.Step
	}
	if config.MaxWindow == 0 {
		config.MaxWindow = defaults.MaxWindow
	}
	return config
}

// Validate applies defaults and verifies all fail-closed constraints.
func (config Config) Validate() error {
	return validateConfig(config.WithDefaults())
}

func validateConfig(config Config) error {
	switch {
	case !validDNSLabel(config.Namespace):
		return invalidConfig("namespace must be a DNS label")
	case config.Start.IsZero() || config.End.IsZero():
		return invalidConfig("start and end are required")
	case !isUTC(config.Start) || !isUTC(config.End):
		return invalidConfig("start and end must be UTC")
	case !config.Start.Before(config.End):
		return invalidConfig("start must precede end")
	case config.MaxWindow <= 0 || config.MaxWindow > MaximumWindow:
		return invalidConfig("maximum window is out of range")
	case config.End.Sub(config.Start) > config.MaxWindow:
		return invalidConfig("requested window exceeds maximum")
	case !boundedDuration(config.CommandTimeout, MaximumCommandTimeout):
		return invalidConfig("command timeout is out of range")
	case !boundedDuration(config.DiscoveryTimeout, MaximumDiscoveryTimeout):
		return invalidConfig("discovery timeout is out of range")
	case !boundedDuration(config.ReadinessTimeout, MaximumReadinessTimeout):
		return invalidConfig("readiness timeout is out of range")
	case !boundedDuration(config.ConnectTimeout, MaximumConnectTimeout):
		return invalidConfig("connect timeout is out of range")
	case !boundedDuration(config.RequestTimeout, MaximumRequestTimeout):
		return invalidConfig("request timeout is out of range")
	case !boundedDuration(config.IdleTimeout, MaximumIdleTimeout):
		return invalidConfig("idle timeout is out of range")
	case !boundedDuration(config.OverallTimeout, MaximumOverallTimeout):
		return invalidConfig("overall timeout is out of range")
	case config.OverallTimeout < config.RequestTimeout:
		return invalidConfig("overall timeout must cover a request timeout")
	case config.MaxResponseBytes <= 0 || config.MaxResponseBytes > MaximumResponseBytes:
		return invalidConfig("response byte limit is out of range")
	case config.MaxRetainedBytesPerQuery <= 0 ||
		config.MaxRetainedBytesPerQuery > MaximumRetainedBytesPerQuery:
		return invalidConfig("per-query retained byte limit is out of range")
	case config.MaxTotalRetainedBytes <= 0 ||
		config.MaxTotalRetainedBytes > MaximumTotalRetainedBytes:
		return invalidConfig("total retained byte limit is out of range")
	case config.MaxRetainedBytesPerQuery > config.MaxTotalRetainedBytes:
		return invalidConfig("per-query retained byte limit exceeds total limit")
	case config.MaxQueries <= 0 || config.MaxQueries > MaximumQueries:
		return invalidConfig("query limit is out of range")
	case config.MaxSeriesPerQuery <= 0 || config.MaxSeriesPerQuery > MaximumSeriesPerQuery:
		return invalidConfig("series limit is out of range")
	case config.MaxSamplesPerSeries <= 0 || config.MaxSamplesPerSeries > MaximumSamplesPerSeries:
		return invalidConfig("sample limit is out of range")
	case config.Step < MinimumStep || config.Step > MaximumStep:
		return invalidConfig("step is out of range")
	case config.Step%time.Second != 0:
		return invalidConfig("step must be a whole number of seconds")
	}
	return validateNamespaceScope(config)
}

func validateNamespaceScope(config Config) error {
	switch {
	case config.AllNamespaces && len(config.Namespaces) != 0:
		return invalidConfig("all-namespaces scope cannot include explicit namespaces")
	case !config.AllNamespaces &&
		(len(config.Namespaces) == 0 || len(config.Namespaces) > MaximumNamespaces):
		return invalidConfig("explicit namespace scope is out of range")
	}
	seen := make(map[string]struct{}, len(config.Namespaces))
	for _, namespace := range config.Namespaces {
		if !validDNSLabel(namespace) {
			return invalidConfig("workload namespace must be a DNS label")
		}
		if _, duplicate := seen[namespace]; duplicate {
			return invalidConfig("workload namespaces must be unique")
		}
		seen[namespace] = struct{}{}
	}
	return nil
}

func boundedDuration(value time.Duration, maximum time.Duration) bool {
	return value > 0 && value <= maximum
}

func invalidConfig(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, message)
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

// Query is one immutable catalog entry. Returned query values are copies.
type Query struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	Description  string   `json:"description"`
	PromQL       string   `json:"promql"`
	StepSeconds  int64    `json:"step_seconds"`
	RetainLabels []string `json:"retain_labels"`
}

// Catalog describes the built-in query set.
type Catalog struct {
	Version string  `json:"version"`
	Queries []Query `json:"queries"`
}

type CoverageState string

const (
	CoverageCollected CoverageState = "collected"
	CoverageNoData    CoverageState = "no_data"
	CoveragePartial   CoverageState = "partial"
	CoverageFailed    CoverageState = "failed"
	CoverageSkipped   CoverageState = "skipped"
)

type ReportState string

const (
	ReportComplete ReportState = "complete"
	ReportPartial  ReportState = "partial"
	ReportFailed   ReportState = "failed"
)

// Coverage records only stable, non-sensitive query outcomes.
type Coverage struct {
	QueryID         string        `json:"query_id"`
	Category        string        `json:"category"`
	State           CoverageState `json:"state"`
	Reason          string        `json:"reason,omitempty"`
	Diagnostic      string        `json:"diagnostic,omitempty"`
	SeriesFound     int           `json:"series_found"`
	SeriesRetained  int           `json:"series_retained"`
	SamplesFound    int           `json:"samples_found"`
	SamplesRetained int           `json:"samples_retained"`
	RetainedBytes   int64         `json:"retained_bytes"`
	Truncated       bool          `json:"truncated"`
}

// Artifact identifies sanitized output staged in the support bundle.
type Artifact struct {
	Path    string `json:"path"`
	Records int    `json:"records"`
	Bytes   int64  `json:"bytes"`
}

// Report summarizes collection without exposing raw Prometheus data.
type Report struct {
	CatalogVersion string `json:"catalog_version"`

	RequestedStart string `json:"requested_start"`
	RequestedEnd   string `json:"requested_end"`
	ActualStart    string `json:"actual_start"`
	ActualEnd      string `json:"actual_end"`
	StepSeconds    int64  `json:"step_seconds"`

	State      ReportState `json:"state"`
	Reason     string      `json:"reason,omitempty"`
	Diagnostic string      `json:"diagnostic,omitempty"`

	Coverage        []Coverage `json:"coverage"`
	Artifacts       []Artifact `json:"artifacts,omitempty"`
	RetainedRecords int        `json:"retained_records"`
	RetainedBytes   int64      `json:"retained_bytes"`
	Truncated       bool       `json:"truncated"`
}

// Sample is the normalized range sample wire model.
type Sample struct {
	Timestamp string  `json:"timestamp"`
	Value     float64 `json:"value"`
}

// Record is one normalized and redacted matrix series.
type Record struct {
	SchemaVersion string            `json:"schema_version"`
	QueryID       string            `json:"query_id"`
	Category      string            `json:"category"`
	Labels        map[string]string `json:"labels,omitempty"`
	Samples       []Sample          `json:"samples"`
}

const recordSchemaVersion = "1"

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for index, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-'
		if !valid || (character == '-' && (index == 0 || index == len(value)-1)) {
			return false
		}
	}
	return true
}
