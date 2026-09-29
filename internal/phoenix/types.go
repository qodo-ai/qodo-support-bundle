// Package phoenix collects bounded Arize Phoenix traces through a
// loopback-only Kubernetes telemetry tunnel.
package phoenix

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	TracesArtifactPath   = "phoenix/traces.jsonl"
	CoverageArtifactPath = "phoenix/coverage.json"

	ContractVersion = "arize-phoenix-rest-v1-15.5.1"

	DefaultCommandTimeout      = 30 * time.Second
	DefaultDiscoveryTimeout    = 45 * time.Second
	DefaultReadinessTimeout    = 30 * time.Second
	DefaultConnectTimeout      = 10 * time.Second
	DefaultRequestTimeout      = 30 * time.Second
	DefaultIdleTimeout         = 15 * time.Second
	DefaultOverallTimeout      = 5 * time.Minute
	DefaultMaxWindow           = 24 * time.Hour
	DefaultMaxResponseBytes    = int64(8 << 20)
	DefaultMaxProjects         = 100
	DefaultMaxTraces           = 1000
	DefaultMaxSpans            = 10000
	DefaultMaxPages            = 1000
	DefaultPageSize            = 100
	DefaultMaxRetainedPerTrace = int64(1 << 20)
	DefaultMaxTotalRetained    = int64(32 << 20)
	MaximumCommandTimeout      = 5 * time.Minute
	MaximumDiscoveryTimeout    = 5 * time.Minute
	MaximumReadinessTimeout    = 5 * time.Minute
	MaximumConnectTimeout      = time.Minute
	MaximumRequestTimeout      = 5 * time.Minute
	MaximumIdleTimeout         = time.Minute
	MaximumOverallTimeout      = 30 * time.Minute
	MaximumWindow              = 24 * time.Hour
	MaximumResponseBytes       = int64(64 << 20)
	MaximumProjects            = 1000
	MaximumTraces              = 10000
	MaximumSpans               = 100000
	MaximumPages               = 10000
	MaximumPageSize            = 1000
	MaximumRetainedPerTrace    = int64(16 << 20)
	MaximumTotalRetained       = int64(256 << 20)
)

const recordSchemaVersion = "1"

var (
	ErrInvalidConfig   = errors.New("phoenix: invalid configuration")
	ErrArtifactStaging = errors.New("phoenix: artifact staging failed")
	ErrCoverageInvalid = errors.New("phoenix: incomplete coverage")
	traceIDPattern     = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	spanIDPattern      = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)
)

// Config controls one Phoenix collection. Start is inclusive and End is
// exclusive. TraceID selects exact-trace mode when set.
type Config struct {
	Namespace  string
	Context    string
	Kubeconfig string
	Start      time.Time
	End        time.Time
	TraceID    string

	CommandTimeout   time.Duration
	DiscoveryTimeout time.Duration
	ReadinessTimeout time.Duration
	ConnectTimeout   time.Duration
	RequestTimeout   time.Duration
	IdleTimeout      time.Duration
	OverallTimeout   time.Duration

	MaxWindow                time.Duration
	MaxResponseBytes         int64
	MaxProjects              int
	MaxTraces                int
	MaxSpans                 int
	MaxPages                 int
	PageSize                 int
	MaxRetainedBytesPerTrace int64
	MaxTotalRetainedBytes    int64
}

// DefaultConfig returns immutable package defaults.
func DefaultConfig() Config {
	return Config{
		CommandTimeout:           DefaultCommandTimeout,
		DiscoveryTimeout:         DefaultDiscoveryTimeout,
		ReadinessTimeout:         DefaultReadinessTimeout,
		ConnectTimeout:           DefaultConnectTimeout,
		RequestTimeout:           DefaultRequestTimeout,
		IdleTimeout:              DefaultIdleTimeout,
		OverallTimeout:           DefaultOverallTimeout,
		MaxWindow:                DefaultMaxWindow,
		MaxResponseBytes:         DefaultMaxResponseBytes,
		MaxProjects:              DefaultMaxProjects,
		MaxTraces:                DefaultMaxTraces,
		MaxSpans:                 DefaultMaxSpans,
		MaxPages:                 DefaultMaxPages,
		PageSize:                 DefaultPageSize,
		MaxRetainedBytesPerTrace: DefaultMaxRetainedPerTrace,
		MaxTotalRetainedBytes:    DefaultMaxTotalRetained,
	}
}

// WithDefaults fills zero-valued deadline and bound fields and normalizes a
// syntactically valid trace ID to lowercase.
func (config Config) WithDefaults() Config {
	defaults := DefaultConfig()
	fillDuration := func(value *time.Duration, fallback time.Duration) {
		if *value == 0 {
			*value = fallback
		}
	}
	fillInt := func(value *int, fallback int) {
		if *value == 0 {
			*value = fallback
		}
	}
	fillInt64 := func(value *int64, fallback int64) {
		if *value == 0 {
			*value = fallback
		}
	}
	fillDuration(&config.CommandTimeout, defaults.CommandTimeout)
	fillDuration(&config.DiscoveryTimeout, defaults.DiscoveryTimeout)
	fillDuration(&config.ReadinessTimeout, defaults.ReadinessTimeout)
	fillDuration(&config.ConnectTimeout, defaults.ConnectTimeout)
	fillDuration(&config.RequestTimeout, defaults.RequestTimeout)
	fillDuration(&config.IdleTimeout, defaults.IdleTimeout)
	fillDuration(&config.OverallTimeout, defaults.OverallTimeout)
	fillDuration(&config.MaxWindow, defaults.MaxWindow)
	fillInt64(&config.MaxResponseBytes, defaults.MaxResponseBytes)
	fillInt(&config.MaxProjects, defaults.MaxProjects)
	fillInt(&config.MaxTraces, defaults.MaxTraces)
	fillInt(&config.MaxSpans, defaults.MaxSpans)
	fillInt(&config.MaxPages, defaults.MaxPages)
	fillInt(&config.PageSize, defaults.PageSize)
	fillInt64(&config.MaxRetainedBytesPerTrace, defaults.MaxRetainedBytesPerTrace)
	fillInt64(&config.MaxTotalRetainedBytes, defaults.MaxTotalRetainedBytes)
	if traceIDPattern.MatchString(config.TraceID) {
		config.TraceID = strings.ToLower(config.TraceID)
	}
	return config
}

// Validate applies defaults and verifies every fail-closed constraint.
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
	case config.TraceID != "" && !traceIDPattern.MatchString(config.TraceID):
		return invalidConfig("trace id must be 32 hexadecimal characters")
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
	case config.MaxProjects <= 0 || config.MaxProjects > MaximumProjects:
		return invalidConfig("project limit is out of range")
	case config.MaxTraces <= 0 || config.MaxTraces > MaximumTraces:
		return invalidConfig("trace limit is out of range")
	case config.MaxSpans <= 0 || config.MaxSpans > MaximumSpans:
		return invalidConfig("span limit is out of range")
	case config.MaxPages <= 0 || config.MaxPages > MaximumPages:
		return invalidConfig("page limit is out of range")
	case config.PageSize <= 0 || config.PageSize > MaximumPageSize:
		return invalidConfig("page size is out of range")
	case config.MaxRetainedBytesPerTrace <= 0 ||
		config.MaxRetainedBytesPerTrace > MaximumRetainedPerTrace:
		return invalidConfig("per-trace retained byte limit is out of range")
	case config.MaxTotalRetainedBytes <= 0 ||
		config.MaxTotalRetainedBytes > MaximumTotalRetained:
		return invalidConfig("total retained byte limit is out of range")
	case config.MaxRetainedBytesPerTrace > config.MaxTotalRetainedBytes:
		return invalidConfig("per-trace retained byte limit exceeds total limit")
	}
	return nil
}

func boundedDuration(value, maximum time.Duration) bool {
	return value > 0 && value <= maximum
}

func invalidConfig(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, message)
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for index, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-'
		if !valid || character == '-' && (index == 0 || index == len(value)-1) {
			return false
		}
	}
	return true
}

type CoverageState string

const (
	CoverageCollected CoverageState = "collected"
	CoverageNoData    CoverageState = "no_data"
	CoveragePartial   CoverageState = "partial"
	CoverageFailed    CoverageState = "failed"
)

type ReportState string

const (
	ReportComplete ReportState = "complete"
	ReportPartial  ReportState = "partial"
	ReportFailed   ReportState = "failed"
)

// Coverage contains only stable counters and sanitized failure categories.
type Coverage struct {
	State          CoverageState `json:"state"`
	Reason         string        `json:"reason,omitempty"`
	Diagnostic     string        `json:"diagnostic,omitempty"`
	ProjectsFound  int           `json:"projects_found"`
	ProjectsRead   int           `json:"projects_read"`
	TracesFound    int           `json:"traces_found"`
	TracesRetained int           `json:"traces_retained"`
	SpansFound     int           `json:"spans_found"`
	SpansRetained  int           `json:"spans_retained"`
	PagesRead      int           `json:"pages_read"`
	RetainedBytes  int64         `json:"retained_bytes"`
	Truncated      bool          `json:"truncated"`
}

// Artifact identifies sanitized output staged in the support bundle.
type Artifact struct {
	Path    string `json:"path"`
	Records int    `json:"records"`
	Bytes   int64  `json:"bytes"`
}

// Report summarizes collection without exposing raw Phoenix payloads.
type Report struct {
	ContractVersion string      `json:"contract_version"`
	Mode            string      `json:"mode"`
	RequestedStart  string      `json:"requested_start"`
	RequestedEnd    string      `json:"requested_end"`
	ActualStart     string      `json:"actual_start"`
	ActualEnd       string      `json:"actual_end"`
	TraceID         string      `json:"trace_id,omitempty"`
	State           ReportState `json:"state"`
	Reason          string      `json:"reason,omitempty"`
	Diagnostic      string      `json:"diagnostic,omitempty"`
	Coverage        Coverage    `json:"coverage"`
	Artifacts       []Artifact  `json:"artifacts,omitempty"`
}

// Project is the safe project identity retained in each trace record.
type Project struct {
	ID string `json:"id"`
}

// Span is the normalized safe span model.
type Span struct {
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_id,omitempty"`
	SpanKind   string            `json:"span_kind"`
	StatusCode string            `json:"status_code"`
	Start      string            `json:"start"`
	End        string            `json:"end"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Record is one deterministic project/trace group.
type Record struct {
	SchemaVersion   string  `json:"schema_version"`
	ContractVersion string  `json:"contract_version"`
	Project         Project `json:"project"`
	TraceID         string  `json:"trace_id"`
	Start           string  `json:"start"`
	End             string  `json:"end"`
	Correlation     string  `json:"correlation"`
	Spans           []Span  `json:"spans"`
}

func validTraceID(value string) bool {
	return traceIDPattern.MatchString(value)
}

func validSpanID(value string) bool {
	return spanIDPattern.MatchString(value)
}
