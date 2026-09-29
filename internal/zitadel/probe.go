package zitadel

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

const (
	MaxOutputBytes    int64 = 32 << 10
	MaxTargetPodBytes int64 = 2 << 20

	StatusPassed = "passed"
	StatusFailed = "failed"

	ReasonAuthBackendNotOIDC    = "auth_backend_not_oidc"
	ReasonSettingsUnavailable   = "settings_unavailable"
	ReasonInvalidIssuer         = "invalid_issuer"
	ReasonHTTPClientUnavailable = "http_client_unavailable"
	ReasonRedirectRejected      = "redirect_rejected"
	ReasonHTTPError             = "http_error"
	ReasonUnsupportedEncoding   = "unsupported_encoding"
	ReasonResponseTooLarge      = "response_too_large"
	ReasonInvalidJSON           = "invalid_json"
	ReasonInvalidDiscovery      = "invalid_discovery"
	ReasonIssuerMismatch        = "issuer_mismatch"
	ReasonJWKSURIMismatch       = "jwks_uri_mismatch"
	ReasonInvalidJWKS           = "invalid_jwks"
	ReasonTLSError              = "tls_error"
	ReasonDNSError              = "dns_error"
	ReasonConnectionRefused     = "connection_refused"
	ReasonProxyError            = "proxy_error"
	ReasonTimeout               = "timeout"
	ReasonConnectionError       = "connection_error"

	ReasonForbidden        = "forbidden"
	ReasonUnauthorized     = "unauthorized"
	ReasonNotFound         = "not_found"
	ReasonConnectionFailed = "connection_failed"
	ReasonKubectlError     = "kubectl_error"
	ReasonExecError        = "exec_error"

	ReasonPodQueryTimeout     = "pod_query_timeout"
	ReasonPodOutputLimit      = "pod_output_limit"
	ReasonPodInvalidResponse  = "pod_invalid_response"
	ReasonPodNotRunning       = "pod_not_running"
	ReasonContainerNotRunning = "container_not_running"
	ReasonExecTimeout         = "exec_timeout"
	ReasonOutputLimit         = "output_limit"
	ReasonInvalidResponse     = "invalid_response"
)

const (
	checkConfiguration = "configuration"
	checkDiscovery     = "discovery"
	checkJWKS          = "jwks"
)

//go:embed probe.py
var Source string

// Config identifies the existing Platform container used for the probe.
type Config struct {
	Namespace     string
	Pod           string
	Container     string
	Context       string
	Kubeconfig    string
	QueryTimeout  time.Duration
	ProbeTimeout  time.Duration
	PythonCommand string
}

// Check is one fixed, non-secret connectivity result from the in-pod probe.
type Check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	HTTPStatus *int   `json:"http_status,omitempty"`
}

// Report is the schema-v1 connectivity artifact.
type Report struct {
	SchemaVersion int     `json:"schema_version"`
	Issuer        string  `json:"issuer,omitempty"`
	Checks        []Check `json:"checks"`
	Pod           string  `json:"pod"`
	Container     string  `json:"container"`
}

type probeReport struct {
	SchemaVersion int     `json:"schema_version"`
	Issuer        string  `json:"issuer,omitempty"`
	Checks        []Check `json:"checks"`
	Reason        string  `json:"reason,omitempty"`
}

// Outcome distinguishes diagnostic check failures from collection failures.
type Outcome struct {
	Report *Report
	Data   []byte
	Reason string
}

// Collect verifies the target then executes the embedded probe without a shell.
func Collect(
	ctx context.Context,
	config Config,
	runner kubernetes.Runner,
	redactor *redact.Redactor,
) Outcome {
	if reason := verifyTarget(ctx, config, runner); reason != "" {
		return Outcome{Reason: reason}
	}
	python := config.PythonCommand
	if python == "" {
		python = "python"
	}
	internalTimeout := config.ProbeTimeout - time.Second
	if internalTimeout < 100*time.Millisecond {
		internalTimeout = 100 * time.Millisecond
	}
	arguments := append(globalArguments(config),
		"exec",
		"--namespace", config.Namespace,
		"pod/"+config.Pod,
		"--container", config.Container,
		"--",
		python, "-B", "-c", Source,
		strconv.FormatFloat(internalTimeout.Seconds(), 'f', 3, 64),
	)
	probeContext, cancel := context.WithTimeout(ctx, config.ProbeTimeout)
	result, err := runner.Run(probeContext, MaxOutputBytes, arguments...)
	timedOut := errors.Is(probeContext.Err(), context.DeadlineExceeded)
	cancel()
	if timedOut {
		return Outcome{Reason: ReasonExecTimeout}
	}
	if result.Truncated {
		return Outcome{Reason: ReasonOutputLimit}
	}
	if isInternalTimeout(result.Stdout) {
		return Outcome{Reason: ReasonExecTimeout}
	}
	if err != nil {
		return Outcome{Reason: commandFailureReason(result.Stderr, ReasonExecError)}
	}
	report, err := validateReport(result.Stdout)
	if err != nil {
		return Outcome{Reason: ReasonInvalidResponse}
	}
	report.Pod = config.Pod
	report.Container = config.Container
	report.Issuer = redactor.Text(report.Issuer)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Outcome{Reason: ReasonInvalidResponse}
	}
	data = append(data, '\n')
	return Outcome{Report: report, Data: data}
}

func verifyTarget(
	ctx context.Context,
	config Config,
	runner kubernetes.Runner,
) string {
	arguments := append(globalArguments(config),
		"get", "pod", config.Pod,
		"--namespace", config.Namespace,
		"--output", "json",
	)
	queryContext, cancel := context.WithTimeout(ctx, config.QueryTimeout)
	result, err := runner.Run(queryContext, MaxTargetPodBytes, arguments...)
	timedOut := errors.Is(queryContext.Err(), context.DeadlineExceeded)
	cancel()
	if timedOut {
		return ReasonPodQueryTimeout
	}
	if result.Truncated {
		return ReasonPodOutputLimit
	}
	if err != nil {
		return commandFailureReason(result.Stderr, ReasonKubectlError)
	}
	var pod struct {
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name  string         `json:"name"`
				State map[string]any `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if !json.Valid(result.Stdout) {
		return ReasonPodInvalidResponse
	}
	if err := json.Unmarshal(result.Stdout, &pod); err != nil {
		return ReasonPodInvalidResponse
	}
	if pod.Status.Phase == "" {
		return ReasonPodInvalidResponse
	}
	if pod.Status.Phase != "Running" {
		return ReasonPodNotRunning
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == config.Container {
			if running, exists := status.State["running"]; exists && running != nil {
				return ""
			}
			return ReasonContainerNotRunning
		}
	}
	return ReasonContainerNotRunning
}

func validateReport(data []byte) (*Report, error) {
	if len(data) == 0 || int64(len(data)) > MaxOutputBytes {
		return nil, errors.New("invalid report size")
	}
	var wire probeReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if wire.SchemaVersion != 1 {
		return nil, errors.New("unsupported schema")
	}
	if wire.Reason != "" {
		return nil, errors.New("unexpected probe sentinel")
	}
	switch len(wire.Checks) {
	case 1:
		check := wire.Checks[0]
		if check.Name != checkConfiguration ||
			check.Status != StatusFailed ||
			!configurationReasons[check.Reason] ||
			check.HTTPStatus != nil ||
			wire.Issuer != "" {
			return nil, errors.New("invalid configuration report")
		}
	case 2:
		if wire.Checks[0].Name != checkDiscovery ||
			wire.Checks[1].Name != checkJWKS ||
			!validIssuer(wire.Issuer) {
			return nil, errors.New("invalid connectivity report")
		}
		for _, check := range wire.Checks {
			if err := validateNetworkCheck(check); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("invalid check count")
	}
	return &Report{
		SchemaVersion: wire.SchemaVersion,
		Issuer:        wire.Issuer,
		Checks:        wire.Checks,
	}, nil
}

func validateNetworkCheck(check Check) error {
	switch check.Status {
	case StatusPassed:
		if check.Reason != "" || check.HTTPStatus == nil || *check.HTTPStatus != 200 {
			return errors.New("invalid passed check")
		}
	case StatusFailed:
		if !networkReasons[check.Reason] {
			return errors.New("invalid failure reason")
		}
		if check.HTTPStatus != nil &&
			(*check.HTTPStatus < 100 || *check.HTTPStatus > 599) {
			return errors.New("invalid HTTP status")
		}
		switch check.Reason {
		case ReasonRedirectRejected:
			if check.HTTPStatus == nil ||
				*check.HTTPStatus < 300 ||
				*check.HTTPStatus > 399 {
				return errors.New("invalid redirect status")
			}
		case ReasonHTTPError:
			if check.HTTPStatus == nil ||
				*check.HTTPStatus == 200 ||
				(*check.HTTPStatus >= 300 && *check.HTTPStatus <= 399) {
				return errors.New("invalid HTTP error status")
			}
		case ReasonTLSError, ReasonDNSError, ReasonConnectionRefused,
			ReasonProxyError, ReasonTimeout, ReasonConnectionError:
			if check.HTTPStatus != nil {
				return errors.New("transport failure included HTTP status")
			}
		default:
			if check.HTTPStatus == nil || *check.HTTPStatus != 200 {
				return errors.New("response failure requires HTTP 200")
			}
		}
	default:
		return errors.New("invalid check status")
	}
	return nil
}

func validIssuer(value string) bool {
	if value == "" || len(value) > 2048 || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	parsed, err := url.Parse(value)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Hostname() != "" &&
		parsed.Port() != "0" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == ""
}

func isInternalTimeout(data []byte) bool {
	if len(data) == 0 || int64(len(data)) > MaxOutputBytes {
		return false
	}
	var wire probeReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureEOF(decoder) != nil {
		return false
	}
	return wire.SchemaVersion == 1 &&
		wire.Reason == ReasonExecTimeout &&
		wire.Issuer == "" &&
		len(wire.Checks) == 0
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailing data: %w", err)
	}
	return nil
}

func globalArguments(config Config) []string {
	arguments := make([]string, 0, 4)
	if config.Kubeconfig != "" {
		arguments = append(arguments, "--kubeconfig", config.Kubeconfig)
	}
	if config.Context != "" {
		arguments = append(arguments, "--context", config.Context)
	}
	return arguments
}

func commandFailureReason(stderr []byte, fallback string) string {
	message := strings.ToLower(string(stderr))
	for _, category := range []struct {
		patterns []string
		reason   string
	}{
		{patterns: []string{"forbidden"}, reason: ReasonForbidden},
		{patterns: []string{"unauthorized"}, reason: ReasonUnauthorized},
		{
			patterns: []string{"notfound", "not found"},
			reason:   ReasonNotFound,
		},
		{
			patterns: []string{
				"certificate",
				"x509:",
				"tls handshake",
			},
			reason: ReasonTLSError,
		},
		{
			patterns: []string{
				"unable to connect",
				"connection refused",
				"connection reset",
				"dial tcp",
				"no such host",
			},
			reason: ReasonConnectionFailed,
		},
	} {
		for _, pattern := range category.patterns {
			if strings.Contains(message, pattern) {
				return category.reason
			}
		}
	}
	return fallback
}

func (report Report) FailedChecks() int {
	failed := 0
	for _, check := range report.Checks {
		if check.Status == StatusFailed {
			failed++
		}
	}
	return failed
}

var configurationReasons = map[string]bool{
	ReasonAuthBackendNotOIDC:    true,
	ReasonSettingsUnavailable:   true,
	ReasonInvalidIssuer:         true,
	ReasonHTTPClientUnavailable: true,
}

var networkReasons = map[string]bool{
	ReasonRedirectRejected:    true,
	ReasonHTTPError:           true,
	ReasonUnsupportedEncoding: true,
	ReasonResponseTooLarge:    true,
	ReasonInvalidJSON:         true,
	ReasonInvalidDiscovery:    true,
	ReasonIssuerMismatch:      true,
	ReasonJWKSURIMismatch:     true,
	ReasonInvalidJWKS:         true,
	ReasonTLSError:            true,
	ReasonDNSError:            true,
	ReasonConnectionRefused:   true,
	ReasonProxyError:          true,
	ReasonTimeout:             true,
	ReasonConnectionError:     true,
}
