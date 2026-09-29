package prometheus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
)

const (
	expectedPrometheusPort = 9090
	discoveryLabelKey      = "app.kubernetes.io/name"
	discoveryLabelValue    = "prometheus"
	queryRangePath         = "/api/v1/query_range"
)

const (
	reasonQueryLimit        = "query_limit_exceeded"
	reasonSeriesLimit       = "series_limit_exceeded"
	reasonSampleLimit       = "sample_limit_exceeded"
	reasonPerQueryBudget    = "per_query_byte_budget_exceeded"
	reasonTotalBudget       = "total_byte_budget_exceeded"
	reasonResponseLimit     = "response_byte_limit_exceeded"
	reasonMalformed         = "invalid_response"
	reasonHTTPStatus        = "http_status_error"
	reasonRequest           = "request_failed"
	reasonRequestTimeout    = "request_deadline_exceeded"
	reasonIdleTimeout       = "idle_deadline_exceeded"
	reasonDiscovery         = "discovery_failed"
	reasonForward           = "forward_failed"
	reasonTunnelEndpoint    = "invalid_tunnel_endpoint"
	reasonTunnelUnavailable = "tunnel_unavailable"
	reasonCleanup           = "tunnel_cleanup_failed"
	reasonArtifactStaging   = "artifact_staging_failed"
	reasonCanceled          = "collection_canceled"
)

var ErrArtifactStaging = errors.New("prometheus: artifact staging failed")

type queryResult struct {
	body       []byte
	reason     string
	diagnostic string
}

type forwardResult struct {
	tunnel *telemetry.Tunnel
	err    error
}

// Collect discovers Prometheus, opens a loopback tunnel, executes only the
// embedded catalog, and stages normalized redacted artifacts.
func Collect(
	ctx context.Context,
	config Config,
	runner kubernetes.Runner,
	forwarder telemetry.Forwarder,
	sink kubernetes.Sink,
	redactor *redact.Redactor,
) (Report, error) {
	config = config.WithDefaults()
	catalog := BuiltinCatalog()
	report := initialReport(config, catalog)
	if err := validateCollection(config, ctx, runner, forwarder, sink, redactor); err != nil {
		return report, err
	}

	overallCtx, overallCancel := context.WithTimeout(ctx, config.OverallTimeout)
	defer overallCancel()
	deadlineRunner := commandDeadlineRunner{
		runner:  runner,
		timeout: config.CommandTimeout,
	}
	target, err := telemetry.Discover(overallCtx, telemetry.DiscoveryConfig{
		Namespace:        config.Namespace,
		Context:          config.Context,
		Kubeconfig:       config.Kubeconfig,
		Timeout:          config.DiscoveryTimeout,
		MaxResponseBytes: config.MaxResponseBytes,
		LabelMatchers: map[string]string{
			discoveryLabelKey: discoveryLabelValue,
		},
		ExpectedPort: expectedPrometheusPort,
	}, deadlineRunner)
	if err != nil {
		if contextErr := collectionContextError(ctx, overallCtx); contextErr != nil {
			markRemainingCoverage(report.Coverage, reasonCanceled, "context_ended")
			finishReport(&report)
			stageErr := stageCoverage(sink, &report)
			if stageErr != nil {
				return report, stageErr
			}
			return report, contextErr
		}
		markRemainingCoverage(report.Coverage, reasonDiscovery, discoveryDiagnostic(err))
		finishReport(&report)
		if stageErr := stageCoverage(sink, &report); stageErr != nil {
			return report, stageErr
		}
		return report, nil
	}

	tunnel, tunnelCancel, err := openTunnel(
		overallCtx,
		config.ReadinessTimeout,
		forwarder,
		target,
	)
	if err != nil {
		if contextErr := collectionContextError(ctx, overallCtx); contextErr != nil {
			markRemainingCoverage(report.Coverage, reasonCanceled, "context_ended")
			finishReport(&report)
			stageErr := stageCoverage(sink, &report)
			if stageErr != nil {
				return report, stageErr
			}
			return report, contextErr
		}
		markRemainingCoverage(report.Coverage, reasonForward, forwardDiagnostic(err))
		finishReport(&report)
		if stageErr := stageCoverage(sink, &report); stageErr != nil {
			return report, stageErr
		}
		return report, nil
	}
	defer tunnelCancel()

	baseURL, endpointErr := validateTunnelEndpoint(tunnel)
	if endpointErr != nil {
		closeErr := tunnel.Close()
		markRemainingCoverage(report.Coverage, reasonTunnelEndpoint, "endpoint_rejected")
		if closeErr != nil {
			report.Reason = reasonCleanup
			report.Diagnostic = "tunnel_cleanup"
		}
		finishReport(&report)
		if stageErr := stageCoverage(sink, &report); stageErr != nil {
			return report, stageErr
		}
		return report, nil
	}

	client := newHTTPClient(config)
	var metrics bytes.Buffer
	totalRemaining := config.MaxTotalRetainedBytes
	var cancellation error
	for index, query := range catalog.Queries {
		coverage := &report.Coverage[index]
		if index >= config.MaxQueries {
			setCoverageFailure(
				coverage,
				CoverageSkipped,
				reasonQueryLimit,
				"query_limit",
				true,
			)
			continue
		}
		if contextErr := collectionContextError(ctx, overallCtx); contextErr != nil {
			cancellation = contextErr
			setCoverageFailure(
				coverage,
				CoverageSkipped,
				reasonCanceled,
				"context_ended",
				false,
			)
			continue
		}
		if tunnelErr := tunnel.Err(); tunnelErr != nil {
			setCoverageFailure(
				coverage,
				CoverageFailed,
				reasonTunnelUnavailable,
				"tunnel_unavailable",
				false,
			)
			continue
		}

		response := executeRangeQuery(overallCtx, client, baseURL, query, config)
		if response.reason != "" {
			setCoverageFailure(
				coverage,
				CoverageFailed,
				response.reason,
				response.diagnostic,
				response.reason == reasonResponseLimit,
			)
			if contextErr := collectionContextError(ctx, overallCtx); contextErr != nil {
				cancellation = contextErr
			}
			continue
		}
		normalized, normalizeErr := normalizeRangeResponse(
			response.body,
			query,
			config,
			redactor,
		)
		response.body = nil
		if normalizeErr != nil {
			setCoverageFailure(
				coverage,
				CoverageFailed,
				reasonMalformed,
				"matrix_rejected",
				false,
			)
			continue
		}
		retainNormalized(
			&metrics,
			coverage,
			normalized,
			config.MaxRetainedBytesPerQuery,
			&totalRemaining,
		)
	}

	if tunnelErr := tunnel.Err(); tunnelErr != nil {
		report.Reason = reasonTunnelUnavailable
		report.Diagnostic = "tunnel_unavailable"
	}
	if closeErr := tunnel.Close(); closeErr != nil {
		report.Reason = reasonCleanup
		report.Diagnostic = "tunnel_cleanup"
	}
	tunnelCancel()

	finishReport(&report)
	var metricsStagingErr error
	if metrics.Len() > 0 {
		if err := sink.Add(MetricsArtifactPath, append([]byte(nil), metrics.Bytes()...)); err != nil {
			metricsStagingErr = ErrArtifactStaging
			report.Reason = reasonArtifactStaging
			report.Diagnostic = "metrics_staging"
			for index := range report.Coverage {
				coverage := &report.Coverage[index]
				if coverage.SeriesRetained > 0 {
					setCoverageFailure(
						coverage,
						CoveragePartial,
						reasonArtifactStaging,
						"metrics_staging",
						coverage.Truncated,
					)
				}
			}
		} else {
			report.Artifacts = append(report.Artifacts, Artifact{
				Path:    MetricsArtifactPath,
				Records: report.RetainedRecords,
				Bytes:   int64(metrics.Len()),
			})
		}
	}
	finishReport(&report)
	if cancellation == nil {
		cancellation = collectionContextError(ctx, overallCtx)
	}
	if stageErr := stageCoverage(sink, &report); stageErr != nil {
		return report, stageErr
	}
	if metricsStagingErr != nil {
		return report, metricsStagingErr
	}
	if cancellation != nil {
		return report, cancellation
	}
	return report, nil
}

func validateCollection(
	config Config,
	ctx context.Context,
	runner kubernetes.Runner,
	forwarder telemetry.Forwarder,
	sink kubernetes.Sink,
	redactor *redact.Redactor,
) error {
	switch {
	case ctx == nil:
		return invalidConfig("context is required")
	case runner == nil:
		return invalidConfig("runner is required")
	case forwarder == nil:
		return invalidConfig("forwarder is required")
	case sink == nil:
		return invalidConfig("sink is required")
	case redactor == nil || !redactor.Ready():
		return invalidConfig("ready redactor is required")
	}
	return validateConfig(config)
}

func initialReport(config Config, catalog Catalog) Report {
	coverage := make([]Coverage, len(catalog.Queries))
	for index, query := range catalog.Queries {
		coverage[index] = Coverage{
			QueryID:  query.ID,
			Category: query.Category,
			State:    CoverageSkipped,
		}
	}
	return Report{
		CatalogVersion: catalog.Version,
		RequestedStart: config.Start.Format(time.RFC3339Nano),
		RequestedEnd:   config.End.Format(time.RFC3339Nano),
		ActualStart:    config.Start.Format(time.RFC3339Nano),
		ActualEnd:      config.End.Format(time.RFC3339Nano),
		StepSeconds:    int64(config.Step / time.Second),
		State:          ReportFailed,
		Coverage:       coverage,
	}
}

type commandDeadlineRunner struct {
	runner  kubernetes.Runner
	timeout time.Duration
}

func (runner commandDeadlineRunner) Run(
	ctx context.Context,
	maxBytes int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	commandCtx, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()
	result, err := runner.runner.Run(commandCtx, maxBytes, arguments...)
	if commandCtx.Err() != nil && ctx.Err() == nil {
		return result, context.DeadlineExceeded
	}
	return result, err
}

func openTunnel(
	ctx context.Context,
	readinessTimeout time.Duration,
	forwarder telemetry.Forwarder,
	target telemetry.Target,
) (*telemetry.Tunnel, context.CancelFunc, error) {
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	resultChannel := make(chan forwardResult)
	go func() {
		tunnel, err := forwarder.Forward(tunnelCtx, target)
		select {
		case resultChannel <- forwardResult{tunnel: tunnel, err: err}:
		case <-tunnelCtx.Done():
			if tunnel != nil {
				_ = tunnel.Close()
			}
		}
	}()
	timer := time.NewTimer(readinessTimeout)
	defer timer.Stop()
	select {
	case result := <-resultChannel:
		if result.err != nil || result.tunnel == nil {
			if result.tunnel != nil {
				_ = result.tunnel.Close()
			}
			tunnelCancel()
			if result.err == nil {
				result.err = telemetry.ErrForwardStart
			}
			return nil, func() {}, result.err
		}
		return result.tunnel, tunnelCancel, nil
	case <-timer.C:
		tunnelCancel()
		return nil, func() {}, telemetry.ErrForwardTimeout
	case <-ctx.Done():
		tunnelCancel()
		return nil, func() {}, ctx.Err()
	}
}

func validateTunnelEndpoint(tunnel *telemetry.Tunnel) (*url.URL, error) {
	if tunnel == nil {
		return nil, errors.New("nil tunnel")
	}
	parsed, err := url.Parse(tunnel.BaseURL)
	if err != nil ||
		parsed.Scheme != "http" ||
		parsed.Hostname() != "127.0.0.1" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, errors.New("invalid tunnel URL")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid tunnel port")
	}
	if parsed.Host != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) ||
		parsed.Opaque != "" {
		return nil, errors.New("noncanonical tunnel host")
	}
	if tunnel.Port != 0 && tunnel.Port != port {
		return nil, errors.New("tunnel port mismatch")
	}
	return parsed, nil
}

func newHTTPClient(config Config) *http.Client {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		ResponseHeaderTimeout:  min(config.RequestTimeout, config.IdleTimeout),
		MaxResponseHeaderBytes: 64 << 10,
		MaxConnsPerHost:        1,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func executeRangeQuery(
	parent context.Context,
	client *http.Client,
	baseURL *url.URL,
	query Query,
	config Config,
) queryResult {
	renderedPromQL, err := renderScopedPromQL(query, config)
	if err != nil {
		return queryResult{reason: reasonMalformed, diagnostic: "catalog_scope"}
	}
	requestCtx, cancel := context.WithTimeout(parent, config.RequestTimeout)
	defer cancel()
	endpoint := *baseURL
	endpoint.Path = queryRangePath
	parameters := make(url.Values, 4)
	parameters.Set("query", renderedPromQL)
	parameters.Set("start", config.Start.Format(time.RFC3339Nano))
	parameters.Set("end", config.End.Format(time.RFC3339Nano))
	parameters.Set("step", strconv.FormatInt(int64(config.Step/time.Second), 10))
	endpoint.RawQuery = parameters.Encode()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return queryResult{reason: reasonRequest, diagnostic: "request_construction"}
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return queryResult{
				reason:     reasonRequestTimeout,
				diagnostic: "request_timeout",
			}
		}
		return queryResult{reason: reasonRequest, diagnostic: "request_transport"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return queryResult{
			reason:     reasonHTTPStatus,
			diagnostic: httpStatusDiagnostic(response.StatusCode),
		}
	}
	if response.ContentLength > config.MaxResponseBytes {
		return queryResult{
			reason:     reasonResponseLimit,
			diagnostic: "response_oversize",
		}
	}
	body, readReason := readBoundedBody(
		requestCtx,
		cancel,
		response.Body,
		config.MaxResponseBytes,
		config.IdleTimeout,
	)
	if readReason != "" {
		diagnostic := "response_read"
		switch readReason {
		case reasonResponseLimit:
			diagnostic = "response_oversize"
		case reasonIdleTimeout:
			diagnostic = "response_idle"
		case reasonRequestTimeout:
			diagnostic = "request_timeout"
		}
		return queryResult{reason: readReason, diagnostic: diagnostic}
	}
	return queryResult{body: body}
}

type bodyChunk struct {
	data []byte
	err  error
}

func readBoundedBody(
	ctx context.Context,
	cancel context.CancelFunc,
	body io.ReadCloser,
	maxBytes int64,
	idleTimeout time.Duration,
) ([]byte, string) {
	chunks := make(chan bodyChunk)
	go func() {
		buffer := make([]byte, 32<<10)
		for {
			count, err := body.Read(buffer)
			chunk := bodyChunk{err: err}
			if count > 0 {
				chunk.data = append([]byte(nil), buffer[:count]...)
			}
			select {
			case chunks <- chunk:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	var result bytes.Buffer
	for {
		select {
		case chunk := <-chunks:
			if len(chunk.data) > 0 {
				if int64(result.Len()) > maxBytes-int64(len(chunk.data)) {
					cancel()
					_ = body.Close()
					return nil, reasonResponseLimit
				}
				result.Write(chunk.data)
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTimeout)
			}
			if chunk.err != nil {
				if errors.Is(chunk.err, io.EOF) {
					return result.Bytes(), ""
				}
				if ctx.Err() != nil {
					return nil, reasonRequestTimeout
				}
				return nil, reasonRequest
			}
		case <-timer.C:
			cancel()
			_ = body.Close()
			return nil, reasonIdleTimeout
		case <-ctx.Done():
			_ = body.Close()
			return nil, reasonRequestTimeout
		}
	}
}

func retainNormalized(
	metrics *bytes.Buffer,
	coverage *Coverage,
	normalized normalizedQuery,
	perQueryLimit int64,
	totalRemaining *int64,
) {
	coverage.SeriesFound = normalized.seriesFound
	coverage.SamplesFound = normalized.samplesFound
	perQueryRemaining := perQueryLimit
	for _, record := range normalized.records {
		limitedByTotal := *totalRemaining <= perQueryRemaining
		available := min(perQueryRemaining, *totalRemaining)
		line, samples, truncated := marshalRecordWithin(record, available)
		if len(line) == 0 {
			coverage.Truncated = true
			if *totalRemaining <= perQueryRemaining {
				coverage.Reason = reasonTotalBudget
				coverage.Diagnostic = "total_budget"
			} else {
				coverage.Reason = reasonPerQueryBudget
				coverage.Diagnostic = "query_budget"
			}
			break
		}
		metrics.Write(line)
		metrics.WriteByte('\n')
		lineBytes := int64(len(line) + 1)
		perQueryRemaining -= lineBytes
		*totalRemaining -= lineBytes
		coverage.SeriesRetained++
		coverage.SamplesRetained += samples
		coverage.RetainedBytes += lineBytes
		if truncated {
			coverage.Truncated = true
			if limitedByTotal {
				coverage.Reason = reasonTotalBudget
				coverage.Diagnostic = "total_budget"
			} else {
				coverage.Reason = reasonPerQueryBudget
				coverage.Diagnostic = "record_budget"
			}
			break
		}
	}
	if normalized.seriesLimited {
		coverage.Truncated = true
		coverage.Reason = reasonSeriesLimit
		coverage.Diagnostic = "series_limit"
	}
	if normalized.sampleLimited {
		coverage.Truncated = true
		coverage.Reason = reasonSampleLimit
		coverage.Diagnostic = "sample_limit"
	}
	switch {
	case coverage.Truncated:
		coverage.State = CoveragePartial
	case coverage.SeriesRetained == 0:
		coverage.State = CoverageNoData
	default:
		coverage.State = CoverageCollected
	}
}

func marshalRecordWithin(record Record, limit int64) ([]byte, int, bool) {
	if limit <= 1 || len(record.Samples) == 0 {
		return nil, 0, false
	}
	marshal := func(sampleCount int) []byte {
		candidate := record
		candidate.Samples = record.Samples[:sampleCount]
		data, err := json.Marshal(candidate)
		if err != nil {
			return nil
		}
		return data
	}
	full := marshal(len(record.Samples))
	if int64(len(full)+1) <= limit {
		return full, len(record.Samples), false
	}
	low, high := 1, len(record.Samples)-1
	bestCount := 0
	var best []byte
	for low <= high {
		middle := low + (high-low)/2
		data := marshal(middle)
		if data != nil && int64(len(data)+1) <= limit {
			bestCount = middle
			best = data
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	return best, bestCount, bestCount > 0
}

func setCoverageFailure(
	coverage *Coverage,
	state CoverageState,
	reason string,
	diagnostic string,
	truncated bool,
) {
	coverage.State = state
	coverage.Reason = reason
	coverage.Diagnostic = diagnostic
	coverage.Truncated = truncated
}

func markRemainingCoverage(coverage []Coverage, reason string, diagnostic string) {
	for index := range coverage {
		if coverage[index].State == CoverageSkipped && coverage[index].Reason == "" {
			setCoverageFailure(
				&coverage[index],
				CoverageFailed,
				reason,
				diagnostic,
				false,
			)
		}
	}
}

func finishReport(report *Report) {
	report.RetainedRecords = 0
	report.RetainedBytes = 0
	report.Truncated = false
	successful := 0
	incomplete := 0
	for _, coverage := range report.Coverage {
		report.RetainedRecords += coverage.SeriesRetained
		report.RetainedBytes += coverage.RetainedBytes
		report.Truncated = report.Truncated || coverage.Truncated
		switch coverage.State {
		case CoverageCollected, CoverageNoData:
			successful++
		default:
			incomplete++
		}
	}
	switch {
	case incomplete == 0 && report.Reason == "":
		report.State = ReportComplete
	case successful == 0:
		report.State = ReportFailed
	default:
		report.State = ReportPartial
	}
	if report.Reason == "" && incomplete > 0 {
		report.Reason = "query_coverage_incomplete"
		report.Diagnostic = "query_incomplete"
	}
}

func stageCoverage(sink kubernetes.Sink, report *Report) error {
	report.Artifacts = removeArtifact(report.Artifacts, CoverageArtifactPath)
	report.Artifacts = append(report.Artifacts, Artifact{
		Path:    CoverageArtifactPath,
		Records: len(report.Coverage),
	})
	var encoded []byte
	for iteration := 0; iteration < 8; iteration++ {
		candidate, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return errors.Join(ErrArtifactStaging, err)
		}
		candidate = append(candidate, '\n')
		coverageArtifact := &report.Artifacts[len(report.Artifacts)-1]
		if coverageArtifact.Bytes == int64(len(candidate)) {
			encoded = candidate
			break
		}
		coverageArtifact.Bytes = int64(len(candidate))
		encoded = candidate
	}
	if err := sink.Add(CoverageArtifactPath, encoded); err != nil {
		report.State = ReportPartial
		report.Reason = reasonArtifactStaging
		report.Diagnostic = "coverage_staging"
		return ErrArtifactStaging
	}
	return nil
}

func removeArtifact(artifacts []Artifact, artifactPath string) []Artifact {
	result := artifacts[:0]
	for _, artifact := range artifacts {
		if artifact.Path != artifactPath {
			result = append(result, artifact)
		}
	}
	return result
}

func collectionContextError(parent context.Context, overall context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if err := overall.Err(); err != nil {
		return err
	}
	return nil
}

func discoveryDiagnostic(err error) string {
	switch {
	case errors.Is(err, telemetry.ErrNoMatchingService):
		return "service_absent"
	case errors.Is(err, telemetry.ErrAmbiguousService):
		return "service_ambiguous"
	case errors.Is(err, telemetry.ErrServiceNotReady):
		return "service_not_ready"
	case errors.Is(err, telemetry.ErrResponseTooLarge):
		return "discovery_oversize"
	case errors.Is(err, telemetry.ErrDiscoveryTimeout):
		return "discovery_timeout"
	default:
		return "discovery_error"
	}
}

func forwardDiagnostic(err error) string {
	switch {
	case errors.Is(err, telemetry.ErrForwardTimeout):
		return "readiness_timeout"
	case errors.Is(err, telemetry.ErrForwardOutputLimit):
		return "forward_output_limit"
	default:
		return "forward_error"
	}
}

func httpStatusDiagnostic(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_required"
	case status == http.StatusForbidden:
		return "access_forbidden"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status >= 500 && status <= 599:
		return "service_unavailable"
	default:
		return "unexpected_status"
	}
}
