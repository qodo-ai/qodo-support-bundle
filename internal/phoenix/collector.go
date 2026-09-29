package phoenix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/telemetry"
)

const (
	expectedPhoenixPort = 6006
	discoveryLabelKey   = "app.kubernetes.io/name"
	discoveryLabelValue = "phoenix"
	projectsPath        = "/v1/projects"

	reasonProjectLimit      = "project_limit_exceeded"
	reasonTraceLimit        = "trace_limit_exceeded"
	reasonSpanLimit         = "span_limit_exceeded"
	reasonPageLimit         = "page_limit_exceeded"
	reasonPerTraceBudget    = "per_trace_byte_budget_exceeded"
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

	traceMemoryReserve int64 = 2 << 10
	spanMemoryReserve  int64 = 512
)

type requestResult struct {
	body       []byte
	reason     string
	diagnostic string
}

type forwardResult struct {
	tunnel *telemetry.Tunnel
	err    error
}

type traceGroup struct {
	record  Record
	start   time.Time
	end     time.Time
	spanIDs map[string]struct{}
	bytes   int64
}

// Collect discovers Phoenix, opens a loopback tunnel, queries the locked v1
// REST shape, and stages only normalized redacted artifacts.
func Collect(
	ctx context.Context,
	config Config,
	runner kubernetes.Runner,
	forwarder telemetry.Forwarder,
	sink kubernetes.Sink,
	redactor *redact.Redactor,
) (Report, error) {
	config = config.WithDefaults()
	report := initialReport(config)
	if err := validateCollection(config, ctx, runner, forwarder, sink, redactor); err != nil {
		return report, err
	}

	overallCtx, overallCancel := context.WithTimeout(ctx, config.OverallTimeout)
	defer overallCancel()
	deadlineRunner := commandDeadlineRunner{runner: runner, timeout: config.CommandTimeout}
	target, err := telemetry.Discover(overallCtx, telemetry.DiscoveryConfig{
		Namespace:        config.Namespace,
		Context:          config.Context,
		Kubeconfig:       config.Kubeconfig,
		Timeout:          config.DiscoveryTimeout,
		MaxResponseBytes: config.MaxResponseBytes,
		LabelMatchers: map[string]string{
			discoveryLabelKey: discoveryLabelValue,
		},
		ExpectedPort: expectedPhoenixPort,
	}, deadlineRunner)
	if err != nil {
		if cancellation := collectionContextError(ctx, overallCtx); cancellation != nil {
			failReport(&report, reasonCanceled, "context_ended")
			if stageErr := stageCoverage(sink, &report); stageErr != nil {
				return report, stageErr
			}
			return report, cancellation
		}
		failReport(&report, reasonDiscovery, discoveryDiagnostic(err))
		return report, stageCoverage(sink, &report)
	}

	tunnel, tunnelCancel, err := openTunnel(
		overallCtx,
		config.ReadinessTimeout,
		forwarder,
		target,
	)
	if err != nil {
		if cancellation := collectionContextError(ctx, overallCtx); cancellation != nil {
			failReport(&report, reasonCanceled, "context_ended")
			if stageErr := stageCoverage(sink, &report); stageErr != nil {
				return report, stageErr
			}
			return report, cancellation
		}
		failReport(&report, reasonForward, forwardDiagnostic(err))
		return report, stageCoverage(sink, &report)
	}
	defer tunnelCancel()

	baseURL, endpointErr := validateTunnelEndpoint(tunnel)
	if endpointErr != nil {
		closeErr := tunnel.Close()
		failReport(&report, reasonTunnelEndpoint, "endpoint_rejected")
		if closeErr != nil {
			failReport(&report, reasonCleanup, "tunnel_cleanup")
		}
		return report, stageCoverage(sink, &report)
	}

	client := newHTTPClient(config)
	groups, collectReason, collectDiagnostic := collectGroups(
		overallCtx,
		client,
		baseURL,
		config,
		redactor,
		&report.Coverage,
	)
	cancellation := collectionContextError(ctx, overallCtx)
	if cancellation != nil {
		collectReason = reasonCanceled
		collectDiagnostic = "context_ended"
	}
	if tunnelErr := tunnel.Err(); tunnelErr != nil {
		collectReason = reasonTunnelUnavailable
		collectDiagnostic = "tunnel_unavailable"
	}
	if closeErr := tunnel.Close(); closeErr != nil {
		collectReason = reasonCleanup
		collectDiagnostic = "tunnel_cleanup"
	}
	tunnelCancel()

	var traces bytes.Buffer
	retainGroups(&traces, groups, config, &report.Coverage)
	if collectReason != "" {
		report.Coverage.Reason = collectReason
		report.Coverage.Diagnostic = collectDiagnostic
		if collectReason == reasonCanceled {
			report.Coverage.State = CoverageFailed
		} else if report.Coverage.TracesRetained > 0 {
			report.Coverage.State = CoveragePartial
		} else {
			report.Coverage.State = CoverageFailed
		}
	}
	finishReport(&report)

	var tracesStagingErr error
	if traces.Len() > 0 {
		if err := sink.Add(TracesArtifactPath, append([]byte(nil), traces.Bytes()...)); err != nil {
			tracesStagingErr = ErrArtifactStaging
			report.Coverage.State = CoveragePartial
			report.Coverage.Reason = reasonArtifactStaging
			report.Coverage.Diagnostic = "traces_staging"
			report.Reason = reasonArtifactStaging
			report.Diagnostic = "traces_staging"
		} else {
			report.Artifacts = append(report.Artifacts, Artifact{
				Path:    TracesArtifactPath,
				Records: report.Coverage.TracesRetained,
				Bytes:   int64(traces.Len()),
			})
		}
	}
	finishReport(&report)
	if stageErr := stageCoverage(sink, &report); stageErr != nil {
		return report, stageErr
	}
	if tracesStagingErr != nil {
		return report, tracesStagingErr
	}
	if cancellation != nil {
		return report, cancellation
	}
	return report, nil
}

func collectGroups(
	ctx context.Context,
	client *http.Client,
	baseURL *url.URL,
	config Config,
	redactor *redact.Redactor,
	coverage *Coverage,
) ([]*traceGroup, string, string) {
	projects, reason, diagnostic := collectProjects(
		ctx,
		client,
		baseURL,
		config,
		coverage,
	)
	if reason != "" {
		return nil, reason, diagnostic
	}
	groups := make(map[string]*traceGroup)
	var retainedEstimate int64
	for _, project := range projects {
		coverage.ProjectsRead++
		cursor := ""
		seenCursors := make(map[string]struct{})
		for {
			if coverage.PagesRead >= config.MaxPages {
				markTruncated(coverage, reasonPageLimit, "page_limit")
				return sortedGroups(groups), "", ""
			}
			result := executeRequest(
				ctx,
				client,
				baseURL,
				spansPath(project.ID),
				spanParameters(config, cursor),
				config,
			)
			if result.reason != "" {
				return sortedGroups(groups), result.reason, result.diagnostic
			}
			coverage.PagesRead++
			spans, nextCursor, found, err := decodeSpans(result.body, config, redactor)
			result.body = nil
			if err != nil {
				return sortedGroups(groups), reasonMalformed, "spans_rejected"
			}
			remainingSpans := config.MaxSpans - coverage.SpansFound
			coverage.SpansFound += found
			if remainingSpans <= 0 {
				markTruncated(coverage, reasonSpanLimit, "span_limit")
				return sortedGroups(groups), "", ""
			}
			if found > remainingSpans {
				markTruncated(coverage, reasonSpanLimit, "span_limit")
				if len(spans) > remainingSpans {
					spans = spans[:remainingSpans]
				}
			}
			for _, span := range spans {
				spanBytes, err := json.Marshal(span.span)
				if err != nil {
					return sortedGroups(groups), reasonMalformed, "span_encoding"
				}
				spanFootprint := int64(len(spanBytes)) + spanMemoryReserve
				key := project.ID + "\x00" + span.traceID
				group := groups[key]
				if group == nil {
					coverage.TracesFound++
					if len(groups) >= config.MaxTraces {
						markTruncated(coverage, reasonTraceLimit, "trace_limit")
						return sortedGroups(groups), "", ""
					}
					record := Record{
						SchemaVersion:   recordSchemaVersion,
						ContractVersion: ContractVersion,
						Project: Project{
							ID: redactor.Text(project.ID),
						},
						TraceID:     span.traceID,
						Start:       span.start.Format(time.RFC3339Nano),
						End:         span.end.Format(time.RFC3339Nano),
						Correlation: correlation(config),
						Spans:       []Span{},
					}
					base, err := json.Marshal(record)
					if err != nil {
						return sortedGroups(groups), reasonMalformed, "trace_encoding"
					}
					traceFootprint := int64(len(base)) + traceMemoryReserve
					if traceFootprint > config.MaxRetainedBytesPerTrace ||
						spanFootprint > config.MaxRetainedBytesPerTrace-traceFootprint {
						markTruncated(coverage, reasonPerTraceBudget, "trace_budget")
						return sortedGroups(groups), "", ""
					}
					newFootprint := traceFootprint + spanFootprint
					if retainedEstimate > config.MaxTotalRetainedBytes-newFootprint {
						markTruncated(coverage, reasonTotalBudget, "total_budget")
						return sortedGroups(groups), "", ""
					}
					group = &traceGroup{
						record:  record,
						start:   span.start,
						end:     span.end,
						spanIDs: make(map[string]struct{}),
						bytes:   traceFootprint,
					}
					groups[key] = group
					retainedEstimate += traceFootprint
				} else if spanFootprint > config.MaxRetainedBytesPerTrace-group.bytes {
					markTruncated(coverage, reasonPerTraceBudget, "trace_budget")
					return sortedGroups(groups), "", ""
				}
				if retainedEstimate > config.MaxTotalRetainedBytes-spanFootprint {
					markTruncated(coverage, reasonTotalBudget, "total_budget")
					return sortedGroups(groups), "", ""
				}
				if _, duplicate := group.spanIDs[span.span.SpanID]; duplicate {
					return sortedGroups(groups), reasonMalformed, "duplicate_span"
				}
				group.spanIDs[span.span.SpanID] = struct{}{}
				group.record.Spans = append(group.record.Spans, span.span)
				group.bytes += spanFootprint
				retainedEstimate += spanFootprint
				if span.start.Before(group.start) {
					group.start = span.start
				}
				if span.end.After(group.end) {
					group.end = span.end
				}
			}
			if coverage.Truncated {
				return sortedGroups(groups), "", ""
			}
			if nextCursor == "" {
				break
			}
			if _, loop := seenCursors[nextCursor]; loop {
				return sortedGroups(groups), reasonMalformed, "cursor_loop"
			}
			seenCursors[nextCursor] = struct{}{}
			cursor = nextCursor
		}
	}
	return sortedGroups(groups), "", ""
}

func collectProjects(
	ctx context.Context,
	client *http.Client,
	baseURL *url.URL,
	config Config,
	coverage *Coverage,
) ([]Project, string, string) {
	var projects []Project
	seenProjects := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	cursor := ""
	for {
		if coverage.PagesRead >= config.MaxPages {
			markTruncated(coverage, reasonPageLimit, "page_limit")
			return projects, "", ""
		}
		parameters := make(url.Values, 4)
		parameters.Set("limit", strconv.Itoa(config.PageSize))
		parameters.Set("include_experiment_projects", "false")
		parameters.Set("include_dataset_evaluator_projects", "false")
		if cursor != "" {
			parameters.Set("cursor", cursor)
		}
		result := executeRequest(ctx, client, baseURL, projectsPath, parameters, config)
		if result.reason != "" {
			return nil, result.reason, result.diagnostic
		}
		coverage.PagesRead++
		page, nextCursor, err := decodeProjects(result.body)
		result.body = nil
		if err != nil {
			return nil, reasonMalformed, "projects_rejected"
		}
		coverage.ProjectsFound += len(page)
		for _, project := range page {
			if _, duplicate := seenProjects[project.ID]; duplicate {
				return nil, reasonMalformed, "duplicate_project"
			}
			seenProjects[project.ID] = struct{}{}
			if len(projects) >= config.MaxProjects {
				markTruncated(coverage, reasonProjectLimit, "project_limit")
				return projects, "", ""
			}
			projects = append(projects, project)
		}
		if nextCursor == "" {
			break
		}
		if _, loop := seenCursors[nextCursor]; loop {
			return nil, reasonMalformed, "cursor_loop"
		}
		seenCursors[nextCursor] = struct{}{}
		cursor = nextCursor
	}
	sort.Slice(projects, func(left, right int) bool {
		return projects[left].ID < projects[right].ID
	})
	return projects, "", ""
}

func spanParameters(config Config, cursor string) url.Values {
	parameters := make(url.Values, 4)
	parameters.Set("limit", strconv.Itoa(config.PageSize))
	if cursor != "" {
		parameters.Set("cursor", cursor)
	}
	if config.TraceID != "" {
		parameters.Set("trace_id", config.TraceID)
	} else {
		parameters.Set("start_time", config.Start.Format(time.RFC3339Nano))
		parameters.Set("end_time", config.End.Format(time.RFC3339Nano))
	}
	return parameters
}

func spansPath(projectID string) string {
	return "/v1/projects/" + url.PathEscape(projectID) + "/spans"
}

func correlation(config Config) string {
	if config.TraceID != "" {
		return "direct"
	}
	return "surrounding"
}

func sortedGroups(groups map[string]*traceGroup) []*traceGroup {
	result := make([]*traceGroup, 0, len(groups))
	for _, group := range groups {
		group.record.Start = group.start.Format(time.RFC3339Nano)
		group.record.End = group.end.Format(time.RFC3339Nano)
		sortRecord(&group.record)
		result = append(result, group)
	}
	sort.Slice(result, func(left, right int) bool {
		leftRecord := result[left].record
		rightRecord := result[right].record
		if leftRecord.Project.ID != rightRecord.Project.ID {
			return leftRecord.Project.ID < rightRecord.Project.ID
		}
		return leftRecord.TraceID < rightRecord.TraceID
	})
	return result
}

func retainGroups(
	output *bytes.Buffer,
	groups []*traceGroup,
	config Config,
	coverage *Coverage,
) {
	totalRemaining := config.MaxTotalRetainedBytes
	for _, group := range groups {
		limitedByTotal := totalRemaining <= config.MaxRetainedBytesPerTrace
		available := min(config.MaxRetainedBytesPerTrace, totalRemaining)
		line, spanCount, truncated := marshalRecordWithin(group.record, available)
		if len(line) == 0 {
			if totalRemaining <= config.MaxRetainedBytesPerTrace {
				markTruncated(coverage, reasonTotalBudget, "total_budget")
			} else {
				markTruncated(coverage, reasonPerTraceBudget, "trace_budget")
			}
			break
		}
		output.Write(line)
		output.WriteByte('\n')
		lineBytes := int64(len(line) + 1)
		totalRemaining -= lineBytes
		coverage.TracesRetained++
		coverage.SpansRetained += spanCount
		coverage.RetainedBytes += lineBytes
		if truncated {
			if limitedByTotal {
				markTruncated(coverage, reasonTotalBudget, "total_budget")
			} else {
				markTruncated(coverage, reasonPerTraceBudget, "trace_budget")
			}
			break
		}
	}
	switch {
	case coverage.Truncated:
		coverage.State = CoveragePartial
	case coverage.TracesRetained == 0:
		coverage.State = CoverageNoData
	default:
		coverage.State = CoverageCollected
	}
}

func marshalRecordWithin(record Record, limit int64) ([]byte, int, bool) {
	if limit <= 1 || len(record.Spans) == 0 {
		return nil, 0, false
	}
	marshal := func(count int) []byte {
		candidate := record
		candidate.Spans = record.Spans[:count]
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return nil
		}
		return encoded
	}
	full := marshal(len(record.Spans))
	if int64(len(full)+1) <= limit {
		return full, len(record.Spans), false
	}
	low, high := 1, len(record.Spans)-1
	bestCount := 0
	var best []byte
	for low <= high {
		middle := low + (high-low)/2
		encoded := marshal(middle)
		if encoded != nil && int64(len(encoded)+1) <= limit {
			best = encoded
			bestCount = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	return best, bestCount, bestCount > 0
}

func executeRequest(
	parent context.Context,
	client *http.Client,
	baseURL *url.URL,
	path string,
	parameters url.Values,
	config Config,
) requestResult {
	requestCtx, cancel := context.WithTimeout(parent, config.RequestTimeout)
	defer cancel()
	endpoint := *baseURL
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return requestResult{reason: reasonRequest, diagnostic: "request_construction"}
	}
	endpoint.Path = decodedPath
	if decodedPath != path {
		endpoint.RawPath = path
	}
	endpoint.RawQuery = parameters.Encode()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return requestResult{reason: reasonRequest, diagnostic: "request_construction"}
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return requestResult{reason: reasonRequestTimeout, diagnostic: "request_timeout"}
		}
		return requestResult{reason: reasonRequest, diagnostic: "request_transport"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return requestResult{
			reason:     reasonHTTPStatus,
			diagnostic: httpStatusDiagnostic(response.StatusCode),
		}
	}
	if response.ContentLength > config.MaxResponseBytes {
		return requestResult{reason: reasonResponseLimit, diagnostic: "response_oversize"}
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
		return requestResult{reason: readReason, diagnostic: diagnostic}
	}
	return requestResult{body: body}
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

func newHTTPClient(config Config) *http.Client {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			DisableKeepAlives:      true,
			ForceAttemptHTTP2:      false,
			ResponseHeaderTimeout:  min(config.RequestTimeout, config.IdleTimeout),
			MaxResponseHeaderBytes: 64 << 10,
			MaxConnsPerHost:        1,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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

func initialReport(config Config) Report {
	mode := "window"
	if config.TraceID != "" {
		mode = "trace_id"
	}
	return Report{
		ContractVersion: ContractVersion,
		Mode:            mode,
		RequestedStart:  config.Start.Format(time.RFC3339Nano),
		RequestedEnd:    config.End.Format(time.RFC3339Nano),
		ActualStart:     config.Start.Format(time.RFC3339Nano),
		ActualEnd:       config.End.Format(time.RFC3339Nano),
		TraceID:         config.TraceID,
		State:           ReportFailed,
		Coverage:        Coverage{State: CoverageFailed},
	}
}

func failReport(report *Report, reason, diagnostic string) {
	report.State = ReportFailed
	report.Reason = reason
	report.Diagnostic = diagnostic
	report.Coverage.State = CoverageFailed
	report.Coverage.Reason = reason
	report.Coverage.Diagnostic = diagnostic
}

func markTruncated(coverage *Coverage, reason, diagnostic string) {
	coverage.Truncated = true
	coverage.State = CoveragePartial
	coverage.Reason = reason
	coverage.Diagnostic = diagnostic
}

func finishReport(report *Report) {
	switch report.Coverage.State {
	case CoverageCollected, CoverageNoData:
		if report.Reason == "" {
			report.State = ReportComplete
		}
	case CoveragePartial:
		report.State = ReportPartial
		if report.Reason == "" {
			report.Reason = report.Coverage.Reason
			report.Diagnostic = report.Coverage.Diagnostic
		}
	default:
		report.State = ReportFailed
		if report.Reason == "" {
			report.Reason = report.Coverage.Reason
			report.Diagnostic = report.Coverage.Diagnostic
		}
	}
}

func stageCoverage(sink kubernetes.Sink, report *Report) error {
	report.Artifacts = removeArtifact(report.Artifacts, CoverageArtifactPath)
	report.Artifacts = append(report.Artifacts, Artifact{
		Path:    CoverageArtifactPath,
		Records: 1,
	})
	var encoded []byte
	for iteration := 0; iteration < 8; iteration++ {
		candidate, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return errors.Join(ErrArtifactStaging, err)
		}
		candidate = append(candidate, '\n')
		artifact := &report.Artifacts[len(report.Artifacts)-1]
		encoded = candidate
		if artifact.Bytes == int64(len(candidate)) {
			break
		}
		artifact.Bytes = int64(len(candidate))
	}
	if err := sink.Add(CoverageArtifactPath, encoded); err != nil {
		report.State = ReportPartial
		report.Reason = reasonArtifactStaging
		report.Diagnostic = "coverage_staging"
		return ErrArtifactStaging
	}
	return nil
}

func removeArtifact(artifacts []Artifact, path string) []Artifact {
	result := artifacts[:0]
	for _, artifact := range artifacts {
		if artifact.Path != path {
			result = append(result, artifact)
		}
	}
	return result
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
	results := make(chan forwardResult)
	go func() {
		tunnel, err := forwarder.Forward(tunnelCtx, target)
		select {
		case results <- forwardResult{tunnel: tunnel, err: err}:
		case <-tunnelCtx.Done():
			if tunnel != nil {
				_ = tunnel.Close()
			}
		}
	}()
	timer := time.NewTimer(readinessTimeout)
	defer timer.Stop()
	select {
	case result := <-results:
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

func collectionContextError(parent, overall context.Context) error {
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

func requestHasOnly(values url.Values, keys ...string) bool {
	if len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := values[key]; !exists {
			return false
		}
	}
	return true
}

func safeReason(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	return !strings.ContainsAny(value, "\r\n /?&=")
}
