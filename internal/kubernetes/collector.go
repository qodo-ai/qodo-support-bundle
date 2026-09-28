package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

const (
	defaultLogWorkers          = 8
	MaximumMetadataBytes int64 = 1 << 30
	MaximumLogBytes      int64 = 100 << 20
	MaximumTotalLogBytes int64 = 8 << 30
	MaximumLogWorkers          = 64
)

var (
	safePathCharacter   = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	privateKeyBeginLine = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	privateKeyEndLine   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
)

// Collect gathers safe pod metadata, events, and current and previous container logs.
func Collect(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if config.Timeout <= 0 {
		return Report{}, errors.New("command timeout must be positive")
	}
	if config.Since <= 0 {
		return Report{}, errors.New("log lookback must be positive")
	}
	if config.MaxMetadataBytes <= 0 {
		return Report{}, errors.New("max metadata bytes must be positive")
	}
	if config.MaxMetadataBytes > MaximumMetadataBytes {
		return Report{}, fmt.Errorf(
			"max metadata bytes must not exceed %d",
			MaximumMetadataBytes,
		)
	}
	if config.MaxLogBytes <= 0 {
		return Report{}, errors.New("max log bytes must be positive")
	}
	if config.MaxLogBytes > MaximumLogBytes {
		return Report{}, fmt.Errorf("max log bytes must not exceed %d", MaximumLogBytes)
	}
	if config.MaxTotalLogBytes <= 0 {
		return Report{}, errors.New("max total log bytes must be positive")
	}
	if config.MaxTotalLogBytes > MaximumTotalLogBytes {
		return Report{}, fmt.Errorf(
			"max total log bytes must not exceed %d",
			MaximumTotalLogBytes,
		)
	}
	if config.MaxLogBytes > config.MaxTotalLogBytes {
		return Report{}, errors.New("max log bytes must not exceed max total log bytes")
	}
	if config.LogWorkers > MaximumLogWorkers {
		return Report{}, fmt.Errorf("log workers must not exceed %d", MaximumLogWorkers)
	}
	if config.ExcludeSystemNamespaces && !config.AllNamespaces {
		return Report{}, errors.New(
			"system namespaces can only be excluded during all-namespaces collection",
		)
	}
	if config.AllNamespaces &&
		(config.Namespace != "" || len(config.Namespaces) > 0) {
		return Report{}, errors.New(
			"all-namespaces collection cannot include explicit namespaces",
		)
	}
	baseArguments := globalArguments(config)
	var namespaces []string
	var excludedNamespaces []string
	var err error
	if config.AllNamespaces {
		reportProgress(config, Progress{Stage: "discover_namespaces"})
		namespaces, excludedNamespaces, err = discoverNamespaces(
			ctx,
			config,
			baseArguments,
			runner,
			redactor,
		)
	} else {
		namespaces, err = collectionNamespaces(config)
	}
	if err != nil {
		return Report{}, err
	}
	reportProgress(config, Progress{
		Stage:   "namespaces_discovered",
		Current: len(namespaces),
		Total:   len(namespaces),
	})

	report := Report{
		AllNamespaces:       config.AllNamespaces,
		ExcludedNamespaces:  excludedNamespaces,
		Namespaces:          make([]string, 0, len(namespaces)),
		NamespacesRequested: len(namespaces),
		MetadataLimitBytes:  config.MaxMetadataBytes,
	}
	metadata := metadataBudget{remaining: config.MaxMetadataBytes}
	logRequests := make([]logRequest, 0)
	for namespaceIndex, namespace := range namespaces {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if metadata.remaining == 0 {
			skipped := len(namespaces) - namespaceIndex
			report.MetadataNamespacesSkipped += skipped
			report.Issues = append(report.Issues, Issue{
				Operation: "collect Kubernetes metadata",
				Message: fmt.Sprintf(
					"aggregate metadata limit reached; skipped %d namespaces",
					skipped,
				),
			})
			break
		}
		reportProgress(config, Progress{
			Stage:     "scan_namespace",
			Current:   namespaceIndex + 1,
			Total:     len(namespaces),
			Namespace: namespace,
		})
		podArguments := append(
			append([]string{}, baseArguments...),
			"get", "pods", "--namespace", namespace, "--output", "json",
		)
		if config.Selector != "" {
			podArguments = append(podArguments, "--selector", config.Selector)
		}
		podResult, runErr := runWithTimeout(
			ctx,
			config.Timeout,
			runner,
			metadataCommandLimit(metadata.remaining),
			podArguments...,
		)
		if runErr != nil {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			namespaceErr := commandError(
				"list pods",
				namespace,
				podResult,
				runErr,
				redactor,
			)
			if len(namespaces) == 1 {
				return report, namespaceErr
			}
			report.Issues = append(report.Issues, Issue{
				Operation: "list pods",
				Resource:  redactor.Text(namespace),
				Message:   redactor.Text(namespaceErr.Error()),
			})
			continue
		}
		if podResult.Truncated {
			report.Issues = append(report.Issues, Issue{
				Operation: "list pods",
				Resource:  redactor.Text(namespace),
				Message:   "pod metadata exceeded the collection limit",
			})
			continue
		}

		var pods podList
		if err := json.Unmarshal(podResult.Stdout, &pods); err != nil {
			report.Issues = append(report.Issues, Issue{
				Operation: "decode pod metadata",
				Resource:  redactor.Text(namespace),
				Message:   redactor.Text(err.Error()),
			})
			continue
		}
		for index := range pods.Items {
			if pods.Items[index].Metadata.Namespace == "" {
				pods.Items[index].Metadata.Namespace = namespace
			}
		}
		sort.Slice(pods.Items, func(left int, right int) bool {
			return pods.Items[left].Metadata.Name < pods.Items[right].Metadata.Name
		})
		report.Namespaces = append(report.Namespaces, redactor.Text(namespace))
		report.Pods += len(pods.Items)

		podRecords, err := marshalPodRecords(pods.Items, redactor)
		if err != nil {
			return report, err
		}
		if err := metadata.add(
			sink,
			podMetadataPath(namespace, len(namespaces)),
			podRecords,
			"pod metadata",
			redactor.Text(namespace),
			&report,
		); err != nil {
			return report, fmt.Errorf("add pod metadata: %w", err)
		}
		containerEvents, restarts, oomKills, err := marshalContainerEventRecords(
			pods.Items,
			redactor,
		)
		if err != nil {
			return report, err
		}
		report.ContainerRestarts += restarts
		report.OOMKills += oomKills
		if len(containerEvents) > 0 && metadata.remaining > 0 {
			if err := metadata.add(
				sink,
				containerEventPath(namespace, len(namespaces)),
				containerEvents,
				"container-event metadata",
				redactor.Text(namespace),
				&report,
			); err != nil {
				return report, fmt.Errorf("add container events: %w", err)
			}
		}

		if metadata.remaining > 0 {
			if err := collectEvents(
				ctx,
				config,
				namespace,
				len(namespaces),
				runner,
				sink,
				redactor,
				&metadata,
				&report,
			); err != nil {
				return report, err
			}
		}
		for _, currentPod := range pods.Items {
			containers := append(
				append([]containerSpec{}, currentPod.Spec.Containers...),
				currentPod.Spec.InitContainers...,
			)
			ephemeralContainers := currentPod.Spec.EphemeralContainers
			report.Containers += len(containers)
			report.InitContainers += len(currentPod.Spec.InitContainers)
			report.Containers += len(ephemeralContainers)
			report.EphemeralContainers += len(ephemeralContainers)
			for _, container := range containers {
				logRequests = append(logRequests, logRequest{
					namespace:      namespace,
					namespaceCount: len(namespaces),
					podName:        currentPod.Metadata.Name,
					containerName:  container.Name,
				})
				if containerRestartCount(currentPod, container.Name) > 0 {
					logRequests = append(logRequests, logRequest{
						namespace:      namespace,
						namespaceCount: len(namespaces),
						podName:        currentPod.Metadata.Name,
						containerName:  container.Name,
						previous:       true,
					})
				}
			}
			for _, container := range ephemeralContainers {
				logRequests = append(logRequests, logRequest{
					namespace:      namespace,
					namespaceCount: len(namespaces),
					podName:        currentPod.Metadata.Name,
					containerName:  container.Name,
				})
			}
		}
	}
	if len(report.Namespaces) == 0 {
		return report, errors.New("could not collect pods from any requested namespace")
	}
	workers := config.LogWorkers
	if workers <= 0 {
		workers = defaultLogWorkers
	}
	reportProgress(config, Progress{
		Stage:   "collect_logs",
		Total:   len(logRequests),
		Workers: min(workers, len(logRequests)),
	})
	if err := collectLogs(
		ctx,
		config,
		runner,
		sink,
		redactor,
		logRequests,
		&report,
	); err != nil {
		return report, err
	}
	return report, nil
}

type metadataBudget struct {
	remaining int64
}

func (budget *metadataBudget) add(
	sink Sink,
	path string,
	data []byte,
	kind string,
	namespace string,
	report *Report,
) error {
	if int64(len(data)) <= budget.remaining {
		if err := sink.Add(path, data); err != nil {
			return err
		}
		budget.remaining -= int64(len(data))
		report.MetadataBytes += int64(len(data))
		return nil
	}

	retained := completeJSONLLines(data, budget.remaining)
	if len(retained) > 0 {
		if err := sink.Add(path, retained); err != nil {
			return err
		}
		report.MetadataBytes += int64(len(retained))
	}
	budget.remaining = 0
	report.TruncatedMetadataFiles++
	report.Issues = append(report.Issues, Issue{
		Operation: "collect Kubernetes metadata",
		Resource:  namespace,
		Message: fmt.Sprintf(
			"aggregate metadata limit reached while staging %s; output was truncated",
			kind,
		),
	})
	return nil
}

func completeJSONLLines(data []byte, limit int64) []byte {
	if limit <= 0 || len(data) == 0 {
		return nil
	}
	end := min(int64(len(data)), limit)
	lastNewline := bytes.LastIndexByte(data[:int(end)], '\n')
	if lastNewline < 0 {
		return nil
	}
	return data[:lastNewline+1]
}

func collectEvents(
	ctx context.Context,
	config Config,
	namespace string,
	namespaceCount int,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
	metadata *metadataBudget,
	report *Report,
) error {
	arguments := append(
		globalArguments(config),
		"get", "events", "--namespace", namespace, "--output", "json",
	)
	result, err := runWithTimeout(
		ctx,
		config.Timeout,
		runner,
		metadataCommandLimit(metadata.remaining),
		arguments...,
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		report.Issues = append(
			report.Issues,
			issueFromCommand("list events", namespace, result, err, redactor),
		)
		return nil
	}
	if result.Truncated {
		report.Issues = append(report.Issues, Issue{
			Operation: "list events",
			Resource:  redactor.Text(namespace),
			Message:   "event metadata exceeded the collection limit",
		})
		return nil
	}

	var events eventList
	if err := json.Unmarshal(result.Stdout, &events); err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "decode events",
			Resource:  redactor.Text(namespace),
			Message:   redactor.Text(err.Error()),
		})
		return nil
	}
	records, err := marshalEventRecords(events.Items, redactor)
	if err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "encode events",
			Message:   redactor.Text(err.Error()),
		})
		return nil
	}
	if err := metadata.add(
		sink,
		eventMetadataPath(namespace, namespaceCount),
		records,
		"event metadata",
		redactor.Text(namespace),
		report,
	); err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "add events",
			Resource:  redactor.Text(namespace),
			Message:   redactor.Text(err.Error()),
		})
	}
	return nil
}

func collectLogs(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
	requests []logRequest,
	report *Report,
) error {
	workers := config.LogWorkers
	if workers <= 0 {
		workers = defaultLogWorkers
	}
	workers = min(workers, len(requests))
	if workers == 0 {
		return ctx.Err()
	}
	results := make(chan collectedLog, workers)
	remaining := config.MaxTotalLogBytes
	next := 0
	active := 0
	completed := 0
	progressInterval := max(len(requests)/20, 1)
	for active > 0 || next < len(requests) {
		for active < workers && next < len(requests) && remaining > 0 {
			if ctx.Err() != nil {
				break
			}
			if remaining < config.MaxLogBytes && active > 0 {
				break
			}
			request := requests[next]
			request.maxBytes = min(config.MaxLogBytes, remaining)
			remaining -= request.maxBytes
			next++
			active++
			go func() {
				results <- readLog(ctx, config, runner, redactor, request)
			}()
		}
		if active == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			skipped := len(requests) - next
			report.Issues = append(report.Issues, Issue{
				Operation: "collect container logs",
				Message: fmt.Sprintf(
					"total log collection limit reached; skipped %d log streams",
					skipped,
				),
			})
			completed += skipped
			reportProgress(config, Progress{
				Stage:   "logs_progress",
				Current: completed,
				Total:   len(requests),
				Workers: workers,
			})
			break
		}

		result := <-results
		active--
		completed++
		if ctx.Err() != nil {
			continue
		}
		retained := int64(0)
		if result.issue != nil {
			report.Issues = append(report.Issues, *result.issue)
		} else {
			report.LogStreamsCollected++
			if result.retainedTruncated {
				report.TruncatedLogFiles++
				message := "container log exceeded the per-stream byte limit"
				if result.reserved < config.MaxLogBytes {
					message = "total log collection limit truncated this stream"
				}
				report.Issues = append(report.Issues, Issue{
					Operation: "collect container log",
					Resource:  redactor.Text(result.path),
					Message:   message,
				})
			}
			if len(result.data) > 0 {
				if err := sink.Add(result.path, result.data); err != nil {
					report.Issues = append(report.Issues, Issue{
						Operation: "add container log",
						Resource:  result.path,
						Message:   redactor.Text(err.Error()),
					})
				} else {
					retained = int64(len(result.data))
					report.LogFiles++
				}
			}
		}
		remaining += result.reserved - retained
		if completed == len(requests) || completed%progressInterval == 0 {
			reportProgress(config, Progress{
				Stage:   "logs_progress",
				Current: completed,
				Total:   len(requests),
				Workers: workers,
			})
		}
	}
	return ctx.Err()
}

func readLog(
	ctx context.Context,
	config Config,
	runner Runner,
	redactor *redact.Redactor,
	request logRequest,
) collectedLog {
	arguments := append(
		globalArguments(config),
		"logs",
		"--namespace", request.namespace,
		request.podName,
		"--container", request.containerName,
		"--timestamps=true",
	)
	arguments = append(arguments, "--since", durationArgument(config.Since))
	suffix := ""
	operation := "collect current log"
	if request.previous {
		arguments = append(arguments, "--previous=true")
		suffix = "-previous"
		operation = "collect previous log"
	}
	result, err := runWithTimeout(
		ctx,
		config.Timeout,
		runner,
		request.maxBytes,
		arguments...,
	)
	resource := request.namespace + "/" + request.podName + "/" + request.containerName
	if err != nil {
		issue := issueFromCommand(operation, resource, result, err, redactor)
		return collectedLog{issue: &issue, reserved: request.maxBytes}
	}

	pathParts := []string{"kubernetes", "logs"}
	if request.namespaceCount > 1 {
		pathParts = append(pathParts, safePathSegment(request.namespace))
	}
	pathParts = append(
		pathParts,
		safePathSegment(request.podName),
		safePathSegment(request.containerName)+suffix+".log",
	)
	path := filepath.ToSlash(filepath.Join(pathParts...))
	data, sanitizationTruncated := sanitizeLog(result.Stdout, redactor, request.maxBytes)
	retainedTruncated := result.Truncated || sanitizationTruncated
	return collectedLog{
		path:              path,
		data:              data,
		retainedTruncated: retainedTruncated,
		reserved:          request.maxBytes,
	}
}

func marshalPodRecords(pods []pod, redactor *redact.Redactor) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, currentPod := range pods {
		record := outputPod{
			SchemaVersion: "1",
			Timestamp:     redactor.Text(currentPod.Status.StartTime),
			Kind:          "Pod",
			Namespace:     redactor.Text(currentPod.Metadata.Namespace),
			Name:          redactor.Text(currentPod.Metadata.Name),
			NodeName:      redactor.Text(currentPod.Spec.NodeName),
			Labels:        sanitizeStringMap(currentPod.Metadata.Labels, redactor),
			Phase:         redactor.Text(currentPod.Status.Phase),
			Conditions:    sanitizeConditions(currentPod.Status.Conditions, redactor),
			Containers: marshalContainerStatuses(
				currentPod.Spec.Containers,
				currentPod.Status.ContainerStatuses,
				redactor,
			),
			InitContainers: marshalContainerStatuses(
				currentPod.Spec.InitContainers,
				currentPod.Status.InitContainerStatuses,
				redactor,
			),
			EphemeralContainers: marshalContainerStatuses(
				currentPod.Spec.EphemeralContainers,
				currentPod.Status.EphemeralContainerStatuses,
				redactor,
			),
			Source: map[string]string{"type": "kubernetes"},
		}
		if err := encoder.Encode(record); err != nil {
			return nil, fmt.Errorf("encode pod record: %w", err)
		}
	}
	return output.Bytes(), nil
}

func marshalContainerStatuses(
	specs []containerSpec,
	statuses []containerStatus,
	redactor *redact.Redactor,
) []outputContainerStatus {
	statusByName := make(map[string]containerStatus, len(statuses))
	for _, status := range statuses {
		statusByName[status.Name] = status
	}
	containers := make([]outputContainerStatus, 0, len(specs))
	for _, spec := range specs {
		status := statusByName[spec.Name]
		image := status.Image
		if image == "" {
			image = spec.Image
		}
		containers = append(containers, outputContainerStatus{
			Name:         redactor.Text(spec.Name),
			Ready:        status.Ready,
			RestartCount: status.RestartCount,
			Image:        redactor.Text(image),
			ImageID:      redactor.Text(status.ImageID),
			State:        sanitizeContainerStates(status.State, redactor),
			LastState:    sanitizeContainerStates(status.LastState, redactor),
		})
	}
	return containers
}

func marshalEventRecords(events []event, redactor *redact.Redactor) ([]byte, error) {
	sort.Slice(events, func(left int, right int) bool {
		return eventTimestamp(events[left]) < eventTimestamp(events[right])
	})
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, currentEvent := range events {
		record := outputEvent{
			SchemaVersion:      "1",
			Timestamp:          redactor.Text(eventTimestamp(currentEvent)),
			Kind:               redactor.Text(currentEvent.Involved.Kind),
			Namespace:          redactor.Text(currentEvent.Involved.Namespace),
			Name:               redactor.Text(currentEvent.Involved.Name),
			Type:               redactor.Text(currentEvent.Type),
			Reason:             redactor.Text(currentEvent.Reason),
			Message:            redactor.Text(currentEvent.Message),
			Count:              currentEvent.Count,
			FirstTimestamp:     redactor.Text(currentEvent.FirstTimestamp),
			LastTimestamp:      redactor.Text(currentEvent.LastTimestamp),
			ReportingComponent: redactor.Text(reportingComponent(currentEvent)),
			Source:             map[string]string{"type": "kubernetes_event"},
		}
		if err := encoder.Encode(record); err != nil {
			return nil, fmt.Errorf("encode event record: %w", err)
		}
	}
	return output.Bytes(), nil
}

func marshalContainerEventRecords(
	pods []pod,
	redactor *redact.Redactor,
) ([]byte, int, int, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	restarts := 0
	oomKills := 0
	for _, currentPod := range pods {
		statuses := append(
			append([]containerStatus{}, currentPod.Status.ContainerStatuses...),
			currentPod.Status.InitContainerStatuses...,
		)
		statuses = append(statuses, currentPod.Status.EphemeralContainerStatuses...)
		for _, status := range statuses {
			terminated := status.LastState["terminated"]
			if terminated.Reason == "" && terminated.FinishedAt == "" {
				terminated = status.State["terminated"]
			}
			oomKilled := strings.EqualFold(terminated.Reason, "OOMKilled")
			if status.RestartCount <= 0 && !oomKilled {
				continue
			}
			restarts += status.RestartCount
			kind := "ContainerRestart"
			severity := "warning"
			if oomKilled {
				kind = "OOMKilled"
				severity = "error"
				oomKills++
			}
			timestamp := firstNonEmptyValue(
				terminated.FinishedAt,
				terminated.StartedAt,
				currentPod.Status.StartTime,
			)
			record := outputContainerEvent{
				SchemaVersion: "1",
				Timestamp:     redactor.Text(timestamp),
				Kind:          kind,
				Severity:      severity,
				Namespace:     redactor.Text(currentPod.Metadata.Namespace),
				Pod:           redactor.Text(currentPod.Metadata.Name),
				Container:     redactor.Text(status.Name),
				RestartCount:  status.RestartCount,
				Reason:        redactor.Text(terminated.Reason),
				Message:       redactor.Text(terminated.Message),
				Source:        map[string]string{"type": "kubernetes_container"},
			}
			if err := encoder.Encode(record); err != nil {
				return nil, 0, 0, fmt.Errorf("encode container event: %w", err)
			}
		}
	}
	return output.Bytes(), restarts, oomKills, nil
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sanitizeLog(input []byte, redactor *redact.Redactor, maxBytes int64) ([]byte, bool) {
	output := newBoundedBuffer(maxBytes)
	inPrivateKey := false
	var jsonSkipper redact.JSONValueSkipper
	var jsonContext redact.JSONStructureTracker
	forEachLogLine(input, func(_ int, line []byte) {
		if jsonSkipper.Pending() {
			consumed := jsonSkipper.Consume(string(line))
			if jsonSkipper.Pending() {
				return
			}
			if consumed < len(line) {
				writeSensitiveJSONLogLine(
					output,
					string(line[consumed:]),
					redactor,
					&jsonSkipper,
					redact.JSONAssignmentModeObjectFragment,
					&jsonContext,
				)
				_, _ = output.WriteString("\n")
			}
			finishJSONStructureLine(&jsonSkipper, &jsonContext)
			return
		}
		if jsonContext.Invalid() {
			jsonSkipper.FailClosed()
			return
		}
		if len(line) == 0 {
			if !inPrivateKey {
				jsonContext.EndLine()
				if jsonContext.Invalid() {
					jsonSkipper.FailClosed()
					return
				}
				_, _ = output.WriteString("\n")
			}
			return
		}
		remaining := string(line)
		writeLine := false
		for remaining != "" {
			if inPrivateKey {
				end := privateKeyEndLine.FindStringIndex(remaining)
				if end == nil {
					remaining = ""
					break
				}
				inPrivateKey = false
				remaining = remaining[end[1]:]
				continue
			}

			begin := privateKeyBeginLine.FindStringIndex(remaining)
			if begin == nil {
				mode := jsonContext.AssignmentMode()
				writeSensitiveJSONLogLine(output, remaining, redactor, &jsonSkipper, mode, &jsonContext)
				writeLine = true
				break
			}
			prefix := remaining[:begin[0]]
			if prefix != "" {
				mode := jsonContext.AssignmentMode()
				jsonContext.Observe(prefix)
				sanitized, ok := sanitizeJSONLogText(redactor, prefix, mode)
				if !ok {
					failJSONLog(&jsonSkipper, &jsonContext)
					return
				}
				_, _ = output.WriteString(sanitized)
			}
			_, _ = output.WriteString(redact.Replacement)
			writeLine = true
			remaining = remaining[begin[1]:]
			inPrivateKey = true
		}
		if writeLine {
			_, _ = output.WriteString("\n")
		}
		finishJSONStructureLine(&jsonSkipper, &jsonContext)
	})
	return output.Bytes(), output.Truncated()
}

func writeSensitiveJSONLogLine(
	output *boundedBuffer,
	line string,
	redactor *redact.Redactor,
	jsonSkipper *redact.JSONValueSkipper,
	mode redact.JSONAssignmentMode,
	jsonContext *redact.JSONStructureTracker,
) {
	if jsonContext != nil && jsonContext.Invalid() {
		jsonSkipper.FailClosed()
		return
	}
	remaining := line
	first := true
	for remaining != "" {
		scanMode := mode
		if !first {
			scanMode = redact.JSONAssignmentModeObjectFragment
		}
		assignment, ok := redact.ScanSensitiveJSONAssignment(remaining, scanMode)
		if !ok {
			observeJSONStructure(jsonContext, jsonSkipper, remaining)
			if jsonContext != nil && jsonContext.Invalid() {
				return
			}
			sanitized, valid := sanitizeJSONLogText(redactor, remaining, scanMode)
			if !valid {
				failJSONLog(jsonSkipper, jsonContext)
				return
			}
			_, _ = output.WriteString(sanitized)
			return
		}
		observeJSONStructure(jsonContext, jsonSkipper, remaining[:assignment.ValueOffset])
		if jsonContext != nil && jsonContext.Invalid() {
			return
		}
		prefix := remaining[:assignment.ValueOffset]
		sanitized, valid := sanitizeJSONAssignmentPrefix(redactor, prefix, assignment, scanMode)
		if !valid {
			failJSONLog(jsonSkipper, jsonContext)
			return
		}
		if !strings.HasSuffix(strings.TrimSpace(sanitized), redact.Replacement) {
			sanitized += redact.Replacement
		}
		_, _ = output.WriteString(sanitized)
		jsonSkipper.Start()
		if assignment.Invalid {
			jsonSkipper.FailClosed()
			if jsonContext != nil {
				jsonContext.FailClosed()
			}
			return
		}
		if assignment.ValueOffset >= len(remaining) {
			return
		}
		fragment := remaining[assignment.ValueOffset:]
		consumed := jsonSkipper.Consume(fragment)
		if jsonSkipper.Pending() {
			return
		}
		if consumed <= 0 || consumed > len(fragment) {
			jsonSkipper.FailClosed()
			if jsonContext != nil {
				jsonContext.FailClosed()
			}
			return
		}
		next := fragment[consumed:]
		if len(next) >= len(remaining) {
			jsonSkipper.FailClosed()
			if jsonContext != nil {
				jsonContext.FailClosed()
			}
			return
		}
		remaining = next
		first = false
	}
}

func sanitizeJSONAssignmentPrefix(
	redactor *redact.Redactor,
	prefix string,
	assignment redact.JSONAssignment,
	mode redact.JSONAssignmentMode,
) (string, bool) {
	if mode != redact.JSONAssignmentModeObjectFragment ||
		assignment.KeyOffset < 0 ||
		assignment.KeyOffset > len(prefix) {
		return redactor.JSONLine(prefix), true
	}
	sanitized, ok := redactor.JSONObjectFragment(prefix[:assignment.KeyOffset])
	if !ok {
		return "", false
	}
	return sanitized + prefix[assignment.KeyOffset:], true
}

func sanitizeJSONLogText(
	redactor *redact.Redactor,
	text string,
	mode redact.JSONAssignmentMode,
) (string, bool) {
	if mode == redact.JSONAssignmentModeObjectFragment {
		return redactor.JSONObjectFragment(text)
	}
	return redactor.JSONLine(text), true
}

func failJSONLog(jsonSkipper *redact.JSONValueSkipper, jsonContext *redact.JSONStructureTracker) {
	jsonSkipper.FailClosed()
	if jsonContext != nil {
		jsonContext.FailClosed()
	}
}

func observeJSONStructure(
	jsonContext *redact.JSONStructureTracker,
	jsonSkipper *redact.JSONValueSkipper,
	fragment string,
) {
	if jsonContext == nil {
		return
	}
	jsonContext.Observe(fragment)
	if jsonContext.Invalid() {
		jsonSkipper.FailClosed()
	}
}

func finishJSONStructureLine(jsonSkipper *redact.JSONValueSkipper, jsonContext *redact.JSONStructureTracker) {
	if jsonSkipper.Pending() || jsonContext.Invalid() {
		return
	}
	jsonContext.EndLine()
	if jsonContext.Invalid() {
		jsonSkipper.FailClosed()
	}
}

func forEachLogLine(input []byte, visit func(index int, line []byte)) {
	index := 0
	for len(input) > 0 {
		lineEnd := bytes.IndexByte(input, '\n')
		if lineEnd < 0 {
			visit(index, input)
			return
		}
		visit(index, input[:lineEnd])
		index++
		input = input[lineEnd+1:]
	}
}

func sanitizeStringMap(values map[string]string, redactor *redact.Redactor) map[string]string {
	sanitized := make(map[string]string, len(values))
	for key, value := range values {
		if redact.IsSensitiveKey(key) {
			sanitized[key] = redact.Replacement
		} else {
			sanitized[redactor.Text(key)] = redactor.Text(value)
		}
	}
	return sanitized
}

func sanitizeConditions(
	conditions []podCondition,
	redactor *redact.Redactor,
) []podCondition {
	sanitized := make([]podCondition, len(conditions))
	for index, condition := range conditions {
		sanitized[index] = podCondition{
			Type:               redactor.Text(condition.Type),
			Status:             redactor.Text(condition.Status),
			Reason:             redactor.Text(condition.Reason),
			Message:            redactor.Text(condition.Message),
			LastTransitionTime: redactor.Text(condition.LastTransitionTime),
		}
	}
	return sanitized
}

func sanitizeContainerStates(
	states map[string]containerState,
	redactor *redact.Redactor,
) map[string]containerState {
	sanitized := make(map[string]containerState, len(states))
	for stateName, state := range states {
		sanitized[redactor.Text(stateName)] = containerState{
			Reason:     redactor.Text(state.Reason),
			Message:    redactor.Text(state.Message),
			ExitCode:   state.ExitCode,
			Signal:     state.Signal,
			StartedAt:  redactor.Text(state.StartedAt),
			FinishedAt: redactor.Text(state.FinishedAt),
		}
	}
	return sanitized
}

func discoverNamespaces(
	ctx context.Context,
	config Config,
	baseArguments []string,
	runner Runner,
	redactor *redact.Redactor,
) ([]string, []string, error) {
	arguments := append(
		append([]string{}, baseArguments...),
		"get", "namespaces", "--output", "json",
	)
	result, err := runWithTimeout(
		ctx,
		config.Timeout,
		runner,
		metadataCommandLimit(config.MaxMetadataBytes),
		arguments...,
	)
	if err != nil {
		return nil, nil, commandError("list namespaces", "", result, err, redactor)
	}
	if result.Truncated {
		return nil, nil, errors.New(
			"namespace metadata exceeded the collection limit",
		)
	}
	var listed namespaceList
	if err := json.Unmarshal(result.Stdout, &listed); err != nil {
		return nil, nil, fmt.Errorf("decode namespace metadata: %w", err)
	}
	namespaces := make([]string, 0, len(listed.Items))
	excludedNamespaces := make([]string, 0)
	for _, item := range listed.Items {
		namespace := strings.TrimSpace(item.Metadata.Name)
		if namespace == "" {
			continue
		}
		if config.ExcludeSystemNamespaces && isSystemNamespace(namespace) {
			excludedNamespaces = append(excludedNamespaces, namespace)
			continue
		}
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	sort.Strings(excludedNamespaces)
	if len(namespaces) == 0 {
		return nil, excludedNamespaces, errors.New(
			"no Kubernetes application namespaces were discovered",
		)
	}
	return namespaces, excludedNamespaces, nil
}

func isSystemNamespace(namespace string) bool {
	switch namespace {
	case "kube-system",
		"kube-public",
		"kube-node-lease",
		"gmp-system",
		"gmp-public",
		"cnrm-system",
		"configconnector-operator-system":
		return true
	default:
		return strings.HasPrefix(namespace, "gke-managed-")
	}
}

func collectionNamespaces(config Config) ([]string, error) {
	values := config.Namespaces
	if len(values) == 0 && config.Namespace != "" {
		values = []string{config.Namespace}
	}
	namespaces := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		namespace := strings.TrimSpace(value)
		if namespace == "" {
			return nil, errors.New("namespace cannot be empty")
		}
		if _, duplicate := seen[namespace]; duplicate {
			continue
		}
		seen[namespace] = struct{}{}
		namespaces = append(namespaces, namespace)
	}
	if len(namespaces) == 0 {
		return nil, errors.New("at least one namespace is required")
	}
	return namespaces, nil
}

func podMetadataPath(namespace string, namespaceCount int) string {
	if namespaceCount == 1 {
		return "kubernetes/pods.jsonl"
	}
	return filepath.ToSlash(filepath.Join(
		"kubernetes",
		"pods",
		safePathSegment(namespace)+".jsonl",
	))
}

func eventMetadataPath(namespace string, namespaceCount int) string {
	if namespaceCount == 1 {
		return "kubernetes/events.jsonl"
	}
	return filepath.ToSlash(filepath.Join(
		"kubernetes",
		"events",
		safePathSegment(namespace)+".jsonl",
	))
}

func containerEventPath(namespace string, namespaceCount int) string {
	if namespaceCount == 1 {
		return "kubernetes/container_events.jsonl"
	}
	return filepath.ToSlash(filepath.Join(
		"kubernetes",
		"container_events",
		safePathSegment(namespace)+".jsonl",
	))
}

func reportProgress(config Config, progress Progress) {
	if config.Progress != nil {
		config.Progress(progress)
	}
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

func runWithTimeout(
	parent context.Context,
	timeout time.Duration,
	runner Runner,
	maxBytes int64,
	arguments ...string,
) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result, err := runner.Run(ctx, maxBytes, arguments...)
	if ctx.Err() != nil {
		return result, fmt.Errorf("command timed out after %s: %w", timeout, ctx.Err())
	}
	return result, err
}

func commandError(
	operation string,
	resource string,
	result CommandResult,
	err error,
	redactor *redact.Redactor,
) error {
	issue := issueFromCommand(operation, resource, result, err, redactor)
	return errors.New(issue.Message)
}

func issueFromCommand(
	operation string,
	resource string,
	result CommandResult,
	err error,
	redactor *redact.Redactor,
) Issue {
	message := strings.TrimSpace(string(result.Stderr))
	if message == "" {
		message = err.Error()
	}
	return Issue{
		Operation: operation,
		Resource:  redactor.Text(resource),
		Message:   redactor.Text(message),
	}
}

func containerRestartCount(currentPod pod, containerName string) int {
	statuses := append(
		append([]containerStatus{}, currentPod.Status.ContainerStatuses...),
		currentPod.Status.InitContainerStatuses...,
	)
	statuses = append(statuses, currentPod.Status.EphemeralContainerStatuses...)
	for _, status := range statuses {
		if status.Name == containerName {
			return status.RestartCount
		}
	}
	return 0
}

func metadataCommandLimit(budget int64) int64 {
	const minimumDecodableMetadataBytes int64 = 1 << 20
	return min(max(budget, minimumDecodableMetadataBytes), MaximumMetadataBytes)
}

func eventTimestamp(currentEvent event) string {
	if currentEvent.EventTime != "" {
		return currentEvent.EventTime
	}
	if currentEvent.LastTimestamp != "" {
		return currentEvent.LastTimestamp
	}
	if currentEvent.FirstTimestamp != "" {
		return currentEvent.FirstTimestamp
	}
	return currentEvent.Metadata.CreationTimestamp
}

func reportingComponent(currentEvent event) string {
	if currentEvent.ReportingComponent != "" {
		return currentEvent.ReportingComponent
	}
	return currentEvent.Source.Component
}

func durationArgument(duration time.Duration) string {
	seconds := int64(duration.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}

func safePathSegment(value string) string {
	sanitized := safePathCharacter.ReplaceAllString(value, "_")
	sanitized = strings.Trim(sanitized, ".")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

type boundedBuffer struct {
	buffer      bytes.Buffer
	remaining   int64
	truncated   bool
	stopAtLimit bool
	onLimit     func()
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{remaining: limit}
}

func newStoppingBoundedBuffer(limit int64, onLimit func()) *boundedBuffer {
	return &boundedBuffer{remaining: limit, stopAtLimit: true, onLimit: onLimit}
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	if int64(len(data)) > buffer.remaining {
		data = data[:max(buffer.remaining, 0)]
		buffer.truncated = true
	}
	if len(data) > 0 {
		_, _ = buffer.buffer.Write(data)
		buffer.remaining -= int64(len(data))
	}
	if buffer.truncated && buffer.stopAtLimit {
		if buffer.onLimit != nil {
			buffer.onLimit()
			buffer.onLimit = nil
		}
		return len(data), errCommandOutputLimit
	}
	return originalLength, nil
}

func (buffer *boundedBuffer) WriteString(data string) (int, error) {
	originalLength := len(data)
	if int64(len(data)) > buffer.remaining {
		data = data[:max(buffer.remaining, 0)]
		buffer.truncated = true
	}
	if len(data) > 0 {
		_, _ = buffer.buffer.WriteString(data)
		buffer.remaining -= int64(len(data))
	}
	if buffer.stopAtLimit && buffer.truncated {
		if buffer.onLimit != nil {
			buffer.onLimit()
		}
		return len(data), errCommandOutputLimit
	}
	return originalLength, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) Truncated() bool {
	return buffer.truncated
}
