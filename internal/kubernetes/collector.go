package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
)

const (
	metadataOutputLimit = 64 << 20
	defaultLogWorkers   = 8
)

var safePathCharacter = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Sink receives sanitized files for the support bundle.
type Sink interface {
	Add(path string, data []byte) error
}

// CommandResult contains bounded command output.
type CommandResult struct {
	Stdout    []byte
	Stderr    []byte
	Truncated bool
}

// Runner executes kubectl without invoking a shell.
type Runner interface {
	Run(ctx context.Context, maxBytes int64, arguments ...string) (CommandResult, error)
}

// ExecRunner executes a kubectl-compatible binary.
type ExecRunner struct {
	Binary string
}

// Run executes one bounded kubectl command.
func (runner ExecRunner) Run(
	ctx context.Context,
	maxBytes int64,
	arguments ...string,
) (CommandResult, error) {
	stdout := newBoundedBuffer(maxBytes)
	stderr := newBoundedBuffer(64 << 10)
	command := exec.CommandContext(ctx, runner.Binary, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	return CommandResult{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: stdout.Truncated(),
	}, err
}

// Config controls a Kubernetes collection.
type Config struct {
	Namespace               string
	Namespaces              []string
	AllNamespaces           bool
	ExcludeSystemNamespaces bool
	Selector                string
	Context                 string
	Kubeconfig              string
	Since                   time.Duration
	Timeout                 time.Duration
	MaxLogBytes             int64
	LogWorkers              int
	Progress                func(Progress)
}

// Progress reports coarse collection stages without exposing log contents.
type Progress struct {
	Stage     string
	Current   int
	Total     int
	Namespace string
	Workers   int
}

// Issue records a sanitized non-fatal collection failure.
type Issue struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource,omitempty"`
	Message   string `json:"message"`
}

// Report summarizes Kubernetes data added to the bundle.
type Report struct {
	AllNamespaces       bool     `json:"all_namespaces"`
	ExcludedNamespaces  []string `json:"excluded_namespaces,omitempty"`
	Namespaces          []string `json:"namespaces"`
	NamespacesRequested int      `json:"namespaces_requested"`
	Pods                int      `json:"pods"`
	Containers          int      `json:"containers"`
	InitContainers      int      `json:"init_containers"`
	LogFiles            int      `json:"log_files"`
	TruncatedLogFiles   int      `json:"truncated_log_files"`
	Issues              []Issue  `json:"issues,omitempty"`
}

type namespaceList struct {
	Items []struct {
		Metadata objectMetadata `json:"metadata"`
	} `json:"items"`
}

type logRequest struct {
	namespace      string
	namespaceCount int
	podName        string
	containerName  string
	previous       bool
}

type collectedLog struct {
	path      string
	data      []byte
	truncated bool
	issue     *Issue
}

type podList struct {
	Items []pod `json:"items"`
}

type pod struct {
	Metadata objectMetadata `json:"metadata"`
	Spec     struct {
		NodeName       string          `json:"nodeName"`
		Containers     []containerSpec `json:"containers"`
		InitContainers []containerSpec `json:"initContainers"`
	} `json:"spec"`
	Status podStatus `json:"status"`
}

type objectMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Labels            map[string]string `json:"labels"`
	CreationTimestamp string            `json:"creationTimestamp"`
}

type containerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type podStatus struct {
	Phase                 string            `json:"phase"`
	StartTime             string            `json:"startTime"`
	Conditions            []podCondition    `json:"conditions"`
	ContainerStatuses     []containerStatus `json:"containerStatuses"`
	InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
}

type podCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

type containerStatus struct {
	Name         string                    `json:"name"`
	Ready        bool                      `json:"ready"`
	RestartCount int                       `json:"restartCount"`
	Image        string                    `json:"image"`
	ImageID      string                    `json:"imageID"`
	State        map[string]containerState `json:"state"`
	LastState    map[string]containerState `json:"lastState"`
}

type containerState struct {
	Reason     string `json:"reason"`
	Message    string `json:"message"`
	ExitCode   int    `json:"exitCode"`
	Signal     int    `json:"signal"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
}

type eventList struct {
	Items []event `json:"items"`
}

type event struct {
	Metadata       objectMetadata  `json:"metadata"`
	Involved       objectReference `json:"involvedObject"`
	Type           string          `json:"type"`
	Reason         string          `json:"reason"`
	Message        string          `json:"message"`
	Count          int             `json:"count"`
	FirstTimestamp string          `json:"firstTimestamp"`
	LastTimestamp  string          `json:"lastTimestamp"`
	EventTime      string          `json:"eventTime"`
	Source         struct {
		Component string `json:"component"`
	} `json:"source"`
	ReportingComponent string `json:"reportingComponent"`
}

type objectReference struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type outputPod struct {
	SchemaVersion  string                  `json:"schema_version"`
	Timestamp      string                  `json:"@timestamp,omitempty"`
	Kind           string                  `json:"kind"`
	Namespace      string                  `json:"namespace"`
	Name           string                  `json:"name"`
	NodeName       string                  `json:"node_name,omitempty"`
	Labels         map[string]string       `json:"labels,omitempty"`
	Phase          string                  `json:"phase"`
	Conditions     []podCondition          `json:"conditions,omitempty"`
	Containers     []outputContainerStatus `json:"containers,omitempty"`
	InitContainers []outputContainerStatus `json:"init_containers,omitempty"`
	Source         map[string]string       `json:"source"`
}

type outputContainerStatus struct {
	Name         string                    `json:"name"`
	Ready        bool                      `json:"ready"`
	RestartCount int                       `json:"restart_count"`
	Image        string                    `json:"image,omitempty"`
	ImageID      string                    `json:"image_id,omitempty"`
	State        map[string]containerState `json:"state,omitempty"`
	LastState    map[string]containerState `json:"last_state,omitempty"`
}

type outputEvent struct {
	SchemaVersion      string            `json:"schema_version"`
	Timestamp          string            `json:"@timestamp,omitempty"`
	Kind               string            `json:"kind"`
	Namespace          string            `json:"namespace"`
	Name               string            `json:"name"`
	Type               string            `json:"type"`
	Reason             string            `json:"reason"`
	Message            string            `json:"message"`
	Count              int               `json:"count"`
	FirstTimestamp     string            `json:"first_timestamp,omitempty"`
	LastTimestamp      string            `json:"last_timestamp,omitempty"`
	ReportingComponent string            `json:"reporting_component,omitempty"`
	Source             map[string]string `json:"source"`
}

// Collect gathers safe pod metadata, events, and current and previous container logs.
func Collect(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
) (Report, error) {
	if config.MaxLogBytes <= 0 {
		return Report{}, errors.New("max log bytes must be positive")
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
	}
	logRequests := make([]logRequest, 0)
	for namespaceIndex, namespace := range namespaces {
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
			metadataOutputLimit,
			podArguments...,
		)
		if runErr != nil {
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
		if err := sink.Add(
			podMetadataPath(namespace, len(namespaces)),
			podRecords,
		); err != nil {
			return report, fmt.Errorf("add pod metadata: %w", err)
		}

		collectEvents(
			ctx,
			config,
			namespace,
			len(namespaces),
			runner,
			sink,
			redactor,
			&report,
		)
		for _, currentPod := range pods.Items {
			containers := append(
				append([]containerSpec{}, currentPod.Spec.Containers...),
				currentPod.Spec.InitContainers...,
			)
			report.Containers += len(containers)
			report.InitContainers += len(currentPod.Spec.InitContainers)
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
	collectLogs(
		ctx,
		config,
		runner,
		sink,
		redactor,
		logRequests,
		&report,
	)
	return report, nil
}

func collectEvents(
	ctx context.Context,
	config Config,
	namespace string,
	namespaceCount int,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
	report *Report,
) {
	arguments := append(
		globalArguments(config),
		"get", "events", "--namespace", namespace, "--output", "json",
	)
	result, err := runWithTimeout(
		ctx,
		config.Timeout,
		runner,
		metadataOutputLimit,
		arguments...,
	)
	if err != nil {
		report.Issues = append(
			report.Issues,
			issueFromCommand("list events", namespace, result, err, redactor),
		)
		return
	}
	if result.Truncated {
		report.Issues = append(report.Issues, Issue{
			Operation: "list events",
			Resource:  redactor.Text(namespace),
			Message:   "event metadata exceeded the collection limit",
		})
		return
	}

	var events eventList
	if err := json.Unmarshal(result.Stdout, &events); err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "decode events",
			Resource:  redactor.Text(namespace),
			Message:   redactor.Text(err.Error()),
		})
		return
	}
	records, err := marshalEventRecords(events.Items, redactor)
	if err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "encode events",
			Message:   redactor.Text(err.Error()),
		})
		return
	}
	if err := sink.Add(eventMetadataPath(namespace, namespaceCount), records); err != nil {
		report.Issues = append(report.Issues, Issue{
			Operation: "add events",
			Resource:  redactor.Text(namespace),
			Message:   redactor.Text(err.Error()),
		})
	}
}

func collectLogs(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
	requests []logRequest,
	report *Report,
) {
	workers := config.LogWorkers
	if workers <= 0 {
		workers = defaultLogWorkers
	}
	workers = min(workers, len(requests))
	if workers == 0 {
		return
	}
	jobs := make(chan logRequest)
	results := make(chan collectedLog)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			for request := range jobs {
				results <- readLog(ctx, config, runner, redactor, request)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, request := range requests {
			select {
			case jobs <- request:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		waitGroup.Wait()
		close(results)
	}()
	completed := 0
	progressInterval := max(len(requests)/20, 1)
	for result := range results {
		completed++
		if completed == len(requests) || completed%progressInterval == 0 {
			reportProgress(config, Progress{
				Stage:   "logs_progress",
				Current: completed,
				Total:   len(requests),
				Workers: workers,
			})
		}
		if result.issue != nil {
			report.Issues = append(report.Issues, *result.issue)
			continue
		}
		if err := sink.Add(result.path, result.data); err != nil {
			report.Issues = append(report.Issues, Issue{
				Operation: "add container log",
				Resource:  result.path,
				Message:   redactor.Text(err.Error()),
			})
			continue
		}
		report.LogFiles++
		if result.truncated {
			report.TruncatedLogFiles++
		}
	}
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
		"--since", durationArgument(config.Since),
	)
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
		config.MaxLogBytes,
		arguments...,
	)
	resource := request.namespace + "/" + request.podName + "/" + request.containerName
	if err != nil {
		issue := issueFromCommand(operation, resource, result, err, redactor)
		return collectedLog{issue: &issue}
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
	return collectedLog{
		path:      path,
		data:      sanitizeLog(result.Stdout, redactor),
		truncated: result.Truncated,
	}
}

func marshalPodRecords(pods []pod, redactor *redact.Redactor) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, currentPod := range pods {
		record := outputPod{
			SchemaVersion: "1",
			Timestamp:     currentPod.Status.StartTime,
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

func sanitizeLog(input []byte, redactor *redact.Redactor) []byte {
	lines := bytes.Split(input, []byte("\n"))
	var output bytes.Buffer
	for index, line := range lines {
		if index == len(lines)-1 && len(line) == 0 {
			break
		}
		output.WriteString(redactor.JSONLine(string(line)))
		output.WriteByte('\n')
	}
	return output.Bytes()
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
		metadataOutputLimit,
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
	for _, status := range statuses {
		if status.Name == containerName {
			return status.RestartCount
		}
	}
	return 0
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
	buffer    bytes.Buffer
	remaining int64
	truncated bool
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{remaining: limit}
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
	return originalLength, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) Truncated() bool {
	return buffer.truncated
}
