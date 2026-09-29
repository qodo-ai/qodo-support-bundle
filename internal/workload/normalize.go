package workload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

// Kind identifies a Kubernetes workload kind accepted by NormalizeListJSON.
type Kind string

const (
	DeploymentKind              Kind = "Deployment"
	StatefulSetKind             Kind = "StatefulSet"
	DaemonSetKind               Kind = "DaemonSet"
	JobKind                     Kind = "Job"
	CronJobKind                 Kind = "CronJob"
	serviceKind                 Kind = "Service"
	endpointSliceKind           Kind = "EndpointSlice"
	horizontalPodAutoscalerKind Kind = "HorizontalPodAutoscaler"
	persistentVolumeClaimKind   Kind = "PersistentVolumeClaim"
)

const (
	maxWorkloads            = 100
	maxStringBytes          = 512
	maxContainers           = 32
	maxConditions           = 32
	maxMapEntries           = 32
	maxTolerations          = 32
	maxTopologySpread       = 16
	maxAffinityTerms        = 16
	maxSelectorTerms        = 16
	maxSelectorRequirements = 16
	maxSelectorValues       = 16
	maxNamespaces           = 16
	maxJSONDepth            = 64
)

// NormalizationResult contains normalized workloads and reports whether any
// retained string had controls removed or any string or collection was
// shortened to a deterministic hard bound.
type NormalizationResult struct {
	Workloads []Workload
	Truncated bool
}

// NormalizeListJSON decodes one kubectl-style list response for kind and
// returns only the normalized support-bundle fields. The caller must provide a
// configured redactor. Unknown JSON fields are ignored, while duplicate keys,
// mismatched kinds, ambiguous probes, invalid timestamps, and invalid probe
// ports are rejected.
func NormalizeListJSON(
	kind Kind,
	data []byte,
	redactor *redact.Redactor,
) (NormalizationResult, error) {
	if err := validateKind(kind); err != nil {
		return NormalizationResult{}, err
	}
	normalizer, err := newNormalizer(data, redactor, "workload")
	if err != nil {
		return NormalizationResult{}, err
	}

	var workloads []Workload
	switch kind {
	case DeploymentKind:
		workloads, err = decodeDeployments(data, normalizer)
	case StatefulSetKind:
		workloads, err = decodeStatefulSets(data, normalizer)
	case DaemonSetKind:
		workloads, err = decodeDaemonSets(data, normalizer)
	case JobKind:
		workloads, err = decodeJobs(data, normalizer)
	case CronJobKind:
		workloads, err = decodeCronJobs(data, normalizer)
	}
	if err != nil {
		return NormalizationResult{}, err
	}
	return NormalizationResult{
		Workloads: workloads,
		Truncated: normalizer.truncated,
	}, nil
}

func newNormalizer(
	data []byte,
	redactor *redact.Redactor,
	subject string,
) (*normalizer, error) {
	if !redactor.Ready() {
		return nil, errors.New("configured redactor is required")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s JSON is not valid UTF-8", subject)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("validate %s JSON: %w", subject, err)
	}
	return &normalizer{redactor: redactor}, nil
}

func validateKind(kind Kind) error {
	switch kind {
	case DeploymentKind, StatefulSetKind, DaemonSetKind, JobKind, CronJobKind:
		return nil
	default:
		return fmt.Errorf("unsupported workload kind %q", kind)
	}
}

type normalizer struct {
	redactor    *redact.Redactor
	validateAll bool
	truncated   bool
}

func (current *normalizer) validator() *normalizer {
	return &normalizer{
		redactor:    current.redactor,
		validateAll: true,
	}
}

func decodeDeployments(data []byte, normalizer *normalizer) ([]Workload, error) {
	var list rawDeploymentList
	if err := decodeList(data, DeploymentKind, &list); err != nil {
		return nil, err
	}
	if err := validateListKind(list.Kind, DeploymentKind); err != nil {
		return nil, err
	}
	validator := normalizer.validator()
	for index := range list.Items {
		if _, err := normalizeDeploymentItem(validator, list.Items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(list.Items), maxWorkloads)
	output := make([]Workload, 0, count)
	for index := 0; index < count; index++ {
		workload, err := normalizeDeploymentItem(normalizer, list.Items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, workload)
	}
	return output, nil
}

func normalizeDeploymentItem(
	normalizer *normalizer,
	item rawDeployment,
	index int,
) (Workload, error) {
	if err := validateItemKind(item.Kind, DeploymentKind, index); err != nil {
		return Workload{}, err
	}
	workload, err := normalizer.controllerWorkload(
		DeploymentKind,
		item.Metadata,
		item.Spec.Template,
		item.Spec.Strategy.Type,
		Replicas{
			Desired:   copyInt32(item.Spec.Replicas),
			Current:   copyInt32(item.Status.Replicas),
			Ready:     copyInt32(item.Status.ReadyReplicas),
			Available: copyInt32(item.Status.AvailableReplicas),
		},
		item.Status.Conditions,
	)
	if err != nil {
		return Workload{}, fmt.Errorf("normalize Deployment item %d: %w", index, err)
	}
	return workload, nil
}

func decodeStatefulSets(data []byte, normalizer *normalizer) ([]Workload, error) {
	var list rawStatefulSetList
	if err := decodeList(data, StatefulSetKind, &list); err != nil {
		return nil, err
	}
	if err := validateListKind(list.Kind, StatefulSetKind); err != nil {
		return nil, err
	}
	validator := normalizer.validator()
	for index := range list.Items {
		if _, err := normalizeStatefulSetItem(validator, list.Items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(list.Items), maxWorkloads)
	output := make([]Workload, 0, count)
	for index := 0; index < count; index++ {
		workload, err := normalizeStatefulSetItem(normalizer, list.Items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, workload)
	}
	return output, nil
}

func normalizeStatefulSetItem(
	normalizer *normalizer,
	item rawStatefulSet,
	index int,
) (Workload, error) {
	if err := validateItemKind(item.Kind, StatefulSetKind, index); err != nil {
		return Workload{}, err
	}
	workload, err := normalizer.controllerWorkload(
		StatefulSetKind,
		item.Metadata,
		item.Spec.Template,
		item.Spec.UpdateStrategy.Type,
		Replicas{
			Desired:   copyInt32(item.Spec.Replicas),
			Current:   copyInt32(item.Status.Replicas),
			Ready:     copyInt32(item.Status.ReadyReplicas),
			Available: copyInt32(item.Status.AvailableReplicas),
		},
		item.Status.Conditions,
	)
	if err != nil {
		return Workload{}, fmt.Errorf("normalize StatefulSet item %d: %w", index, err)
	}
	return workload, nil
}

func decodeDaemonSets(data []byte, normalizer *normalizer) ([]Workload, error) {
	var list rawDaemonSetList
	if err := decodeList(data, DaemonSetKind, &list); err != nil {
		return nil, err
	}
	if err := validateListKind(list.Kind, DaemonSetKind); err != nil {
		return nil, err
	}
	validator := normalizer.validator()
	for index := range list.Items {
		if _, err := normalizeDaemonSetItem(validator, list.Items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(list.Items), maxWorkloads)
	output := make([]Workload, 0, count)
	for index := 0; index < count; index++ {
		workload, err := normalizeDaemonSetItem(normalizer, list.Items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, workload)
	}
	return output, nil
}

func normalizeDaemonSetItem(
	normalizer *normalizer,
	item rawDaemonSet,
	index int,
) (Workload, error) {
	if err := validateItemKind(item.Kind, DaemonSetKind, index); err != nil {
		return Workload{}, err
	}
	workload, err := normalizer.controllerWorkload(
		DaemonSetKind,
		item.Metadata,
		item.Spec.Template,
		item.Spec.UpdateStrategy.Type,
		Replicas{
			Desired:   copyInt32(item.Status.DesiredNumberScheduled),
			Current:   copyInt32(item.Status.CurrentNumberScheduled),
			Ready:     copyInt32(item.Status.NumberReady),
			Available: copyInt32(item.Status.NumberAvailable),
		},
		item.Status.Conditions,
	)
	if err != nil {
		return Workload{}, fmt.Errorf("normalize DaemonSet item %d: %w", index, err)
	}
	return workload, nil
}

func decodeJobs(data []byte, normalizer *normalizer) ([]Workload, error) {
	var list rawJobList
	if err := decodeList(data, JobKind, &list); err != nil {
		return nil, err
	}
	if err := validateListKind(list.Kind, JobKind); err != nil {
		return nil, err
	}
	validator := normalizer.validator()
	for index := range list.Items {
		if _, err := normalizeJobItem(validator, list.Items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(list.Items), maxWorkloads)
	output := make([]Workload, 0, count)
	for index := 0; index < count; index++ {
		workload, err := normalizeJobItem(normalizer, list.Items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, workload)
	}
	return output, nil
}

func normalizeJobItem(
	normalizer *normalizer,
	item rawJob,
	index int,
) (Workload, error) {
	if err := validateItemKind(item.Kind, JobKind, index); err != nil {
		return Workload{}, err
	}
	workload, err := normalizer.controllerWorkload(
		JobKind,
		item.Metadata,
		item.Spec.Template,
		"",
		Replicas{},
		item.Status.Conditions,
	)
	if err != nil {
		return Workload{}, fmt.Errorf("normalize Job item %d: %w", index, err)
	}
	workload.JobStatus = &JobStatus{
		Active:    item.Status.Active,
		Succeeded: item.Status.Succeeded,
		Failed:    item.Status.Failed,
		Suspended: item.Spec.Suspend != nil && *item.Spec.Suspend,
	}
	return workload, nil
}

func decodeCronJobs(data []byte, normalizer *normalizer) ([]Workload, error) {
	var list rawCronJobList
	if err := decodeList(data, CronJobKind, &list); err != nil {
		return nil, err
	}
	if err := validateListKind(list.Kind, CronJobKind); err != nil {
		return nil, err
	}
	validator := normalizer.validator()
	for index := range list.Items {
		if _, err := normalizeCronJobItem(validator, list.Items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(list.Items), maxWorkloads)
	output := make([]Workload, 0, count)
	for index := 0; index < count; index++ {
		workload, err := normalizeCronJobItem(normalizer, list.Items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, workload)
	}
	return output, nil
}

func normalizeCronJobItem(
	normalizer *normalizer,
	item rawCronJob,
	index int,
) (Workload, error) {
	if err := validateItemKind(item.Kind, CronJobKind, index); err != nil {
		return Workload{}, err
	}
	if item.Spec.JobTemplate == nil || item.Spec.JobTemplate.Spec == nil {
		return Workload{}, fmt.Errorf(
			"normalize CronJob item %d: job template spec is required",
			index,
		)
	}
	workload, err := normalizer.controllerWorkload(
		CronJobKind,
		item.Metadata,
		item.Spec.JobTemplate.Spec.Template,
		"",
		Replicas{},
		nil,
	)
	if err != nil {
		return Workload{}, fmt.Errorf("normalize CronJob item %d: %w", index, err)
	}
	if len(item.Status.Active) > math.MaxInt32 {
		return Workload{}, fmt.Errorf("normalize CronJob item %d: active job count overflows int32", index)
	}
	workload.JobStatus = &JobStatus{
		Active:    int32(len(item.Status.Active)),
		Suspended: item.Spec.Suspend != nil && *item.Spec.Suspend,
	}
	return workload, nil
}

func decodeList(data []byte, kind Kind, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s list: %w", kind, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s list: multiple JSON values", kind)
		}
		return fmt.Errorf("decode %s list: trailing JSON: %w", kind, err)
	}
	return nil
}

func validateListKind(actual string, kind Kind) error {
	expected := string(kind) + "List"
	if actual != expected {
		return fmt.Errorf("decode %s list: top-level kind %q, want %q", kind, actual, expected)
	}
	return nil
}

func validateItemKind(actual string, expected Kind, index int) error {
	if actual != string(expected) {
		return fmt.Errorf(
			"decode %s list: item %d kind %q, want %q",
			expected,
			index,
			actual,
			expected,
		)
	}
	return nil
}

func (normalizer *normalizer) controllerWorkload(
	kind Kind,
	metadata rawMetadata,
	template *rawPodTemplate,
	strategy string,
	replicas Replicas,
	conditions []rawCondition,
) (Workload, error) {
	if template == nil || template.Spec == nil {
		return Workload{}, errors.New("pod template spec is required")
	}
	if len(template.Spec.Containers) == 0 {
		return Workload{}, errors.New("pod template must contain at least one container")
	}
	resource, err := normalizer.resource(kind, metadata)
	if err != nil {
		return Workload{}, err
	}
	containers, err := normalizer.containers(template.Spec.Containers)
	if err != nil {
		return Workload{}, err
	}
	scheduling, err := normalizer.scheduling(*template.Spec)
	if err != nil {
		return Workload{}, err
	}
	normalizedConditions, err := normalizer.conditions(conditions)
	if err != nil {
		return Workload{}, err
	}
	return Workload{
		Resource:           resource,
		ServiceAccountName: normalizer.string(template.Spec.ServiceAccountName),
		Strategy:           normalizer.string(strategy),
		Replicas:           replicas,
		Containers:         containers,
		Scheduling:         scheduling,
		Conditions:         normalizedConditions,
	}, nil
}

func (normalizer *normalizer) resource(kind Kind, metadata rawMetadata) (Resource, error) {
	if metadata.Name == "" || metadata.Namespace == "" {
		return Resource{}, errors.New("metadata name and namespace are required")
	}
	name := normalizer.string(metadata.Name)
	namespace := normalizer.string(metadata.Namespace)
	if name == "" || namespace == "" {
		return Resource{}, errors.New("metadata name and namespace must survive sanitization")
	}
	createdAt, err := parseOptionalTime(metadata.CreationTimestamp)
	if err != nil {
		return Resource{}, fmt.Errorf("creation timestamp: %w", err)
	}

	labelValues := make(map[string]string)
	for key, value := range metadata.Labels {
		if identityLabelAllowed(key) {
			labelValues[key] = normalizer.string(value)
		}
	}
	labels, err := NewIdentityLabels(labelValues, normalizer.redactor)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Kind:              string(kind),
		Namespace:         namespace,
		Name:              name,
		CreationTimestamp: createdAt,
		Labels:            labels,
	}, nil
}

func (normalizer *normalizer) containers(input []rawContainer) ([]Container, error) {
	count := normalizer.boundedLength(len(input), maxContainers)
	output := make([]Container, 0, count)
	for index := 0; index < count; index++ {
		container := input[index]
		if container.Name == "" || container.Image == "" {
			return nil, fmt.Errorf("container %d name and image are required", index)
		}
		name := normalizer.string(container.Name)
		image := normalizer.string(container.Image)
		if name == "" || image == "" {
			return nil, fmt.Errorf(
				"container %d name and image must survive sanitization",
				index,
			)
		}
		liveness, err := normalizer.probe(container.LivenessProbe)
		if err != nil {
			return nil, fmt.Errorf("container %d liveness probe: %w", index, err)
		}
		readiness, err := normalizer.probe(container.ReadinessProbe)
		if err != nil {
			return nil, fmt.Errorf("container %d readiness probe: %w", index, err)
		}
		startup, err := normalizer.probe(container.StartupProbe)
		if err != nil {
			return nil, fmt.Errorf("container %d startup probe: %w", index, err)
		}
		output = append(output, Container{
			Name:            name,
			Image:           image,
			ImagePullPolicy: normalizer.string(container.ImagePullPolicy),
			Resources: Resources{
				CPURequest:    normalizer.string(container.Resources.Requests.CPU),
				MemoryRequest: normalizer.string(container.Resources.Requests.Memory),
				CPULimit:      normalizer.string(container.Resources.Limits.CPU),
				MemoryLimit:   normalizer.string(container.Resources.Limits.Memory),
			},
			LivenessProbe:  liveness,
			ReadinessProbe: readiness,
			StartupProbe:   startup,
		})
	}
	return output, nil
}

func (normalizer *normalizer) probe(input *rawProbe) (*Probe, error) {
	if input == nil {
		return nil, nil
	}
	handlers := 0
	if input.HTTPGet != nil {
		handlers++
	}
	if input.TCPSocket != nil {
		handlers++
	}
	if input.GRPC != nil {
		handlers++
	}
	if input.Exec != nil {
		handlers++
	}
	if handlers != 1 {
		return nil, fmt.Errorf("exactly one probe handler is required, got %d", handlers)
	}

	output := &Probe{
		InitialDelaySeconds: input.InitialDelaySeconds,
		PeriodSeconds:       input.PeriodSeconds,
		TimeoutSeconds:      input.TimeoutSeconds,
		SuccessThreshold:    input.SuccessThreshold,
		FailureThreshold:    input.FailureThreshold,
	}
	switch {
	case input.HTTPGet != nil:
		if !input.HTTPGet.Port.set {
			return nil, errors.New("HTTP GET probe port is required")
		}
		output.Type = "http_get"
		output.Path = normalizer.string(input.HTTPGet.Path)
		output.Port = normalizer.string(input.HTTPGet.Port.value)
		if output.Port == "" {
			return nil, errors.New("HTTP GET probe port must survive sanitization")
		}
		output.Scheme = normalizer.string(input.HTTPGet.Scheme)
	case input.TCPSocket != nil:
		if !input.TCPSocket.Port.set {
			return nil, errors.New("TCP socket probe port is required")
		}
		output.Type = "tcp_socket"
		output.Port = normalizer.string(input.TCPSocket.Port.value)
		if output.Port == "" {
			return nil, errors.New("TCP socket probe port must survive sanitization")
		}
	case input.GRPC != nil:
		if input.GRPC.Port < 1 || input.GRPC.Port > 65535 {
			return nil, errors.New("gRPC probe port must be between 1 and 65535")
		}
		output.Type = "grpc"
		output.Port = fmt.Sprint(input.GRPC.Port)
	case input.Exec != nil:
		output.Type = "exec"
	}
	return output, nil
}

func (normalizer *normalizer) scheduling(input rawPodSpec) (Scheduling, error) {
	nodeSelector, err := normalizer.stringMap(input.NodeSelector)
	if err != nil {
		return Scheduling{}, fmt.Errorf("node selector: %w", err)
	}
	affinity, err := normalizer.affinity(input.Affinity)
	if err != nil {
		return Scheduling{}, fmt.Errorf("affinity: %w", err)
	}

	tolerationCount := normalizer.boundedLength(len(input.Tolerations), maxTolerations)
	tolerations := make([]Toleration, 0, tolerationCount)
	for index := 0; index < tolerationCount; index++ {
		item := input.Tolerations[index]
		tolerations = append(tolerations, Toleration{
			Key:               normalizer.string(item.Key),
			Operator:          normalizer.string(item.Operator),
			Value:             normalizer.string(item.Value),
			Effect:            normalizer.string(item.Effect),
			TolerationSeconds: copyInt64(item.TolerationSeconds),
		})
	}

	spreadCount := normalizer.boundedLength(len(input.TopologySpreadConstraints), maxTopologySpread)
	topologySpread := make([]TopologySpread, 0, spreadCount)
	for index := 0; index < spreadCount; index++ {
		item := input.TopologySpreadConstraints[index]
		selector, err := normalizer.labelSelector(item.LabelSelector)
		if err != nil {
			return Scheduling{}, fmt.Errorf("topology spread %d selector: %w", index, err)
		}
		topologySpread = append(topologySpread, TopologySpread{
			MaxSkew:            item.MaxSkew,
			TopologyKey:        normalizer.string(item.TopologyKey),
			WhenUnsatisfiable:  normalizer.string(item.WhenUnsatisfiable),
			MinDomains:         copyInt32(item.MinDomains),
			NodeAffinityPolicy: normalizer.string(item.NodeAffinityPolicy),
			NodeTaintsPolicy:   normalizer.string(item.NodeTaintsPolicy),
			Selector:           selector,
		})
	}
	return Scheduling{
		NodeSelector:      nodeSelector,
		SchedulerName:     normalizer.string(input.SchedulerName),
		PriorityClassName: normalizer.string(input.PriorityClassName),
		Tolerations:       tolerations,
		Affinity:          affinity,
		TopologySpread:    topologySpread,
	}, nil
}

func (normalizer *normalizer) affinity(input *rawAffinity) (*Affinity, error) {
	if input == nil {
		return nil, nil
	}
	output := &Affinity{}
	if input.NodeAffinity != nil {
		required, err := normalizer.nodeSelector(input.NodeAffinity.Required)
		if err != nil {
			return nil, fmt.Errorf("required node selector: %w", err)
		}
		output.RequiredNode = required
		count := normalizer.boundedLength(len(input.NodeAffinity.Preferred), maxAffinityTerms)
		output.PreferredNode = make([]WeightedSelectorTerm, 0, count)
		for index := 0; index < count; index++ {
			item := input.NodeAffinity.Preferred[index]
			term, err := normalizer.selectorTerm(item.Preference)
			if err != nil {
				return nil, fmt.Errorf("preferred node term %d: %w", index, err)
			}
			output.PreferredNode = append(output.PreferredNode, WeightedSelectorTerm{
				Weight:     item.Weight,
				Preference: term,
			})
		}
	}
	var err error
	if input.PodAffinity != nil {
		output.RequiredPod, err = normalizer.podAffinityTerms(input.PodAffinity.Required)
		if err != nil {
			return nil, fmt.Errorf("required pod affinity: %w", err)
		}
		output.PreferredPod, err = normalizer.weightedPodAffinityTerms(input.PodAffinity.Preferred)
		if err != nil {
			return nil, fmt.Errorf("preferred pod affinity: %w", err)
		}
	}
	if input.PodAntiAffinity != nil {
		output.RequiredPodAnti, err = normalizer.podAffinityTerms(input.PodAntiAffinity.Required)
		if err != nil {
			return nil, fmt.Errorf("required pod anti-affinity: %w", err)
		}
		output.PreferredPodAnti, err = normalizer.weightedPodAffinityTerms(input.PodAntiAffinity.Preferred)
		if err != nil {
			return nil, fmt.Errorf("preferred pod anti-affinity: %w", err)
		}
	}
	return output, nil
}

func (normalizer *normalizer) nodeSelector(input *rawNodeSelector) (*NodeSelector, error) {
	if input == nil {
		return nil, nil
	}
	count := normalizer.boundedLength(len(input.NodeSelectorTerms), maxSelectorTerms)
	output := &NodeSelector{Terms: make([]SelectorTerm, 0, count)}
	for index := 0; index < count; index++ {
		term, err := normalizer.selectorTerm(input.NodeSelectorTerms[index])
		if err != nil {
			return nil, fmt.Errorf("term %d: %w", index, err)
		}
		output.Terms = append(output.Terms, term)
	}
	return output, nil
}

func (normalizer *normalizer) selectorTerm(input rawNodeSelectorTerm) (SelectorTerm, error) {
	expressions := normalizer.selectorRequirements(input.MatchExpressions)
	fields := normalizer.selectorRequirements(input.MatchFields)
	return SelectorTerm{
		MatchExpressions: expressions,
		MatchFields:      fields,
	}, nil
}

func (normalizer *normalizer) selectorRequirements(
	input []rawSelectorRequirement,
) []SelectorRequirement {
	count := normalizer.boundedLength(len(input), maxSelectorRequirements)
	output := make([]SelectorRequirement, 0, count)
	for index := 0; index < count; index++ {
		item := input[index]
		valueCount := normalizer.boundedLength(len(item.Values), maxSelectorValues)
		values := make([]string, 0, valueCount)
		for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
			values = append(values, normalizer.string(item.Values[valueIndex]))
		}
		output = append(output, SelectorRequirement{
			Key:      normalizer.string(item.Key),
			Operator: normalizer.string(item.Operator),
			Values:   values,
		})
	}
	return output
}

func (normalizer *normalizer) podAffinityTerms(
	input []rawPodAffinityTerm,
) ([]PodAffinityTerm, error) {
	count := normalizer.boundedLength(len(input), maxAffinityTerms)
	output := make([]PodAffinityTerm, 0, count)
	for index := 0; index < count; index++ {
		item, err := normalizer.podAffinityTerm(input[index])
		if err != nil {
			return nil, fmt.Errorf("term %d: %w", index, err)
		}
		output = append(output, item)
	}
	return output, nil
}

func (normalizer *normalizer) weightedPodAffinityTerms(
	input []rawWeightedPodAffinityTerm,
) ([]WeightedPodAffinity, error) {
	count := normalizer.boundedLength(len(input), maxAffinityTerms)
	output := make([]WeightedPodAffinity, 0, count)
	for index := 0; index < count; index++ {
		term, err := normalizer.podAffinityTerm(input[index].PodAffinityTerm)
		if err != nil {
			return nil, fmt.Errorf("term %d: %w", index, err)
		}
		output = append(output, WeightedPodAffinity{
			Weight:          input[index].Weight,
			PodAffinityTerm: term,
		})
	}
	return output, nil
}

func (normalizer *normalizer) podAffinityTerm(
	input rawPodAffinityTerm,
) (PodAffinityTerm, error) {
	selector, err := normalizer.labelSelector(input.LabelSelector)
	if err != nil {
		return PodAffinityTerm{}, fmt.Errorf("label selector: %w", err)
	}
	namespaceSelector, err := normalizer.labelSelector(input.NamespaceSelector)
	if err != nil {
		return PodAffinityTerm{}, fmt.Errorf("namespace selector: %w", err)
	}
	count := normalizer.boundedLength(len(input.Namespaces), maxNamespaces)
	namespaces := make([]string, 0, count)
	for index := 0; index < count; index++ {
		namespaces = append(namespaces, normalizer.string(input.Namespaces[index]))
	}
	return PodAffinityTerm{
		TopologyKey:       normalizer.string(input.TopologyKey),
		Namespaces:        namespaces,
		Selector:          selector,
		NamespaceSelector: namespaceSelector,
	}, nil
}

func (normalizer *normalizer) labelSelector(
	input *rawLabelSelector,
) (*LabelSelector, error) {
	if input == nil {
		return nil, nil
	}
	labels, err := normalizer.stringMap(input.MatchLabels)
	if err != nil {
		return nil, err
	}
	return &LabelSelector{
		MatchLabels:      labels,
		MatchExpressions: normalizer.selectorRequirements(input.MatchExpressions),
	}, nil
}

func (normalizer *normalizer) conditions(input []rawCondition) ([]Condition, error) {
	count := normalizer.boundedLength(len(input), maxConditions)
	output := make([]Condition, 0, count)
	for index := 0; index < count; index++ {
		item := input[index]
		transitionTime, err := parseOptionalTime(item.LastTransitionTime)
		if err != nil {
			return nil, fmt.Errorf("condition %d transition time: %w", index, err)
		}
		output = append(output, Condition{
			Type:               normalizer.string(item.Type),
			Status:             normalizer.string(item.Status),
			Reason:             normalizer.string(item.Reason),
			Message:            normalizer.string(item.Message),
			LastTransitionTime: transitionTime,
		})
	}
	return output, nil
}

func (normalizer *normalizer) stringMap(input map[string]string) (map[string]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	count := normalizer.boundedLength(len(keys), maxMapEntries)
	output := make(map[string]string, count)
	for _, key := range keys[:count] {
		sanitizedKey := normalizer.string(key)
		if sanitizedKey == "" {
			return nil, errors.New("map key is empty after sanitization")
		}
		if _, duplicate := output[sanitizedKey]; duplicate {
			return nil, fmt.Errorf("map keys collide after sanitization at %q", sanitizedKey)
		}
		output[sanitizedKey] = normalizer.string(input[key])
	}
	return output, nil
}

func (normalizer *normalizer) boundedLength(length int, maximum int) int {
	if normalizer.validateAll {
		return length
	}
	if length > maximum {
		normalizer.truncated = true
		return maximum
	}
	return length
}

func (normalizer *normalizer) string(value string) string {
	withoutControls := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
	if withoutControls != value {
		normalizer.truncated = true
	}
	sanitized := normalizer.redactor.Text(withoutControls)
	if len(sanitized) <= maxStringBytes {
		return sanitized
	}
	normalizer.truncated = true
	truncated := sanitized[:maxStringBytes]
	for !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

func parseOptionalTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func copyInt32(value *int32) *int32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0, false); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple top-level JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int, caseSensitiveKeys bool) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
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
		keys := make(map[string]string)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			folded := key
			if !caseSensitiveKeys {
				folded = caseFoldKey(key)
			}
			if existing, duplicate := keys[folded]; duplicate {
				return fmt.Errorf(
					"duplicate object keys %q and %q match case-insensitively",
					existing,
					key,
				)
			}
			keys[folded] = key
			if err := scanJSONValue(
				decoder,
				depth+1,
				caseSensitiveJSONMap(key),
			); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object has invalid closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1, caseSensitiveKeys); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array has invalid closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func caseSensitiveJSONMap(field string) bool {
	for _, mapField := range []string{
		"annotations",
		"capacity",
		"labels",
		"matchLabels",
		"nodeSelector",
		"requests",
		"selector",
	} {
		if strings.EqualFold(field, mapField) {
			return true
		}
	}
	return false
}

func caseFoldKey(value string) string {
	var folded strings.Builder
	folded.Grow(len(value))
	for _, character := range value {
		canonical := character
		for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		folded.WriteRune(canonical)
	}
	return folded.String()
}
