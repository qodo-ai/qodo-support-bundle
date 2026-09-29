// Package workload defines the narrow, normalized Kubernetes workload
// artifacts that may enter a support bundle.
package workload

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

// Resource identifies one Kubernetes object without retaining its raw metadata.
type Resource struct {
	Kind              string          `json:"kind"`
	Namespace         string          `json:"namespace"`
	Name              string          `json:"name"`
	CreationTimestamp *time.Time      `json:"creation_timestamp,omitempty"`
	Labels            *IdentityLabels `json:"labels,omitempty"`
}

func (resource Resource) resourceIdentity() Resource {
	return resource
}

// IdentityLabels contains only allowlisted, redacted workload identity labels.
// Its values are private so raw Kubernetes labels cannot be assigned directly.
type IdentityLabels struct {
	values map[string]string
}

// MarshalJSON emits the normalized label map.
func (labels IdentityLabels) MarshalJSON() ([]byte, error) {
	return json.Marshal(labels.values)
}

// Workload records approved controller, pod-template, and rollout fields.
type Workload struct {
	Resource
	ServiceAccountName string      `json:"service_account_name,omitempty"`
	Strategy           string      `json:"strategy,omitempty"`
	Replicas           Replicas    `json:"replicas"`
	JobStatus          *JobStatus  `json:"job_status,omitempty"`
	Containers         []Container `json:"containers,omitempty"`
	Scheduling         Scheduling  `json:"scheduling"`
	Conditions         []Condition `json:"conditions,omitempty"`
}

// Replicas records controller replica state.
type Replicas struct {
	Desired   *int32 `json:"desired,omitempty"`
	Current   *int32 `json:"current,omitempty"`
	Ready     *int32 `json:"ready,omitempty"`
	Available *int32 `json:"available,omitempty"`
}

// JobStatus records bounded Job or CronJob execution state.
type JobStatus struct {
	Active    int32 `json:"active"`
	Succeeded int32 `json:"succeeded"`
	Failed    int32 `json:"failed"`
	Suspended bool  `json:"suspended"`
}

// Container records identity, resource, and header-free health-check settings.
type Container struct {
	Name            string    `json:"name"`
	Image           string    `json:"image"`
	ImagePullPolicy string    `json:"image_pull_policy,omitempty"`
	Resources       Resources `json:"resources"`
	LivenessProbe   *Probe    `json:"liveness_probe,omitempty"`
	ReadinessProbe  *Probe    `json:"readiness_probe,omitempty"`
	StartupProbe    *Probe    `json:"startup_probe,omitempty"`
}

// Resources records only CPU and memory requests and limits.
type Resources struct {
	CPURequest    string `json:"cpu_request,omitempty"`
	MemoryRequest string `json:"memory_request,omitempty"`
	CPULimit      string `json:"cpu_limit,omitempty"`
	MemoryLimit   string `json:"memory_limit,omitempty"`
}

// Probe records the approved target and timing fields without headers.
type Probe struct {
	Type                string `json:"type"`
	Path                string `json:"path,omitempty"`
	Port                string `json:"port,omitempty"`
	Scheme              string `json:"scheme,omitempty"`
	InitialDelaySeconds int32  `json:"initial_delay_seconds,omitempty"`
	PeriodSeconds       int32  `json:"period_seconds,omitempty"`
	TimeoutSeconds      int32  `json:"timeout_seconds,omitempty"`
	SuccessThreshold    int32  `json:"success_threshold,omitempty"`
	FailureThreshold    int32  `json:"failure_threshold,omitempty"`
}

// Scheduling records bounded constraints useful for diagnosing placement.
type Scheduling struct {
	NodeSelector      map[string]string `json:"node_selector,omitempty"`
	SchedulerName     string            `json:"scheduler_name,omitempty"`
	PriorityClassName string            `json:"priority_class_name,omitempty"`
	Tolerations       []Toleration      `json:"tolerations,omitempty"`
	Affinity          *Affinity         `json:"affinity,omitempty"`
	TopologySpread    []TopologySpread  `json:"topology_spread,omitempty"`
}

// Toleration records scheduling behavior without retaining unrelated fields.
type Toleration struct {
	Key               string `json:"key,omitempty"`
	Operator          string `json:"operator,omitempty"`
	Value             string `json:"value,omitempty"`
	Effect            string `json:"effect,omitempty"`
	TolerationSeconds *int64 `json:"toleration_seconds,omitempty"`
}

// TopologySpread records one placement constraint.
type TopologySpread struct {
	MaxSkew            int32          `json:"max_skew"`
	TopologyKey        string         `json:"topology_key"`
	WhenUnsatisfiable  string         `json:"when_unsatisfiable"`
	MinDomains         *int32         `json:"min_domains,omitempty"`
	NodeAffinityPolicy string         `json:"node_affinity_policy,omitempty"`
	NodeTaintsPolicy   string         `json:"node_taints_policy,omitempty"`
	Selector           *LabelSelector `json:"selector,omitempty"`
}

// Affinity records bounded, normalized scheduling predicates.
type Affinity struct {
	RequiredNode     *NodeSelector          `json:"required_node,omitempty"`
	PreferredNode    []WeightedSelectorTerm `json:"preferred_node,omitempty"`
	RequiredPod      []PodAffinityTerm      `json:"required_pod,omitempty"`
	PreferredPod     []WeightedPodAffinity  `json:"preferred_pod,omitempty"`
	RequiredPodAnti  []PodAffinityTerm      `json:"required_pod_anti,omitempty"`
	PreferredPodAnti []WeightedPodAffinity  `json:"preferred_pod_anti,omitempty"`
}

// NodeSelector preserves the presence and terms of required node affinity.
type NodeSelector struct {
	Terms []SelectorTerm `json:"terms"`
}

// SelectorTerm records the predicates in one node selector term.
type SelectorTerm struct {
	MatchExpressions []SelectorRequirement `json:"match_expressions,omitempty"`
	MatchFields      []SelectorRequirement `json:"match_fields,omitempty"`
}

// LabelSelector preserves nil, empty, and populated Kubernetes selectors.
type LabelSelector struct {
	MatchLabels      map[string]string     `json:"match_labels,omitempty"`
	MatchExpressions []SelectorRequirement `json:"match_expressions,omitempty"`
}

// SelectorRequirement records one allowlisted selector predicate.
type SelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// WeightedSelectorTerm records one preferred node selector.
type WeightedSelectorTerm struct {
	Weight     int32        `json:"weight"`
	Preference SelectorTerm `json:"preference"`
}

// PodAffinityTerm records one pod affinity or anti-affinity predicate.
type PodAffinityTerm struct {
	TopologyKey       string         `json:"topology_key"`
	Namespaces        []string       `json:"namespaces,omitempty"`
	Selector          *LabelSelector `json:"selector,omitempty"`
	NamespaceSelector *LabelSelector `json:"namespace_selector,omitempty"`
}

// WeightedPodAffinity records one preferred pod affinity predicate.
type WeightedPodAffinity struct {
	Weight          int32           `json:"weight"`
	PodAffinityTerm PodAffinityTerm `json:"pod_affinity_term"`
}

// Condition records sanitized rollout or execution status.
type Condition struct {
	Type               string     `json:"type"`
	Status             string     `json:"status"`
	Reason             string     `json:"reason,omitempty"`
	Message            string     `json:"message,omitempty"`
	LastTransitionTime *time.Time `json:"last_transition_time,omitempty"`
}

// Service records approved routing metadata without cluster or endpoint IPs.
type Service struct {
	Resource
	Type      string            `json:"type"`
	Selectors map[string]string `json:"selectors,omitempty"`
	Ports     []ServicePort     `json:"ports,omitempty"`
}

// ServicePort records one service port mapping.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port,omitempty"`
}

// EndpointSlice summarizes endpoint state without retaining addresses.
type EndpointSlice struct {
	Resource
	ServiceName string `json:"service_name,omitempty"`
	AddressType string `json:"address_type,omitempty"`
	Ready       int    `json:"ready"`
	NotReady    int    `json:"not_ready"`
	Unknown     int    `json:"unknown"`
	Serving     int    `json:"serving"`
	Terminating int    `json:"terminating"`
}

// Autoscaler records replica state for one workload target.
type Autoscaler struct {
	Resource
	Target          TargetReference `json:"target"`
	CurrentReplicas int32           `json:"current_replicas"`
	DesiredReplicas int32           `json:"desired_replicas"`
	MinimumReplicas *int32          `json:"minimum_replicas,omitempty"`
	MaximumReplicas int32           `json:"maximum_replicas"`
}

// TargetReference identifies a related workload.
type TargetReference struct {
	APIVersion string `json:"api_version,omitempty"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

// Storage records approved PersistentVolumeClaim capacity and status fields.
type Storage struct {
	Resource
	Phase             string   `json:"phase,omitempty"`
	RequestedCapacity string   `json:"requested_capacity,omitempty"`
	Capacity          string   `json:"capacity,omitempty"`
	AccessModes       []string `json:"access_modes,omitempty"`
	StorageClassName  *string  `json:"storage_class_name,omitempty"`
	VolumeMode        string   `json:"volume_mode,omitempty"`
}

// NewIdentityLabels returns approved, redacted identity labels.
func NewIdentityLabels(
	labels map[string]string,
	redactor *redact.Redactor,
) (*IdentityLabels, error) {
	if !redactor.Ready() {
		return nil, errors.New("configured redactor is required")
	}
	selected := make(map[string]string)
	for key, value := range labels {
		if identityLabelAllowed(key) {
			selected[key] = redactor.Text(value)
		}
	}
	if len(selected) == 0 {
		return nil, nil
	}
	return &IdentityLabels{values: selected}, nil
}

func identityLabelAllowed(key string) bool {
	switch key {
	case "app",
		"component",
		"app.kubernetes.io/name",
		"app.kubernetes.io/instance",
		"app.kubernetes.io/component",
		"app.kubernetes.io/part-of",
		"app.kubernetes.io/version":
		return true
	default:
		return false
	}
}
