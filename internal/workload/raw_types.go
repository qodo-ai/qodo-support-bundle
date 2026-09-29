package workload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type rawMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Labels            rawIdentityLabels `json:"labels"`
}

type rawListMetadata struct {
	Continue string `json:"continue"`
}

type rawIdentityLabels map[string]string

const endpointSliceServiceNameLabel = "kubernetes.io/service-name"

func (labels *rawIdentityLabels) UnmarshalJSON(data []byte) error {
	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	selected := make(rawIdentityLabels)
	for key, value := range decoded {
		if identityLabelAllowed(key) || key == endpointSliceServiceNameLabel {
			selected[key] = value
		}
	}
	*labels = selected
	return nil
}

type rawPodTemplate struct {
	Spec *rawPodSpec `json:"spec"`
}

type rawPodSpec struct {
	ServiceAccountName        string                        `json:"serviceAccountName"`
	Containers                []rawContainer                `json:"containers"`
	NodeSelector              map[string]string             `json:"nodeSelector"`
	SchedulerName             string                        `json:"schedulerName"`
	PriorityClassName         string                        `json:"priorityClassName"`
	Tolerations               []rawToleration               `json:"tolerations"`
	Affinity                  *rawAffinity                  `json:"affinity"`
	TopologySpreadConstraints []rawTopologySpreadConstraint `json:"topologySpreadConstraints"`
}

type rawContainer struct {
	Name            string       `json:"name"`
	Image           string       `json:"image"`
	ImagePullPolicy string       `json:"imagePullPolicy"`
	Resources       rawResources `json:"resources"`
	LivenessProbe   *rawProbe    `json:"livenessProbe"`
	ReadinessProbe  *rawProbe    `json:"readinessProbe"`
	StartupProbe    *rawProbe    `json:"startupProbe"`
}

type rawResources struct {
	Requests rawResourceValues `json:"requests"`
	Limits   rawResourceValues `json:"limits"`
}

type rawResourceValues struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

type rawProbe struct {
	HTTPGet             *rawHTTPGetAction   `json:"httpGet"`
	TCPSocket           *rawTCPSocketAction `json:"tcpSocket"`
	GRPC                *rawGRPCAction      `json:"grpc"`
	Exec                *struct{}           `json:"exec"`
	InitialDelaySeconds int32               `json:"initialDelaySeconds"`
	PeriodSeconds       int32               `json:"periodSeconds"`
	TimeoutSeconds      int32               `json:"timeoutSeconds"`
	SuccessThreshold    int32               `json:"successThreshold"`
	FailureThreshold    int32               `json:"failureThreshold"`
}

type rawHTTPGetAction struct {
	Path   string  `json:"path"`
	Port   rawPort `json:"port"`
	Scheme string  `json:"scheme"`
}

type rawTCPSocketAction struct {
	Port rawPort `json:"port"`
}

type rawGRPCAction struct {
	Port int32 `json:"port"`
}

type rawPort struct {
	value string
	set   bool
}

func (port *rawPort) UnmarshalJSON(data []byte) error {
	if port == nil {
		return errors.New("nil probe port")
	}
	*port = rawPort{}
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return errors.New("probe port must be an integer or string")
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return fmt.Errorf("decode named probe port: %w", err)
		}
		if value == "" {
			return errors.New("named probe port must not be empty")
		}
		port.value = value
		port.set = true
		return nil
	}
	for _, character := range data {
		if character < '0' || character > '9' {
			return errors.New("numeric probe port must be a base-10 integer")
		}
	}
	number, err := strconv.ParseInt(string(data), 10, 32)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("numeric probe port must be between 1 and 65535")
	}
	port.value = strconv.FormatInt(number, 10)
	port.set = true
	return nil
}

type rawToleration struct {
	Key               string `json:"key"`
	Operator          string `json:"operator"`
	Value             string `json:"value"`
	Effect            string `json:"effect"`
	TolerationSeconds *int64 `json:"tolerationSeconds"`
}

type rawTopologySpreadConstraint struct {
	MaxSkew            int32             `json:"maxSkew"`
	TopologyKey        string            `json:"topologyKey"`
	WhenUnsatisfiable  string            `json:"whenUnsatisfiable"`
	MinDomains         *int32            `json:"minDomains"`
	NodeAffinityPolicy string            `json:"nodeAffinityPolicy"`
	NodeTaintsPolicy   string            `json:"nodeTaintsPolicy"`
	LabelSelector      *rawLabelSelector `json:"labelSelector"`
}

type rawAffinity struct {
	NodeAffinity    *rawNodeAffinity `json:"nodeAffinity"`
	PodAffinity     *rawPodAffinity  `json:"podAffinity"`
	PodAntiAffinity *rawPodAffinity  `json:"podAntiAffinity"`
}

type rawNodeAffinity struct {
	Required  *rawNodeSelector             `json:"requiredDuringSchedulingIgnoredDuringExecution"`
	Preferred []rawPreferredSchedulingTerm `json:"preferredDuringSchedulingIgnoredDuringExecution"`
}

type rawNodeSelector struct {
	NodeSelectorTerms []rawNodeSelectorTerm `json:"nodeSelectorTerms"`
}

type rawPreferredSchedulingTerm struct {
	Weight     int32               `json:"weight"`
	Preference rawNodeSelectorTerm `json:"preference"`
}

type rawNodeSelectorTerm struct {
	MatchExpressions []rawSelectorRequirement `json:"matchExpressions"`
	MatchFields      []rawSelectorRequirement `json:"matchFields"`
}

type rawPodAffinity struct {
	Required  []rawPodAffinityTerm         `json:"requiredDuringSchedulingIgnoredDuringExecution"`
	Preferred []rawWeightedPodAffinityTerm `json:"preferredDuringSchedulingIgnoredDuringExecution"`
}

type rawPodAffinityTerm struct {
	LabelSelector     *rawLabelSelector `json:"labelSelector"`
	Namespaces        []string          `json:"namespaces"`
	TopologyKey       string            `json:"topologyKey"`
	NamespaceSelector *rawLabelSelector `json:"namespaceSelector"`
}

type rawWeightedPodAffinityTerm struct {
	Weight          int32              `json:"weight"`
	PodAffinityTerm rawPodAffinityTerm `json:"podAffinityTerm"`
}

type rawLabelSelector struct {
	MatchLabels      map[string]string        `json:"matchLabels"`
	MatchExpressions []rawSelectorRequirement `json:"matchExpressions"`
}

type rawSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type rawCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

type rawDeploymentList struct {
	Kind     string          `json:"kind"`
	Metadata rawListMetadata `json:"metadata"`
	Items    []rawDeployment `json:"items"`
}

type rawDeployment struct {
	Kind     string              `json:"kind"`
	Metadata rawMetadata         `json:"metadata"`
	Spec     rawDeploymentSpec   `json:"spec"`
	Status   rawControllerStatus `json:"status"`
}

type rawDeploymentSpec struct {
	Replicas *int32          `json:"replicas"`
	Strategy rawStrategy     `json:"strategy"`
	Template *rawPodTemplate `json:"template"`
}

type rawStrategy struct {
	Type string `json:"type"`
}

type rawControllerStatus struct {
	Replicas          *int32         `json:"replicas"`
	ReadyReplicas     *int32         `json:"readyReplicas"`
	AvailableReplicas *int32         `json:"availableReplicas"`
	Conditions        []rawCondition `json:"conditions"`
}

type rawStatefulSetList struct {
	Kind     string           `json:"kind"`
	Metadata rawListMetadata  `json:"metadata"`
	Items    []rawStatefulSet `json:"items"`
}

type rawStatefulSet struct {
	Kind     string               `json:"kind"`
	Metadata rawMetadata          `json:"metadata"`
	Spec     rawStatefulSetSpec   `json:"spec"`
	Status   rawStatefulSetStatus `json:"status"`
}

type rawStatefulSetSpec struct {
	Replicas       *int32          `json:"replicas"`
	UpdateStrategy rawStrategy     `json:"updateStrategy"`
	Template       *rawPodTemplate `json:"template"`
}

type rawStatefulSetStatus struct {
	Replicas          *int32         `json:"replicas"`
	CurrentReplicas   *int32         `json:"currentReplicas"`
	ReadyReplicas     *int32         `json:"readyReplicas"`
	AvailableReplicas *int32         `json:"availableReplicas"`
	Conditions        []rawCondition `json:"conditions"`
}

type rawDaemonSetList struct {
	Kind     string          `json:"kind"`
	Metadata rawListMetadata `json:"metadata"`
	Items    []rawDaemonSet  `json:"items"`
}

type rawDaemonSet struct {
	Kind     string             `json:"kind"`
	Metadata rawMetadata        `json:"metadata"`
	Spec     rawDaemonSetSpec   `json:"spec"`
	Status   rawDaemonSetStatus `json:"status"`
}

type rawDaemonSetSpec struct {
	UpdateStrategy rawStrategy     `json:"updateStrategy"`
	Template       *rawPodTemplate `json:"template"`
}

type rawDaemonSetStatus struct {
	DesiredNumberScheduled *int32         `json:"desiredNumberScheduled"`
	CurrentNumberScheduled *int32         `json:"currentNumberScheduled"`
	NumberReady            *int32         `json:"numberReady"`
	NumberAvailable        *int32         `json:"numberAvailable"`
	Conditions             []rawCondition `json:"conditions"`
}

type rawJobList struct {
	Kind     string          `json:"kind"`
	Metadata rawListMetadata `json:"metadata"`
	Items    []rawJob        `json:"items"`
}

type rawJob struct {
	Kind     string       `json:"kind"`
	Metadata rawMetadata  `json:"metadata"`
	Spec     rawJobSpec   `json:"spec"`
	Status   rawJobStatus `json:"status"`
}

type rawJobSpec struct {
	Suspend  *bool           `json:"suspend"`
	Template *rawPodTemplate `json:"template"`
}

type rawJobStatus struct {
	Active     int32          `json:"active"`
	Succeeded  int32          `json:"succeeded"`
	Failed     int32          `json:"failed"`
	Conditions []rawCondition `json:"conditions"`
}

type rawCronJobList struct {
	Kind     string          `json:"kind"`
	Metadata rawListMetadata `json:"metadata"`
	Items    []rawCronJob    `json:"items"`
}

type rawCronJob struct {
	Kind     string           `json:"kind"`
	Metadata rawMetadata      `json:"metadata"`
	Spec     rawCronJobSpec   `json:"spec"`
	Status   rawCronJobStatus `json:"status"`
}

type rawCronJobSpec struct {
	Suspend     *bool               `json:"suspend"`
	JobTemplate *rawJobTemplateSpec `json:"jobTemplate"`
}

type rawJobTemplateSpec struct {
	Spec *rawJobSpec `json:"spec"`
}

type rawCronJobStatus struct {
	Active []struct{} `json:"active"`
}
