package kubernetes

import (
	"context"
	"time"
)

// Sink receives sanitized files for the support bundle.
type Sink interface {
	Add(path string, data []byte) error
}

// CommandResult contains bounded command output.
type CommandResult struct {
	Stdout []byte
	Stderr []byte
	// Truncated reports that stdout exceeded the caller-provided limit.
	Truncated bool
	// StderrTruncated reports that stderr exceeded its fixed safety limit.
	StderrTruncated bool
}

// Runner executes kubectl without invoking a shell.
type Runner interface {
	Run(ctx context.Context, maxBytes int64, arguments ...string) (CommandResult, error)
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
	MaxMetadataBytes        int64
	MaxLogBytes             int64
	MaxTotalLogBytes        int64
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
	AllNamespaces             bool     `json:"all_namespaces"`
	ExcludedNamespaces        []string `json:"excluded_namespaces,omitempty"`
	Namespaces                []string `json:"namespaces"`
	CollectionNamespaces      []string `json:"-"`
	NamespacesRequested       int      `json:"namespaces_requested"`
	Pods                      int      `json:"pods"`
	Containers                int      `json:"containers"`
	InitContainers            int      `json:"init_containers"`
	EphemeralContainers       int      `json:"ephemeral_containers"`
	ContainerRestarts         int      `json:"container_restarts"`
	OOMKills                  int      `json:"oom_kills"`
	MetadataBytes             int64    `json:"metadata_bytes"`
	MetadataLimitBytes        int64    `json:"metadata_limit_bytes"`
	TruncatedMetadataFiles    int      `json:"truncated_metadata_files"`
	MetadataNamespacesSkipped int      `json:"metadata_namespaces_skipped"`
	LogFiles                  int      `json:"log_files"`
	LogStreamsCollected       int      `json:"log_streams_collected"`
	TruncatedLogFiles         int      `json:"truncated_log_files"`
	Issues                    []Issue  `json:"issues,omitempty"`
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
	maxBytes       int64
}

type collectedLog struct {
	path              string
	data              []byte
	retainedTruncated bool
	issue             *Issue
	err               error
	reserved          int64
}

type podList struct {
	Items []pod `json:"items"`
}

type pod struct {
	Metadata objectMetadata `json:"metadata"`
	Spec     struct {
		NodeName            string          `json:"nodeName"`
		Containers          []containerSpec `json:"containers"`
		InitContainers      []containerSpec `json:"initContainers"`
		EphemeralContainers []containerSpec `json:"ephemeralContainers"`
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
	Phase                      string            `json:"phase"`
	StartTime                  string            `json:"startTime"`
	Conditions                 []podCondition    `json:"conditions"`
	ContainerStatuses          []containerStatus `json:"containerStatuses"`
	InitContainerStatuses      []containerStatus `json:"initContainerStatuses"`
	EphemeralContainerStatuses []containerStatus `json:"ephemeralContainerStatuses"`
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
	SchemaVersion       string                  `json:"schema_version"`
	Timestamp           string                  `json:"@timestamp,omitempty"`
	Kind                string                  `json:"kind"`
	Namespace           string                  `json:"namespace"`
	Name                string                  `json:"name"`
	NodeName            string                  `json:"node_name,omitempty"`
	Labels              map[string]string       `json:"labels,omitempty"`
	Phase               string                  `json:"phase"`
	Conditions          []podCondition          `json:"conditions,omitempty"`
	Containers          []outputContainerStatus `json:"containers,omitempty"`
	InitContainers      []outputContainerStatus `json:"init_containers,omitempty"`
	EphemeralContainers []outputContainerStatus `json:"ephemeral_containers,omitempty"`
	Source              map[string]string       `json:"source"`
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

type outputContainerEvent struct {
	SchemaVersion string            `json:"schema_version"`
	Timestamp     string            `json:"@timestamp,omitempty"`
	Kind          string            `json:"kind"`
	Severity      string            `json:"severity"`
	Namespace     string            `json:"namespace"`
	Pod           string            `json:"pod"`
	Container     string            `json:"container"`
	RestartCount  int               `json:"restart_count"`
	Reason        string            `json:"reason,omitempty"`
	Message       string            `json:"message,omitempty"`
	Source        map[string]string `json:"source"`
}
