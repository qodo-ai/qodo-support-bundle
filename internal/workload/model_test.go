package workload

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func TestNormalizedModelsExcludeForbiddenFields(t *testing.T) {
	t.Parallel()
	replicas := int32(2)
	createdAt := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	storageClass := "standard"
	labels, err := NewIdentityLabels(
		map[string]string{"app.kubernetes.io/name": "platform"},
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	records := []any{
		Workload{
			Resource: Resource{
				Kind:              "Deployment",
				Namespace:         "qodo",
				Name:              "platform",
				CreationTimestamp: &createdAt,
				Labels:            labels,
			},
			ServiceAccountName: "platform",
			Replicas:           Replicas{Desired: &replicas},
			Containers: []Container{{
				Name:            "platform",
				Image:           "registry.example/platform:v1",
				ImagePullPolicy: "IfNotPresent",
				Resources: Resources{
					CPURequest:    "500m",
					MemoryRequest: "1Gi",
				},
				ReadinessProbe: &Probe{
					Type:   "http_get",
					Path:   "/health",
					Port:   "8080",
					Scheme: "HTTP",
				},
			}},
			Scheduling: Scheduling{
				NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
				Affinity: &Affinity{
					RequiredNode: &NodeSelector{
						Terms: []SelectorTerm{{
							MatchExpressions: []SelectorRequirement{{
								Key:      "node.kubernetes.io/instance-type",
								Operator: "In",
								Values:   []string{"standard"},
							}},
						}},
					},
				},
			},
			Conditions: []Condition{{
				Type:    "Available",
				Status:  "True",
				Reason:  "MinimumReplicasAvailable",
				Message: "deployment is available",
			}},
		},
		Service{
			Resource: Resource{Kind: "Service", Namespace: "qodo", Name: "platform"},
			Type:     "ClusterIP",
			Ports:    []ServicePort{{Name: "http", Port: 80, TargetPort: "8080"}},
		},
		EndpointSlice{
			Resource:    Resource{Kind: "EndpointSlice", Namespace: "qodo", Name: "platform-a"},
			ServiceName: "platform",
			Ready:       2,
		},
		Autoscaler{
			Resource: Resource{Kind: "HorizontalPodAutoscaler", Namespace: "qodo", Name: "platform"},
			Target: TargetReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "platform",
			},
			MinimumReplicas: &replicas,
			MaximumReplicas: 10,
		},
		Storage{
			Resource:          Resource{Kind: "PersistentVolumeClaim", Namespace: "qodo", Name: "data"},
			Phase:             "Bound",
			RequestedCapacity: "20Gi",
			Capacity:          "20Gi",
			AccessModes:       []string{"ReadWriteOnce"},
			StorageClassName:  &storageClass,
		},
	}

	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, forbidden := range []string{
		`"annotations"`,
		`"env"`,
		`"command"`,
		`"args"`,
		`"headers"`,
		`"addresses"`,
		`"cluster_ip"`,
		`"pod_ip"`,
		`"node_name"`,
		`"secret"`,
		`"config_map"`,
		`"raw_manifest"`,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("normalized output contains forbidden field %s: %s", forbidden, output)
		}
	}
	for _, approved := range []string{
		`"kind":"Deployment"`,
		`"cpu_request":"500m"`,
		`"readiness_probe"`,
		`"required_node"`,
		`"ready":2`,
		`"maximum_replicas":10`,
		`"requested_capacity":"20Gi"`,
		`"capacity":"20Gi"`,
	} {
		if !strings.Contains(output, approved) {
			t.Fatalf("normalized output omitted %s: %s", approved, output)
		}
	}
}

func TestNormalizedJSONFieldAllowlists(t *testing.T) {
	t.Parallel()
	expected := map[reflect.Type][]string{
		reflect.TypeOf(Resource{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
		},
		reflect.TypeOf(Workload{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
			"service_account_name", "strategy", "replicas", "job_status",
			"containers", "scheduling", "conditions",
		},
		reflect.TypeOf(Replicas{}): {
			"desired", "current", "ready", "available",
		},
		reflect.TypeOf(JobStatus{}): {
			"active", "succeeded", "failed", "suspended",
		},
		reflect.TypeOf(Container{}): {
			"name", "image", "image_pull_policy", "resources",
			"liveness_probe", "readiness_probe", "startup_probe",
		},
		reflect.TypeOf(Resources{}): {
			"cpu_request", "memory_request", "cpu_limit", "memory_limit",
		},
		reflect.TypeOf(Probe{}): {
			"type", "path", "port", "scheme", "initial_delay_seconds",
			"period_seconds", "timeout_seconds", "success_threshold",
			"failure_threshold",
		},
		reflect.TypeOf(Scheduling{}): {
			"node_selector", "scheduler_name", "priority_class_name",
			"tolerations", "affinity", "topology_spread",
		},
		reflect.TypeOf(Toleration{}): {
			"key", "operator", "value", "effect", "toleration_seconds",
		},
		reflect.TypeOf(TopologySpread{}): {
			"max_skew", "topology_key", "when_unsatisfiable", "min_domains",
			"node_affinity_policy", "node_taints_policy", "selector",
		},
		reflect.TypeOf(Affinity{}): {
			"required_node", "preferred_node", "required_pod", "preferred_pod",
			"required_pod_anti", "preferred_pod_anti",
		},
		reflect.TypeOf(NodeSelector{}): {
			"terms",
		},
		reflect.TypeOf(SelectorTerm{}): {
			"match_expressions", "match_fields",
		},
		reflect.TypeOf(LabelSelector{}): {
			"match_labels", "match_expressions",
		},
		reflect.TypeOf(SelectorRequirement{}): {
			"key", "operator", "values",
		},
		reflect.TypeOf(WeightedSelectorTerm{}): {
			"weight", "preference",
		},
		reflect.TypeOf(PodAffinityTerm{}): {
			"topology_key", "namespaces", "selector", "namespace_selector",
		},
		reflect.TypeOf(WeightedPodAffinity{}): {
			"weight", "pod_affinity_term",
		},
		reflect.TypeOf(Condition{}): {
			"type", "status", "reason", "message", "last_transition_time",
		},
		reflect.TypeOf(Service{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
			"type", "selectors", "ports",
		},
		reflect.TypeOf(ServicePort{}): {
			"name", "protocol", "port", "target_port",
		},
		reflect.TypeOf(EndpointSlice{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
			"service_name", "address_type", "ready", "not_ready", "unknown",
			"serving", "terminating",
		},
		reflect.TypeOf(Autoscaler{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
			"target", "current_replicas", "desired_replicas",
			"minimum_replicas", "maximum_replicas",
		},
		reflect.TypeOf(TargetReference{}): {
			"api_version", "kind", "name",
		},
		reflect.TypeOf(Storage{}): {
			"kind", "namespace", "name", "creation_timestamp", "labels",
			"phase", "requested_capacity", "capacity", "access_modes",
			"storage_class_name", "volume_mode",
		},
	}

	discovered := make(map[reflect.Type]bool)
	for _, root := range []reflect.Type{
		reflect.TypeOf(Workload{}),
		reflect.TypeOf(Service{}),
		reflect.TypeOf(EndpointSlice{}),
		reflect.TypeOf(Autoscaler{}),
		reflect.TypeOf(Storage{}),
	} {
		validateJSONContract(t, root, expected, discovered)
	}
	for model := range expected {
		if !discovered[model] {
			t.Fatalf("allowlisted model %s is unreachable from artifact roots", model)
		}
	}
}

func TestOptionalTimestampsAreOmitted(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Workload{Resource: Resource{Kind: "Deployment"}})
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if strings.Contains(output, "creation_timestamp") ||
		strings.Contains(output, "last_transition_time") ||
		strings.Contains(output, "0001-01-01") {
		t.Fatalf("missing timestamp was serialized: %s", output)
	}
}

func TestStorageClassPreservesAbsentAndExplicitEmpty(t *testing.T) {
	t.Parallel()
	empty := ""
	absent, err := json.Marshal(Storage{})
	if err != nil {
		t.Fatal(err)
	}
	explicitEmpty, err := json.Marshal(Storage{StorageClassName: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(absent), "storage_class_name") {
		t.Fatalf("absent storage class was serialized: %s", absent)
	}
	if !strings.Contains(string(explicitEmpty), `"storage_class_name":""`) {
		t.Fatalf("explicit empty storage class was lost: %s", explicitEmpty)
	}
}

func TestSelectorsPreserveAbsentAndExplicitEmpty(t *testing.T) {
	t.Parallel()
	absent, err := json.Marshal(Affinity{})
	if err != nil {
		t.Fatal(err)
	}
	explicitEmpty, err := json.Marshal(Affinity{
		RequiredNode: &NodeSelector{Terms: []SelectorTerm{}},
		RequiredPod: []PodAffinityTerm{{
			Selector:          &LabelSelector{},
			NamespaceSelector: &LabelSelector{},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(absent), "required_node") {
		t.Fatalf("absent selector was serialized: %s", absent)
	}
	for _, expected := range []string{
		`"required_node":{"terms":[]}`,
		`"selector":{}`,
		`"namespace_selector":{}`,
	} {
		if !strings.Contains(string(explicitEmpty), expected) {
			t.Fatalf("explicit empty selector was lost: %s", explicitEmpty)
		}
	}
}

func TestIdentityLabelsAllowlistAndRedaction(t *testing.T) {
	t.Parallel()
	const secret = "raw-secret"
	input := map[string]string{
		"app":                         "password=" + secret,
		"app.kubernetes.io/name":      "platform",
		"app.kubernetes.io/component": "api",
		"customer.internal/id":        "customer-123",
		"token":                       secret,
	}

	first, err := NewIdentityLabels(input, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewIdentityLabels(input, redact.New())
	if err != nil {
		t.Fatal(err)
	}

	if first.values["app.kubernetes.io/name"] != "platform" ||
		first.values["app.kubernetes.io/component"] != "api" {
		t.Fatalf("approved labels were not retained: %+v", first)
	}
	if strings.Contains(first.values["app"], secret) ||
		!strings.Contains(first.values["app"], redact.Replacement) {
		t.Fatalf("approved label value was not redacted: %+v", first)
	}
	if _, exists := first.values["customer.internal/id"]; exists {
		t.Fatalf("unapproved customer label was retained: %+v", first)
	}
	if _, exists := first.values["token"]; exists {
		t.Fatalf("unapproved sensitive label was retained: %+v", first)
	}

	first.values["app.kubernetes.io/name"] = "mutated"
	if second.values["app.kubernetes.io/name"] != "platform" {
		t.Fatalf("label result maps share mutable state: %+v", second)
	}
}

func TestIdentityLabelsOmitsEmptySetAndRequiresRedactor(t *testing.T) {
	t.Parallel()
	labels, err := NewIdentityLabels(nil, redact.New())
	if err != nil || labels != nil {
		t.Fatalf("unexpected empty label set: %#v", labels)
	}
	if _, err := NewIdentityLabels(nil, nil); err == nil {
		t.Fatal("expected missing redactor error")
	}
	if _, err := NewIdentityLabels(
		map[string]string{"app": "password=raw-secret"},
		&redact.Redactor{},
	); err == nil {
		t.Fatal("expected unconfigured redactor error")
	}
}

func exportedJSONFields(model reflect.Type) []string {
	fields := make([]string, 0, model.NumField())
	for index := 0; index < model.NumField(); index++ {
		field := model.Field(index)
		if field.Anonymous {
			fields = append(fields, exportedJSONFields(field.Type)...)
			continue
		}
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		fields = append(fields, name)
	}
	return fields
}

func validateJSONContract(
	t *testing.T,
	model reflect.Type,
	expected map[reflect.Type][]string,
	discovered map[reflect.Type]bool,
) {
	t.Helper()
	for model.Kind() == reflect.Pointer ||
		model.Kind() == reflect.Slice ||
		model.Kind() == reflect.Array ||
		model.Kind() == reflect.Map {
		model = model.Elem()
	}
	if model.Kind() != reflect.Struct ||
		model == reflect.TypeOf(time.Time{}) ||
		model == reflect.TypeOf(IdentityLabels{}) ||
		discovered[model] {
		return
	}
	allowed, exists := expected[model]
	if !exists {
		t.Fatalf("nested JSON model %s has no explicit field allowlist", model)
	}
	actual := exportedJSONFields(model)
	if !reflect.DeepEqual(actual, allowed) {
		t.Fatalf("%s JSON fields changed: got=%v want=%v", model, actual, allowed)
	}
	discovered[model] = true
	for index := 0; index < model.NumField(); index++ {
		validateJSONContract(t, model.Field(index).Type, expected, discovered)
	}
}
