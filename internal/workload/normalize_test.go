package workload

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func TestNormalizeListJSONSupportsAllWorkloadKinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind          Kind
		input         string
		wantName      string
		wantStrategy  string
		wantTruncated bool
		assert        func(*testing.T, Workload)
	}{
		{
			kind:          DeploymentKind,
			input:         deploymentFixture,
			wantName:      "api",
			wantStrategy:  "RollingUpdate",
			wantTruncated: false,
			assert: func(t *testing.T, workload Workload) {
				t.Helper()
				assertInt32Pointer(t, workload.Replicas.Desired, 0)
				assertInt32Pointer(t, workload.Replicas.Current, 2)
				assertInt32Pointer(t, workload.Replicas.Ready, 1)
				assertInt32Pointer(t, workload.Replicas.Available, 1)
				if workload.JobStatus != nil {
					t.Fatal("deployment unexpectedly has job status")
				}
			},
		},
		{
			kind:         StatefulSetKind,
			input:        statefulSetFixture,
			wantName:     "database",
			wantStrategy: "OnDelete",
			assert: func(t *testing.T, workload Workload) {
				t.Helper()
				assertInt32Pointer(t, workload.Replicas.Desired, 3)
				assertInt32Pointer(t, workload.Replicas.Current, 1)
				assertInt32Pointer(t, workload.Replicas.Ready, 2)
				assertInt32Pointer(t, workload.Replicas.Available, 2)
			},
		},
		{
			kind:         DaemonSetKind,
			input:        daemonSetFixture,
			wantName:     "node-agent",
			wantStrategy: "RollingUpdate",
			assert: func(t *testing.T, workload Workload) {
				t.Helper()
				assertInt32Pointer(t, workload.Replicas.Desired, 4)
				assertInt32Pointer(t, workload.Replicas.Current, 4)
				assertInt32Pointer(t, workload.Replicas.Ready, 3)
				assertInt32Pointer(t, workload.Replicas.Available, 3)
			},
		},
		{
			kind:     JobKind,
			input:    jobFixture,
			wantName: "migration",
			assert: func(t *testing.T, workload Workload) {
				t.Helper()
				if workload.JobStatus == nil {
					t.Fatal("job status is missing")
				}
				if *workload.JobStatus != (JobStatus{
					Active: 1, Succeeded: 2, Failed: 3, Suspended: true,
				}) {
					t.Fatalf("unexpected job status: %+v", workload.JobStatus)
				}
				if workload.Replicas.Desired != nil {
					t.Fatal("job unexpectedly has desired replicas")
				}
			},
		},
		{
			kind:     CronJobKind,
			input:    cronJobFixture,
			wantName: "nightly",
			assert: func(t *testing.T, workload Workload) {
				t.Helper()
				if workload.JobStatus == nil {
					t.Fatal("cron job status is missing")
				}
				if *workload.JobStatus != (JobStatus{Active: 2, Suspended: true}) {
					t.Fatalf("unexpected cron job status: %+v", workload.JobStatus)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(string(test.kind), func(t *testing.T) {
			t.Parallel()
			result, err := NormalizeListJSON(test.kind, []byte(test.input), redact.New())
			if err != nil {
				t.Fatal(err)
			}
			if result.Truncated != test.wantTruncated {
				t.Fatalf("truncated=%v want=%v", result.Truncated, test.wantTruncated)
			}
			if len(result.Workloads) != 1 {
				t.Fatalf("workload count=%d", len(result.Workloads))
			}
			workload := result.Workloads[0]
			if workload.Kind != string(test.kind) ||
				workload.Namespace != "platform" ||
				workload.Name != test.wantName ||
				workload.Strategy != test.wantStrategy {
				t.Fatalf("unexpected identity or strategy: %+v", workload)
			}
			if workload.CreationTimestamp == nil ||
				!workload.CreationTimestamp.Equal(
					time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC),
				) {
				t.Fatalf("unexpected creation timestamp: %v", workload.CreationTimestamp)
			}
			if len(workload.Containers) == 0 ||
				workload.Containers[0].Resources.CPURequest != "100m" ||
				workload.Containers[0].Resources.MemoryLimit != "256Mi" {
				t.Fatalf("container resources were not normalized: %+v", workload.Containers)
			}
			test.assert(t, workload)
		})
	}
}

func TestNormalizeListJSONRequiresListItemsButAllowsEmptyArrays(t *testing.T) {
	t.Parallel()
	for _, kind := range []Kind{
		DeploymentKind,
		StatefulSetKind,
		DaemonSetKind,
		JobKind,
		CronJobKind,
	} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			listKind := string(kind) + "List"
			for _, input := range []string{
				fmt.Sprintf(`{"kind":%q}`, listKind),
				fmt.Sprintf(`{"kind":%q,"items":null}`, listKind),
			} {
				if _, err := NormalizeListJSON(kind, []byte(input), redact.New()); err == nil {
					t.Fatalf("missing/null items accepted: %s", input)
				}
			}
			result, err := NormalizeListJSON(
				kind,
				[]byte(fmt.Sprintf(`{"kind":%q,"items":[]}`, listKind)),
				redact.New(),
			)
			if err != nil || len(result.Workloads) != 0 || result.RecordsFound != 0 {
				t.Fatalf("valid empty list result=%+v err=%v", result, err)
			}
		})
	}
}

func TestNormalizeListJSONRejectsNegativeControllerAndJobCounts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		kind  Kind
		input string
	}{
		{
			name: "deployment replicas",
			kind: DeploymentKind,
			input: `{"kind":"DeploymentList","items":[{
				"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},
				"spec":{"replicas":-1,"template":{"spec":{"containers":[]}}}
			}]}`,
		},
		{
			name: "statefulset current replicas",
			kind: StatefulSetKind,
			input: `{"kind":"StatefulSetList","items":[{
				"kind":"StatefulSet","metadata":{"name":"db","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[]}}},
				"status":{"currentReplicas":-1}
			}]}`,
		},
		{
			name: "daemonset available replicas",
			kind: DaemonSetKind,
			input: `{"kind":"DaemonSetList","items":[{
				"kind":"DaemonSet","metadata":{"name":"agent","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[]}}},
				"status":{"numberAvailable":-1}
			}]}`,
		},
		{
			name: "job failed count",
			kind: JobKind,
			input: `{"kind":"JobList","items":[{
				"kind":"Job","metadata":{"name":"migration","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[]}}},
				"status":{"failed":-1}
			}]}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeListJSON(
				test.kind,
				[]byte(test.input),
				redact.New(),
			); err == nil || !strings.Contains(err.Error(), "nonnegative") {
				t.Fatalf("negative count error = %v", err)
			}
		})
	}
}

func TestNormalizeListJSONRejectsInvalidExplicitProbeTiming(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
	}{
		{"negative initial delay", `"initialDelaySeconds":-1`},
		{"zero period", `"periodSeconds":0`},
		{"negative period", `"periodSeconds":-1`},
		{"zero timeout", `"timeoutSeconds":0`},
		{"zero success threshold", `"successThreshold":0`},
		{"negative failure threshold", `"failureThreshold":-1`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := fmt.Sprintf(`{"kind":"DeploymentList","items":[{
				"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[{
					"name":"api","image":"api:latest",
					"livenessProbe":{"httpGet":{"port":8080},%s}
				}]}}}
			}]}`, test.field)
			if _, err := NormalizeListJSON(
				DeploymentKind,
				[]byte(input),
				redact.New(),
			); err == nil {
				t.Fatal("invalid explicit probe timing was accepted")
			}
		})
	}
}

func TestNormalizeListJSONRejectsInvalidSchedulingNumbers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		scheduling string
	}{
		{
			name: "zero topology max skew",
			scheduling: `"topologySpreadConstraints":[{
				"maxSkew":0,"topologyKey":"zone","whenUnsatisfiable":"DoNotSchedule"
			}]`,
		},
		{
			name: "zero topology min domains",
			scheduling: `"topologySpreadConstraints":[{
				"maxSkew":1,"minDomains":0,"topologyKey":"zone",
				"whenUnsatisfiable":"DoNotSchedule"
			}]`,
		},
		{
			name: "node affinity weight above maximum",
			scheduling: `"affinity":{"nodeAffinity":{
				"preferredDuringSchedulingIgnoredDuringExecution":[{
					"weight":101,"preference":{"matchExpressions":[]}
				}]
			}}`,
		},
		{
			name: "pod affinity weight below minimum",
			scheduling: `"affinity":{"podAffinity":{
				"preferredDuringSchedulingIgnoredDuringExecution":[{
					"weight":0,"podAffinityTerm":{"topologyKey":"zone"}
				}]
			}}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := fmt.Sprintf(`{"kind":"DeploymentList","items":[{
				"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[],%s}}}
			}]}`, test.scheduling)
			if _, err := NormalizeListJSON(
				DeploymentKind,
				[]byte(input),
				redact.New(),
			); err == nil {
				t.Fatal("invalid scheduling number was accepted")
			}
		})
	}
}

func TestNormalizeListJSONAllowlistsRedactsAndNormalizesNestedFields(t *testing.T) {
	t.Parallel()
	result, err := NormalizeListJSON(
		DeploymentKind,
		[]byte(deploymentFixture),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Truncated {
		t.Fatal("omitted free-form condition message should not affect retained-field truncation")
	}
	workload := result.Workloads[0]
	if workload.ServiceAccountName != "password="+redact.Replacement {
		t.Fatalf("service account was not redacted: %q", workload.ServiceAccountName)
	}
	labelJSON, err := json.Marshal(workload.Labels)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(labelJSON), "raw-label-secret") ||
		!strings.Contains(string(labelJSON), redact.Replacement) ||
		strings.Contains(string(labelJSON), "customer.internal") {
		t.Fatalf("labels were not allowlisted and redacted: %s", labelJSON)
	}

	if len(workload.Containers) != 4 {
		t.Fatalf("container count=%d", len(workload.Containers))
	}
	probes := []*Probe{
		workload.Containers[0].LivenessProbe,
		workload.Containers[1].ReadinessProbe,
		workload.Containers[2].StartupProbe,
		workload.Containers[3].LivenessProbe,
	}
	wantTypes := []string{"http_get", "tcp_socket", "exec", "grpc"}
	wantPorts := []string{"8080", "metrics", "", "9090"}
	for index := range probes {
		if probes[index] == nil ||
			probes[index].Type != wantTypes[index] ||
			probes[index].Port != wantPorts[index] {
			t.Fatalf("probe %d=%+v", index, probes[index])
		}
	}
	if probes[0].Path != "/health" || probes[0].Scheme != "HTTPS" ||
		probes[0].InitialDelaySeconds != 5 || probes[0].FailureThreshold != 3 {
		t.Fatalf("HTTP probe fields were lost: %+v", probes[0])
	}

	scheduling := workload.Scheduling
	if scheduling.NodeSelector["disk"] != "ssd" ||
		scheduling.SchedulerName != "custom-scheduler" ||
		scheduling.PriorityClassName != "critical" ||
		len(scheduling.Tolerations) != 1 ||
		len(scheduling.TopologySpread) != 1 {
		t.Fatalf("scheduling fields were not retained: %+v", scheduling)
	}
	if scheduling.Affinity == nil ||
		scheduling.Affinity.RequiredNode == nil ||
		len(scheduling.Affinity.RequiredNode.Terms) != 1 ||
		len(scheduling.Affinity.RequiredPod) != 1 ||
		scheduling.Affinity.RequiredPod[0].Selector == nil ||
		scheduling.Affinity.RequiredPod[0].NamespaceSelector == nil {
		t.Fatalf("affinity selector presence was lost: %+v", scheduling.Affinity)
	}
	if len(workload.Conditions) != 1 ||
		workload.Conditions[0].Reason != "MinimumReplicasAvailable" ||
		workload.Conditions[0].LastTransitionTime == nil {
		t.Fatalf("structured condition fields were not retained: %+v", workload.Conditions)
	}

	encoded, err := json.Marshal(workload)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{
		"raw-label-secret",
		"raw-service-account",
		"forbidden-annotation-secret",
		"forbidden-env-secret",
		"forbidden-command-secret",
		"forbidden-arg-secret",
		"forbidden-header-secret",
		"forbidden-host-secret",
		"forbidden-volume-secret",
		"forbidden-mount-secret",
		"forbidden-node-secret",
		"raw-condition-secret",
		`"annotations"`,
		`"env"`,
		`"command"`,
		`"args"`,
		`"httpHeaders"`,
		`"host"`,
		`"volumes"`,
		`"volumeMounts"`,
		`"nodeName"`,
		`"message"`,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("normalized output retained %q: %s", forbidden, output)
		}
	}
}

func TestNormalizeListJSONCleansControlsBeforeRedaction(t *testing.T) {
	t.Parallel()
	input := `{
		"kind":"DeploymentList",
		"items":[{
			"kind":"Deployment",
			"metadata":{"name":"api","namespace":"platform"},
			"spec":{"template":{"spec":{
				"serviceAccountName":"pass\u0000word=raw-control-secret",
				"containers":[{"name":"api","image":"api:latest"}]
			}}}
		}]
	}`
	result, err := NormalizeListJSON(DeploymentKind, []byte(input), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated {
		t.Fatal("control removal did not report truncation")
	}
	actual := result.Workloads[0].ServiceAccountName
	if actual != "password="+redact.Replacement ||
		strings.Contains(actual, "raw-control-secret") {
		t.Fatalf("control-obscured secret was not redacted: %q", actual)
	}
}

func TestStatefulSetReplicaSemanticsUseAppsV1StatusFields(t *testing.T) {
	t.Parallel()
	result, err := NormalizeListJSON(
		StatefulSetKind,
		[]byte(statefulSetFixture),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	workload := result.Workloads[0]
	assertInt32Pointer(t, workload.Replicas.Desired, 3)
	assertInt32Pointer(t, workload.Replicas.Current, 1)
	assertInt32Pointer(t, workload.Replicas.Ready, 2)
	assertInt32Pointer(t, workload.Replicas.Available, 2)
}

func TestNormalizeListJSONBoundsAreDeterministic(t *testing.T) {
	t.Parallel()
	nodeSelector := make(map[string]string)
	for index := maxMapEntries + 2; index >= 0; index-- {
		nodeSelector[fmt.Sprintf("key-%02d", index)] = fmt.Sprintf("value-%02d", index)
	}
	containers := make([]map[string]any, maxContainers+2)
	for index := range containers {
		containers[index] = map[string]any{
			"name":  fmt.Sprintf("container-%02d", index),
			"image": "example/image",
		}
	}
	items := make([]map[string]any, maxWorkloads+1)
	for index := range items {
		items[index] = map[string]any{
			"kind": "Deployment",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("workload-%03d", index),
				"namespace": "platform",
			},
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers":   containers,
						"nodeSelector": nodeSelector,
					},
				},
			},
		}
	}
	items[0]["metadata"].(map[string]any)["name"] =
		"prefix-\u0000" + strings.Repeat("x", maxStringBytes+50)
	input, err := json.Marshal(map[string]any{
		"kind":  "DeploymentList",
		"items": items,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := NormalizeListJSON(DeploymentKind, input, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeListJSON(DeploymentKind, input, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Truncated || !second.Truncated {
		t.Fatal("bounded input did not report truncation")
	}
	if first.RecordsFound != maxWorkloads+1 || second.RecordsFound != maxWorkloads+1 {
		t.Fatalf("records found were not preserved: first=%d second=%d",
			first.RecordsFound,
			second.RecordsFound,
		)
	}
	if len(first.Workloads) != maxWorkloads ||
		len(first.Workloads[0].Containers) != maxContainers ||
		len(first.Workloads[0].Scheduling.NodeSelector) != maxMapEntries {
		t.Fatalf("hard bounds were not applied: workloads=%d containers=%d selector=%d",
			len(first.Workloads),
			len(first.Workloads[0].Containers),
			len(first.Workloads[0].Scheduling.NodeSelector),
		)
	}
	if len(first.Workloads[0].Name) != maxStringBytes ||
		strings.ContainsRune(first.Workloads[0].Name, '\x00') {
		t.Fatalf("string was not stripped and bounded: %q", first.Workloads[0].Name)
	}
	if _, exists := first.Workloads[0].Scheduling.NodeSelector["key-31"]; !exists {
		t.Fatal("sorted in-bound map key was not retained")
	}
	if _, exists := first.Workloads[0].Scheduling.NodeSelector["key-32"]; exists {
		t.Fatal("out-of-bound map key was retained")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("normalization was not deterministic")
	}
}

func TestNormalizeListJSONValidatesElementsBeyondOutputLimits(t *testing.T) {
	t.Parallel()
	validItem := func(name string) map[string]any {
		return map[string]any{
			"kind": "Deployment",
			"metadata": map[string]any{
				"name":      name,
				"namespace": "platform",
			},
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{"containers": []any{
						map[string]any{"name": "api", "image": "api:latest"},
					}},
				},
			},
		}
	}
	normalize := func(t *testing.T, items []map[string]any) error {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"kind":  "DeploymentList",
			"items": items,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = NormalizeListJSON(DeploymentKind, data, redact.New())
		return err
	}

	t.Run("workload after limit has wrong kind", func(t *testing.T) {
		items := make([]map[string]any, maxWorkloads+1)
		for index := range items {
			items[index] = validItem(fmt.Sprintf("workload-%03d", index))
		}
		items[maxWorkloads]["kind"] = "Job"
		if err := normalize(t, items); err == nil {
			t.Fatal("truncated workload bypassed kind validation")
		}
	})

	t.Run("container after limit has ambiguous probe", func(t *testing.T) {
		item := validItem("api")
		containers := make([]any, maxContainers+1)
		for index := range containers {
			containers[index] = map[string]any{
				"name":  fmt.Sprintf("container-%02d", index),
				"image": "example/image",
			}
		}
		containers[maxContainers].(map[string]any)["livenessProbe"] = map[string]any{
			"httpGet": map[string]any{"port": 8080},
			"exec":    map[string]any{},
		}
		podSpec := item["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		podSpec["containers"] = containers
		if err := normalize(t, []map[string]any{item}); err == nil {
			t.Fatal("truncated container bypassed probe validation")
		}
	})

	t.Run("map entries after limit collide when sanitized", func(t *testing.T) {
		item := validItem("api")
		nodeSelector := make(map[string]any)
		for index := 0; index < maxMapEntries; index++ {
			nodeSelector[fmt.Sprintf("a-%02d", index)] = "safe"
		}
		nodeSelector["zcollision"] = "first"
		nodeSelector["zcoll\u0000ision"] = "second"
		podSpec := item["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		podSpec["nodeSelector"] = nodeSelector
		if err := normalize(t, []map[string]any{item}); err == nil {
			t.Fatal("truncated map entries bypassed sanitized-key collision validation")
		}
	})

	t.Run("topology spread after limit has invalid max skew", func(t *testing.T) {
		item := validItem("api")
		constraints := make([]any, maxTopologySpread+1)
		for index := range constraints {
			constraints[index] = map[string]any{
				"maxSkew":           1,
				"topologyKey":       "zone",
				"whenUnsatisfiable": "DoNotSchedule",
			}
		}
		constraints[maxTopologySpread].(map[string]any)["maxSkew"] = 0
		podSpec := item["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		podSpec["topologySpreadConstraints"] = constraints
		if err := normalize(t, []map[string]any{item}); err == nil {
			t.Fatal("truncated topology spread bypassed numeric validation")
		}
	})

	t.Run("condition after limit has invalid timestamp", func(t *testing.T) {
		item := validItem("api")
		conditions := make([]any, maxConditions+1)
		for index := range conditions {
			conditions[index] = map[string]any{
				"type":               "Available",
				"status":             "True",
				"lastTransitionTime": "2026-09-29T08:05:00Z",
			}
		}
		conditions[maxConditions].(map[string]any)["lastTransitionTime"] = "not-time"
		item["status"] = map[string]any{"conditions": conditions}
		if err := normalize(t, []map[string]any{item}); err == nil {
			t.Fatal("truncated condition bypassed timestamp validation")
		}
	})
}

func TestNormalizeListJSONPreservesPointerPresence(t *testing.T) {
	t.Parallel()
	input := `{
		"kind":"DeploymentList",
		"items":[
			{
				"kind":"Deployment",
				"metadata":{"name":"absent","namespace":"platform"},
				"spec":{"template":{"spec":{"containers":[{"name":"api","image":"api:latest"}]}}},
				"status":{}
			},
			{
				"kind":"Deployment",
				"metadata":{"name":"present","namespace":"platform"},
				"spec":{
					"replicas":0,
					"template":{"spec":{
						"containers":[{"name":"api","image":"api:latest"}],
						"affinity":{
							"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[]}},
							"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{
								"topologyKey":"zone",
								"labelSelector":{},
								"namespaceSelector":{}
							}]}
						}
					}}
				},
				"status":{"replicas":0,"readyReplicas":0,"availableReplicas":0}
			}
		]
	}`
	result, err := NormalizeListJSON(DeploymentKind, []byte(input), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	absent := result.Workloads[0]
	present := result.Workloads[1]
	if absent.Replicas.Desired != nil || absent.Replicas.Current != nil {
		t.Fatalf("absent replica fields became present: %+v", absent.Replicas)
	}
	assertInt32Pointer(t, present.Replicas.Desired, 0)
	assertInt32Pointer(t, present.Replicas.Current, 0)
	if present.Scheduling.Affinity == nil ||
		present.Scheduling.Affinity.RequiredNode == nil ||
		present.Scheduling.Affinity.RequiredNode.Terms == nil ||
		present.Scheduling.Affinity.RequiredPod[0].Selector == nil ||
		present.Scheduling.Affinity.RequiredPod[0].NamespaceSelector == nil {
		t.Fatalf("explicit empty selectors were not preserved: %+v", present.Scheduling.Affinity)
	}
}

func TestNormalizeListJSONRejectsMalformedAndAmbiguousInput(t *testing.T) {
	t.Parallel()
	validPrefix := `{"kind":"DeploymentList","items":[{"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},`
	tests := []struct {
		name  string
		kind  Kind
		input string
	}{
		{name: "unsupported kind", kind: Kind("Pod"), input: `{}`},
		{name: "malformed top level", kind: DeploymentKind, input: `[`},
		{name: "top level array", kind: DeploymentKind, input: `[]`},
		{name: "wrong list kind", kind: DeploymentKind, input: `{"kind":"StatefulSetList","items":[]}`},
		{name: "wrong item kind", kind: DeploymentKind, input: `{"kind":"DeploymentList","items":[{"kind":"Job"}]}`},
		{name: "trailing JSON", kind: DeploymentKind, input: `{"kind":"DeploymentList","items":[]} {}`},
		{name: "duplicate key", kind: DeploymentKind, input: `{"kind":"DeploymentList","kind":"DeploymentList","items":[]}`},
		{name: "case-folded duplicate key", kind: DeploymentKind, input: `{"kind":"DeploymentList","Kind":"JobList","items":[]}`},
		{name: "nested case-folded duplicate key", kind: DeploymentKind, input: `{"kind":"DeploymentList","items":[{"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"api","livenessProbe":{"httpGet":{"port":80,"Port":"metrics"}}}]}}}}]}`},
		{
			name:  "missing metadata identity",
			kind:  DeploymentKind,
			input: `{"kind":"DeploymentList","items":[{"kind":"Deployment","metadata":{"name":"api"}}]}`,
		},
		{
			name:  "missing pod template",
			kind:  DeploymentKind,
			input: `{"kind":"DeploymentList","items":[{"kind":"Deployment","metadata":{"name":"api","namespace":"platform"},"spec":{}}]}`,
		},
		{
			name:  "missing pod template spec",
			kind:  StatefulSetKind,
			input: `{"kind":"StatefulSetList","items":[{"kind":"StatefulSet","metadata":{"name":"api","namespace":"platform"},"spec":{"template":{}}}]}`,
		},
		{
			name:  "empty containers",
			kind:  DaemonSetKind,
			input: `{"kind":"DaemonSetList","items":[{"kind":"DaemonSet","metadata":{"name":"api","namespace":"platform"},"spec":{"template":{"spec":{"containers":[]}}}}]}`,
		},
		{
			name:  "missing cron job template",
			kind:  CronJobKind,
			input: `{"kind":"CronJobList","items":[{"kind":"CronJob","metadata":{"name":"api","namespace":"platform"},"spec":{}}]}`,
		},
		{
			name:  "missing cron job template spec",
			kind:  CronJobKind,
			input: `{"kind":"CronJobList","items":[{"kind":"CronJob","metadata":{"name":"api","namespace":"platform"},"spec":{"jobTemplate":{}}}]}`,
		},
		{
			name: "invalid creation timestamp",
			kind: DeploymentKind,
			input: `{"kind":"DeploymentList","items":[{"kind":"Deployment",` +
				`"metadata":{"name":"api","namespace":"platform","creationTimestamp":"not-time"}}]}`,
		},
		{
			name: "invalid condition timestamp",
			kind: DeploymentKind,
			input: validPrefix +
				`"status":{"conditions":[{"lastTransitionTime":"not-time"}]}}]}`,
		},
		{
			name: "ambiguous probe handlers",
			kind: DeploymentKind,
			input: validPrefix +
				`"spec":{"template":{"spec":{"containers":[{"name":"api","image":"api","livenessProbe":{"httpGet":{"port":80},"exec":{}}}]}}}}]}`,
		},
		{
			name: "missing probe handler",
			kind: DeploymentKind,
			input: validPrefix +
				`"spec":{"template":{"spec":{"containers":[{"name":"api","image":"api","livenessProbe":{}}]}}}}]}`,
		},
	}
	for _, port := range []string{`null`, `0`, `65536`, `1.5`, `true`, `{}`, `""`} {
		tests = append(tests, struct {
			name  string
			kind  Kind
			input string
		}{
			name: "invalid port " + port,
			kind: DeploymentKind,
			input: validPrefix +
				`"spec":{"template":{"spec":{"containers":[{"name":"api","image":"api","livenessProbe":{"httpGet":{"port":` + port + `}}}]}}}}]}`,
		})
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeListJSON(test.kind, []byte(test.input), redact.New()); err == nil {
				t.Fatal("expected normalization error")
			}
		})
	}
	for name, redactor := range map[string]*redact.Redactor{
		"nil":        nil,
		"zero value": {},
	} {
		t.Run(name+" redactor", func(t *testing.T) {
			_, err := NormalizeListJSON(
				DeploymentKind,
				[]byte(`{"kind":"DeploymentList","items":[]}`),
				redactor,
			)
			if err == nil || !strings.Contains(err.Error(), "configured redactor is required") {
				t.Fatalf("expected redactor configuration error, got %v", err)
			}
		})
	}
	t.Run("invalid UTF-8", func(t *testing.T) {
		input := append(
			[]byte(`{"kind":"DeploymentList","items":[],"unknown":"`),
			0xff,
		)
		input = append(input, []byte(`"}`)...)
		if _, err := NormalizeListJSON(DeploymentKind, input, redact.New()); err == nil {
			t.Fatal("expected invalid UTF-8 error")
		}
	})
}

func TestRejectDuplicateJSONKeysUsesUnicodeCaseFolding(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"kind":1,"Kind":2}`,
		`{"K":1,"\u212a":2}`,
		`{"\u03a3":1,"\u03c2":2}`,
	} {
		err := rejectDuplicateJSONKeys([]byte(input))
		if err == nil || !strings.Contains(err.Error(), "match case-insensitively") {
			t.Fatalf("input %s: expected case-folded duplicate error, got %v", input, err)
		}
	}
}

func TestNormalizeListJSONReportsDuplicateKeyReason(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"exact":       `{"kind":"DeploymentList","kind":"DeploymentList","items":[]}`,
		"case folded": `{"kind":"DeploymentList","Kind":"JobList","items":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeListJSON(DeploymentKind, []byte(input), redact.New())
			if err == nil || !strings.Contains(err.Error(), "duplicate object keys") {
				t.Fatalf("expected duplicate-key validation error, got %v", err)
			}
		})
	}
}

func TestNormalizeListJSONAllowsCaseDistinctKubernetesMapKeys(t *testing.T) {
	t.Parallel()
	input := `{
		"kind":"DeploymentList",
		"items":[{
			"kind":"Deployment",
			"metadata":{
				"name":"api",
				"namespace":"platform",
				"Labels":{"Team":"one","team":"two"}
			},
			"spec":{"template":{"spec":{
				"containers":[{"name":"api","image":"api:latest"}],
				"NodeSelector":{"Disk":"ssd","disk":"nvme"},
				"affinity":{"podAffinity":{
					"requiredDuringSchedulingIgnoredDuringExecution":[{
						"topologyKey":"zone",
						"labelSelector":{"MatchLabels":{"App":"one","app":"two"}}
					}]
				}}
			}}}
		}]
	}`
	result, err := NormalizeListJSON(DeploymentKind, []byte(input), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Workloads[0].Scheduling.NodeSelector) != 2 {
		t.Fatalf(
			"case-distinct node selector keys were not preserved: %+v",
			result.Workloads[0].Scheduling.NodeSelector,
		)
	}
	affinity := result.Workloads[0].Scheduling.Affinity
	if affinity == nil ||
		len(affinity.RequiredPod) != 1 ||
		affinity.RequiredPod[0].Selector == nil ||
		len(affinity.RequiredPod[0].Selector.MatchLabels) != 2 {
		t.Fatalf("case-distinct match label keys were not preserved: %+v", affinity)
	}
}

func TestNormalizeListJSONRejectsMalformedContainers(t *testing.T) {
	t.Parallel()
	for _, containers := range []string{`[null]`, `[{}]`, `[{"name":"api"}]`, `[{"image":"api:latest"}]`} {
		input := `{"kind":"DeploymentList","items":[{` +
			`"kind":"Deployment",` +
			`"metadata":{"name":"api","namespace":"platform"},` +
			`"spec":{"template":{"spec":{"containers":` + containers + `}}}` +
			`}]}`
		if _, err := NormalizeListJSON(
			DeploymentKind,
			[]byte(input),
			redact.New(),
		); err == nil {
			t.Fatalf("containers %s: expected validation error", containers)
		}
	}
}

func TestRawWorkloadTypesContainNoForbiddenJSONFields(t *testing.T) {
	t.Parallel()
	forbidden := map[string]bool{
		"annotations":    true,
		"env":            true,
		"envFrom":        true,
		"command":        true,
		"args":           true,
		"httpHeaders":    true,
		"host":           true,
		"volumes":        true,
		"volumeMounts":   true,
		"nodeName":       true,
		"podIP":          true,
		"podIPs":         true,
		"addresses":      true,
		"clusterIP":      true,
		"clusterIPs":     true,
		"externalIPs":    true,
		"loadBalancerIP": true,
		"data":           true,
		"stringData":     true,
		"rawManifest":    true,
		"volumeName":     true,
		"dataSource":     true,
		"dataSourceRef":  true,
		"hostname":       true,
		"targetRef":      true,
		"metrics":        true,
		"behavior":       true,
		"currentMetrics": true,
	}
	visited := make(map[reflect.Type]bool)
	for _, root := range []any{
		rawDeploymentList{},
		rawStatefulSetList{},
		rawDaemonSetList{},
		rawJobList{},
		rawCronJobList{},
		rawServiceList{},
		rawEndpointSliceList{},
		rawHorizontalPodAutoscalerList{},
		rawPersistentVolumeClaimList{},
	} {
		assertRawFieldsAllowed(t, reflect.TypeOf(root), forbidden, visited)
	}
}

func assertRawFieldsAllowed(
	t *testing.T,
	model reflect.Type,
	forbidden map[string]bool,
	visited map[reflect.Type]bool,
) {
	t.Helper()
	for model.Kind() == reflect.Pointer ||
		model.Kind() == reflect.Slice ||
		model.Kind() == reflect.Array ||
		model.Kind() == reflect.Map {
		model = model.Elem()
	}
	if model.Kind() != reflect.Struct || visited[model] {
		return
	}
	visited[model] = true
	for index := 0; index < model.NumField(); index++ {
		field := model.Field(index)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if forbidden[name] {
			t.Fatalf("raw type %s contains forbidden JSON field %q", model, name)
		}
		assertRawFieldsAllowed(t, field.Type, forbidden, visited)
	}
}

func assertInt32Pointer(t *testing.T, actual *int32, expected int32) {
	t.Helper()
	if actual == nil || *actual != expected {
		t.Fatalf("pointer=%v, want %d", actual, expected)
	}
}

const deploymentFixture = `{
	"apiVersion":"apps/v1",
	"kind":"DeploymentList",
	"items":[{
		"apiVersion":"apps/v1",
		"kind":"Deployment",
		"metadata":{
			"name":"api",
			"namespace":"platform",
			"creationTimestamp":"2026-09-29T08:00:00Z",
			"labels":{
				"app":"password=raw-label-secret",
				"app.kubernetes.io/component":"api",
				"customer.internal/id":"forbidden-label-secret"
			},
			"annotations":{"token":"forbidden-annotation-secret"}
		},
		"spec":{
			"replicas":0,
			"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":"25%"}},
			"template":{
				"metadata":{"annotations":{"secret":"forbidden-template-secret"}},
				"spec":{
					"serviceAccountName":"password=raw-service-account",
					"nodeName":"forbidden-node-secret",
					"schedulerName":"custom-scheduler",
					"priorityClassName":"critical",
					"nodeSelector":{"disk":"ssd"},
					"tolerations":[{"key":"dedicated","operator":"Equal","value":"api","effect":"NoSchedule","tolerationSeconds":60}],
					"containers":[
						{
							"name":"api",
							"image":"registry.example/api:v1",
							"imagePullPolicy":"IfNotPresent",
							"resources":{"requests":{"cpu":"100m","memory":"128Mi","ephemeral-storage":"1Gi"},"limits":{"cpu":"500m","memory":"256Mi","nvidia.com/gpu":"1"}},
							"env":[{"name":"PASSWORD","value":"forbidden-env-secret"}],
							"command":["forbidden-command-secret"],
							"args":["forbidden-arg-secret"],
							"volumeMounts":[{"name":"secret","mountPath":"/forbidden-mount-secret"}],
							"livenessProbe":{
								"httpGet":{
									"path":"/health",
									"port":8080,
									"scheme":"HTTPS",
									"host":"forbidden-host-secret",
									"httpHeaders":[{"name":"Authorization","value":"forbidden-header-secret"}]
								},
								"initialDelaySeconds":5,
								"periodSeconds":10,
								"timeoutSeconds":2,
								"successThreshold":1,
								"failureThreshold":3
							}
						},
						{"name":"sidecar","image":"registry.example/sidecar:v1","readinessProbe":{"tcpSocket":{"port":"metrics"}}},
						{"name":"worker","image":"registry.example/worker:v1","startupProbe":{"exec":{"command":["forbidden-exec-secret"]},"periodSeconds":2}},
						{"name":"grpc","image":"registry.example/grpc:v1","livenessProbe":{"grpc":{"port":9090,"service":"forbidden-service-secret"}}}
					],
					"volumes":[{"name":"secret","secret":{"secretName":"forbidden-volume-secret"}}],
					"affinity":{
						"nodeAffinity":{
							"requiredDuringSchedulingIgnoredDuringExecution":{
								"nodeSelectorTerms":[{"matchExpressions":[{"key":"topology.kubernetes.io/zone","operator":"In","values":["a","b"]}],"matchFields":[{"key":"metadata.name","operator":"NotIn","values":["node-a"]}]}]
							},
							"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":50,"preference":{"matchExpressions":[{"key":"disk","operator":"In","values":["ssd"]}]}}]
						},
						"podAffinity":{
							"requiredDuringSchedulingIgnoredDuringExecution":[{
								"topologyKey":"kubernetes.io/hostname",
								"namespaces":["platform"],
								"labelSelector":{"matchLabels":{"app":"api"},"matchExpressions":[{"key":"tier","operator":"In","values":["backend"]}]},
								"namespaceSelector":{}
							}]
						},
						"podAntiAffinity":{
							"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":100,"podAffinityTerm":{"topologyKey":"topology.kubernetes.io/zone","labelSelector":{"matchLabels":{"app":"api"}}}}]
						}
					},
					"topologySpreadConstraints":[{
						"maxSkew":1,
						"topologyKey":"topology.kubernetes.io/zone",
						"whenUnsatisfiable":"DoNotSchedule",
						"minDomains":2,
						"nodeAffinityPolicy":"Honor",
						"nodeTaintsPolicy":"Ignore",
						"labelSelector":{"matchLabels":{"app":"api"}}
					}]
				}
			}
		},
		"status":{
			"replicas":2,
			"readyReplicas":1,
			"availableReplicas":1,
			"conditions":[{
				"type":"Available",
				"status":"True",
				"reason":"MinimumReplicasAvailable",
				"message":"password=raw-condition-secret\u000aline",
				"lastTransitionTime":"2026-09-29T08:05:00Z"
			}]
		}
	}]
}`

const statefulSetFixture = `{
	"kind":"StatefulSetList",
	"items":[{
		"kind":"StatefulSet",
		"metadata":{"name":"database","namespace":"platform","creationTimestamp":"2026-09-29T08:00:00Z"},
		"spec":{
			"replicas":3,
			"updateStrategy":{"type":"OnDelete"},
			"template":{"spec":{"containers":[{"name":"database","image":"postgres:17","resources":{"requests":{"cpu":"100m"},"limits":{"memory":"256Mi"}}}]}}
		},
		"status":{"replicas":3,"currentReplicas":1,"readyReplicas":2,"availableReplicas":2}
	}]
}`

const daemonSetFixture = `{
	"kind":"DaemonSetList",
	"items":[{
		"kind":"DaemonSet",
		"metadata":{"name":"node-agent","namespace":"platform","creationTimestamp":"2026-09-29T08:00:00Z"},
		"spec":{
			"updateStrategy":{"type":"RollingUpdate"},
			"template":{"spec":{"containers":[{"name":"agent","image":"agent:v1","resources":{"requests":{"cpu":"100m"},"limits":{"memory":"256Mi"}}}]}}
		},
		"status":{"desiredNumberScheduled":4,"currentNumberScheduled":4,"numberReady":3,"numberAvailable":3}
	}]
}`

const jobFixture = `{
	"kind":"JobList",
	"items":[{
		"kind":"Job",
		"metadata":{"name":"migration","namespace":"platform","creationTimestamp":"2026-09-29T08:00:00Z"},
		"spec":{"suspend":true,"template":{"spec":{"containers":[{"name":"migration","image":"migration:v1","resources":{"requests":{"cpu":"100m"},"limits":{"memory":"256Mi"}}}]}}},
		"status":{"active":1,"succeeded":2,"failed":3,"conditions":[{"type":"Complete","status":"False","lastTransitionTime":"2026-09-29T08:05:00Z"}]}
	}]
}`

const cronJobFixture = `{
	"kind":"CronJobList",
	"items":[{
		"kind":"CronJob",
		"metadata":{"name":"nightly","namespace":"platform","creationTimestamp":"2026-09-29T08:00:00Z"},
		"spec":{"suspend":true,"schedule":"0 0 * * *","jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"nightly","image":"nightly:v1","resources":{"requests":{"cpu":"100m"},"limits":{"memory":"256Mi"}}}]}}}}},
		"status":{"active":[{"name":"nightly-a","namespace":"platform"},{"name":"nightly-b","namespace":"platform"}],"lastScheduleTime":"2026-09-29T08:05:00Z"}
	}]
}`
