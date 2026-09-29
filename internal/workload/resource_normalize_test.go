package workload

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func TestNormalizeResourceListsSupportsAllKinds(t *testing.T) {
	t.Parallel()

	serviceResult, err := NormalizeServiceListJSON(
		readFixture(t, "service-list.json"),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if serviceResult.Truncated || len(serviceResult.Services) != 1 {
		t.Fatalf("unexpected Service result: %+v", serviceResult)
	}
	service := serviceResult.Services[0]
	if service.Kind != string(serviceKind) ||
		service.Namespace != "platform" ||
		service.Name != "api" ||
		service.Type != "ClusterIP" ||
		len(service.Ports) != 2 ||
		service.Ports[0].TargetPort != "8080" ||
		service.Ports[1].TargetPort != "metrics" {
		t.Fatalf("Service fields were not normalized: %+v", service)
	}
	if len(service.Selectors) != 2 ||
		service.Selectors["App"] != "password="+redact.Replacement ||
		service.Selectors["app"] != "api" {
		t.Fatalf("Service selectors were not preserved and redacted: %+v", service.Selectors)
	}

	endpointResult, err := NormalizeEndpointSliceListJSON(
		readFixture(t, "endpointslice-list.json"),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if endpointResult.Truncated || len(endpointResult.EndpointSlices) != 1 {
		t.Fatalf("unexpected EndpointSlice result: %+v", endpointResult)
	}
	endpointSlice := endpointResult.EndpointSlices[0]
	if endpointSlice.Kind != string(endpointSliceKind) ||
		endpointSlice.ServiceName != "password="+redact.Replacement ||
		endpointSlice.AddressType != "IPv4" ||
		endpointSlice.Ready != 1 ||
		endpointSlice.NotReady != 1 ||
		endpointSlice.Unknown != 1 ||
		endpointSlice.Serving != 1 ||
		endpointSlice.Terminating != 1 {
		t.Fatalf("EndpointSlice fields were not summarized: %+v", endpointSlice)
	}

	autoscalerResult, err := NormalizeHorizontalPodAutoscalerListJSON(
		readFixture(t, "hpa-list.json"),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if autoscalerResult.Truncated || len(autoscalerResult.Autoscalers) != 1 {
		t.Fatalf("unexpected HPA result: %+v", autoscalerResult)
	}
	autoscaler := autoscalerResult.Autoscalers[0]
	if autoscaler.Kind != string(horizontalPodAutoscalerKind) ||
		autoscaler.Target.APIVersion != "apps/v1" ||
		autoscaler.Target.Kind != "Deployment" ||
		autoscaler.Target.Name != "password="+redact.Replacement ||
		autoscaler.CurrentReplicas != 3 ||
		autoscaler.DesiredReplicas != 5 ||
		autoscaler.MaximumReplicas != 10 {
		t.Fatalf("HPA fields were not normalized: %+v", autoscaler)
	}
	assertInt32Pointer(t, autoscaler.MinimumReplicas, 0)

	storageResult, err := NormalizePersistentVolumeClaimListJSON(
		readFixture(t, "pvc-list.json"),
		redact.New(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if storageResult.Truncated || len(storageResult.Storage) != 1 {
		t.Fatalf("unexpected PVC result: %+v", storageResult)
	}
	storage := storageResult.Storage[0]
	if storage.Kind != string(persistentVolumeClaimKind) ||
		storage.Phase != "Bound" ||
		storage.RequestedCapacity != "20Gi" ||
		storage.Capacity != "20Gi" ||
		!reflect.DeepEqual(storage.AccessModes, []string{"ReadWriteOnce", "ReadOnlyMany"}) ||
		storage.VolumeMode != "Filesystem" ||
		storage.StorageClassName == nil ||
		*storage.StorageClassName != "password="+redact.Replacement {
		t.Fatalf("PVC fields were not normalized: %+v", storage)
	}

	records := []any{service, endpointSlice, autoscaler, storage}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{
		"forbidden-",
		"raw-service-label-secret",
		"raw-selector-secret",
		"raw-endpoint-service-secret",
		"raw-target-secret",
		"raw-storage-class-secret",
		"10.0.0.1",
		"10.1.2.3",
		"203.0.113",
		`"annotations"`,
		`"addresses"`,
		`"clusterIP"`,
		`"cluster_ip"`,
		`"externalIPs"`,
		`"currentMetrics"`,
		`"behavior"`,
		`"volumeName"`,
		`"dataSource"`,
		`"raw_manifest"`,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("normalized resources retained %q: %s", forbidden, output)
		}
	}
}

func TestNormalizeResourceListsRemoveControlsBeforeRedaction(t *testing.T) {
	t.Parallel()
	input := `{
		"kind":"ServiceList",
		"items":[{
			"kind":"Service",
			"metadata":{"name":"api","namespace":"platform"},
			"spec":{
				"selector":{"app":"pass\u0000word=raw-control-secret"},
				"ports":[{"port":80}]
			}
		}]
	}`
	result, err := NormalizeServiceListJSON([]byte(input), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated {
		t.Fatal("control removal did not report truncation")
	}
	actual := result.Services[0].Selectors["app"]
	if actual != "password="+redact.Replacement ||
		strings.Contains(actual, "raw-control-secret") {
		t.Fatalf("control-obscured secret was not redacted: %q", actual)
	}
}

func TestNormalizeResourceListsPreservePointerPresence(t *testing.T) {
	t.Parallel()
	hpaInput := `{
		"kind":"HorizontalPodAutoscalerList",
		"items":[
			{
				"kind":"HorizontalPodAutoscaler",
				"metadata":{"name":"absent","namespace":"platform"},
				"spec":{"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":10}
			},
			{
				"kind":"HorizontalPodAutoscaler",
				"metadata":{"name":"zero","namespace":"platform"},
				"spec":{"scaleTargetRef":{"kind":"Deployment","name":"api"},"minReplicas":0,"maxReplicas":10}
			}
		]
	}`
	hpas, err := NormalizeHorizontalPodAutoscalerListJSON([]byte(hpaInput), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if hpas.Autoscalers[0].MinimumReplicas != nil {
		t.Fatal("absent minimum replicas became present")
	}
	assertInt32Pointer(t, hpas.Autoscalers[1].MinimumReplicas, 0)

	pvcInput := `{
		"kind":"PersistentVolumeClaimList",
		"items":[
			{
				"kind":"PersistentVolumeClaim",
				"metadata":{"name":"absent","namespace":"platform"},
				"spec":{}
			},
			{
				"kind":"PersistentVolumeClaim",
				"metadata":{"name":"empty","namespace":"platform"},
				"spec":{"storageClassName":""}
			}
		]
	}`
	pvcs, err := NormalizePersistentVolumeClaimListJSON([]byte(pvcInput), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if pvcs.Storage[0].StorageClassName != nil {
		t.Fatal("absent storage class became present")
	}
	if pvcs.Storage[1].StorageClassName == nil || *pvcs.Storage[1].StorageClassName != "" {
		t.Fatalf("explicit empty storage class was lost: %+v", pvcs.Storage[1])
	}
}

func TestNormalizeResourceListsPreserveCaseSensitiveMapKeys(t *testing.T) {
	t.Parallel()
	serviceInput := `{
		"kind":"ServiceList",
		"items":[{
			"kind":"Service",
			"metadata":{"name":"api","namespace":"platform"},
			"spec":{"selector":{"Team":"one","team":"two"},"ports":[{"port":80}]}
		}]
	}`
	services, err := NormalizeServiceListJSON([]byte(serviceInput), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(
		services.Services[0].Selectors,
		map[string]string{"Team": "one", "team": "two"},
	) {
		t.Fatalf("case-distinct selector keys were lost: %+v", services.Services[0].Selectors)
	}

	pvcInput := `{
		"kind":"PersistentVolumeClaimList",
		"items":[{
			"kind":"PersistentVolumeClaim",
			"metadata":{"name":"data","namespace":"platform"},
			"spec":{"resources":{"requests":{"storage":"20Gi","Storage":"forbidden"}}},
			"status":{"capacity":{"storage":"19Gi","Storage":"forbidden"}}
		}]
	}`
	storage, err := NormalizePersistentVolumeClaimListJSON([]byte(pvcInput), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if storage.Storage[0].RequestedCapacity != "20Gi" ||
		storage.Storage[0].Capacity != "19Gi" {
		t.Fatalf("case-sensitive quantity keys were confused: %+v", storage.Storage[0])
	}
}

func TestNormalizeResourceListsApplyDeterministicBounds(t *testing.T) {
	t.Parallel()
	selectors := make(map[string]string)
	for index := maxMapEntries + 2; index >= 0; index-- {
		selectors[fmt.Sprintf("key-%02d", index)] = fmt.Sprintf("value-%02d", index)
	}
	ports := make([]map[string]any, maxServicePorts+2)
	for index := range ports {
		ports[index] = map[string]any{
			"name": fmt.Sprintf("port-%02d", index),
			"port": int32(index + 1),
		}
	}
	items := make([]map[string]any, maxServices+1)
	for index := range items {
		items[index] = map[string]any{
			"kind": "Service",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("service-%03d", index),
				"namespace": "platform",
			},
			"spec": map[string]any{"ports": []any{map[string]any{"port": 80}}},
		}
	}
	items[0]["metadata"].(map[string]any)["name"] =
		"prefix-\u0000" + strings.Repeat("x", maxStringBytes+50)
	items[0]["spec"] = map[string]any{
		"selector": selectors,
		"ports":    ports,
	}
	data, err := json.Marshal(map[string]any{
		"kind":  "ServiceList",
		"items": items,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := NormalizeServiceListJSON(data, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeServiceListJSON(data, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Truncated ||
		len(first.Services) != maxServices ||
		len(first.Services[0].Selectors) != maxMapEntries ||
		len(first.Services[0].Ports) != maxServicePorts ||
		len(first.Services[0].Name) != maxStringBytes {
		t.Fatalf("Service bounds were not applied: %+v", first.Services[0])
	}
	if _, exists := first.Services[0].Selectors["key-31"]; !exists {
		t.Fatal("sorted in-bound selector key was not retained")
	}
	if _, exists := first.Services[0].Selectors["key-32"]; exists {
		t.Fatal("out-of-bound selector key was retained")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Service normalization was not deterministic")
	}

	accessModes := make([]string, maxAccessModes+2)
	for index := range accessModes {
		accessModes[index] = fmt.Sprintf("Mode-%02d", index)
	}
	pvcData, err := json.Marshal(map[string]any{
		"kind": "PersistentVolumeClaimList",
		"items": []any{map[string]any{
			"kind": "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      "data",
				"namespace": "platform",
			},
			"spec": map[string]any{"accessModes": accessModes},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pvcs, err := NormalizePersistentVolumeClaimListJSON(pvcData, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if !pvcs.Truncated || len(pvcs.Storage[0].AccessModes) != maxAccessModes {
		t.Fatalf("PVC access modes were not bounded: %+v", pvcs)
	}
}

func TestNormalizeOtherResourceListsApplyDeterministicRecordBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		listKind  string
		itemKind  string
		maximum   int
		validItem func(int) map[string]any
		normalize func([]byte) (int, string, bool, any, error)
	}{
		{
			name:     "EndpointSlice",
			listKind: "EndpointSliceList",
			itemKind: "EndpointSlice",
			maximum:  maxEndpointSlices,
			validItem: func(index int) map[string]any {
				item := resourceItem("EndpointSlice", index, nil)
				item["addressType"] = "IPv4"
				item["endpoints"] = []any{map[string]any{
					"addresses": []string{fmt.Sprintf("10.0.0.%d", index+1)},
				}}
				return item
			},
			normalize: func(data []byte) (int, string, bool, any, error) {
				result, err := NormalizeEndpointSliceListJSON(data, redact.New())
				if err != nil || len(result.EndpointSlices) == 0 {
					return len(result.EndpointSlices), "", result.Truncated, result, err
				}
				return len(result.EndpointSlices),
					result.EndpointSlices[len(result.EndpointSlices)-1].Name,
					result.Truncated,
					result,
					nil
			},
		},
		{
			name:     "HorizontalPodAutoscaler",
			listKind: "HorizontalPodAutoscalerList",
			itemKind: "HorizontalPodAutoscaler",
			maximum:  maxAutoscalers,
			validItem: func(index int) map[string]any {
				return resourceItem("HorizontalPodAutoscaler", index, map[string]any{
					"scaleTargetRef": map[string]any{
						"kind": "Deployment",
						"name": fmt.Sprintf("target-%03d", index),
					},
					"maxReplicas": 10,
				})
			},
			normalize: func(data []byte) (int, string, bool, any, error) {
				result, err := NormalizeHorizontalPodAutoscalerListJSON(data, redact.New())
				if err != nil || len(result.Autoscalers) == 0 {
					return len(result.Autoscalers), "", result.Truncated, result, err
				}
				return len(result.Autoscalers),
					result.Autoscalers[len(result.Autoscalers)-1].Name,
					result.Truncated,
					result,
					nil
			},
		},
		{
			name:     "PersistentVolumeClaim",
			listKind: "PersistentVolumeClaimList",
			itemKind: "PersistentVolumeClaim",
			maximum:  maxStorageClaims,
			validItem: func(index int) map[string]any {
				return resourceItem("PersistentVolumeClaim", index, nil)
			},
			normalize: func(data []byte) (int, string, bool, any, error) {
				result, err := NormalizePersistentVolumeClaimListJSON(data, redact.New())
				if err != nil || len(result.Storage) == 0 {
					return len(result.Storage), "", result.Truncated, result, err
				}
				return len(result.Storage),
					result.Storage[len(result.Storage)-1].Name,
					result.Truncated,
					result,
					nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			items := make([]map[string]any, test.maximum+1)
			for index := range items {
				items[index] = test.validItem(index)
			}
			data, err := json.Marshal(map[string]any{
				"kind":  test.listKind,
				"items": items,
			})
			if err != nil {
				t.Fatal(err)
			}
			count, lastName, truncated, first, err := test.normalize(data)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, second, err := test.normalize(data)
			if err != nil {
				t.Fatal(err)
			}
			if !truncated || count != test.maximum ||
				lastName != fmt.Sprintf("resource-%03d", test.maximum-1) {
				t.Fatalf(
					"%s bounds not applied: count=%d last=%q truncated=%v",
					test.itemKind,
					count,
					lastName,
					truncated,
				)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("%s truncation was not deterministic", test.itemKind)
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "EndpointSlice" && strings.Contains(string(encoded), "10.0.0.") {
				t.Fatalf("EndpointSlice output retained endpoint addresses: %s", encoded)
			}
		})
	}
}

func TestNormalizeResourceListsValidateRecordsBeyondOutputLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		listKind      string
		itemKind      string
		maximum       int
		validItem     func(int) map[string]any
		normalizeData func([]byte) error
	}{
		{
			name:     "Service",
			listKind: "ServiceList",
			itemKind: "Service",
			maximum:  maxServices,
			validItem: func(index int) map[string]any {
				return resourceItem("Service", index, map[string]any{
					"ports": []any{map[string]any{"port": 80}},
				})
			},
			normalizeData: func(data []byte) error {
				_, err := NormalizeServiceListJSON(data, redact.New())
				return err
			},
		},
		{
			name:     "EndpointSlice",
			listKind: "EndpointSliceList",
			itemKind: "EndpointSlice",
			maximum:  maxEndpointSlices,
			validItem: func(index int) map[string]any {
				item := resourceItem("EndpointSlice", index, nil)
				item["addressType"] = "IPv4"
				item["endpoints"] = []any{}
				return item
			},
			normalizeData: func(data []byte) error {
				_, err := NormalizeEndpointSliceListJSON(data, redact.New())
				return err
			},
		},
		{
			name:     "HorizontalPodAutoscaler",
			listKind: "HorizontalPodAutoscalerList",
			itemKind: "HorizontalPodAutoscaler",
			maximum:  maxAutoscalers,
			validItem: func(index int) map[string]any {
				return resourceItem("HorizontalPodAutoscaler", index, map[string]any{
					"scaleTargetRef": map[string]any{
						"kind": "Deployment",
						"name": "api",
					},
					"maxReplicas": 10,
				})
			},
			normalizeData: func(data []byte) error {
				_, err := NormalizeHorizontalPodAutoscalerListJSON(data, redact.New())
				return err
			},
		},
		{
			name:     "PersistentVolumeClaim",
			listKind: "PersistentVolumeClaimList",
			itemKind: "PersistentVolumeClaim",
			maximum:  maxStorageClaims,
			validItem: func(index int) map[string]any {
				return resourceItem("PersistentVolumeClaim", index, nil)
			},
			normalizeData: func(data []byte) error {
				_, err := NormalizePersistentVolumeClaimListJSON(data, redact.New())
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			items := make([]map[string]any, test.maximum+1)
			for index := range items {
				items[index] = test.validItem(index)
			}
			items[test.maximum]["kind"] = "WrongKind"
			data, err := json.Marshal(map[string]any{
				"kind":  test.listKind,
				"items": items,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = test.normalizeData(data)
			if err == nil || !strings.Contains(err.Error(), `kind "WrongKind"`) {
				t.Fatalf(
					"%s after output limit: expected kind validation error, got %v",
					test.itemKind,
					err,
				)
			}
		})
	}
	t.Run("Service port after nested limit", func(t *testing.T) {
		ports := make([]map[string]any, maxServicePorts+1)
		for index := range ports {
			ports[index] = map[string]any{"port": 80}
		}
		ports[maxServicePorts]["port"] = 0
		data, err := json.Marshal(map[string]any{
			"kind": "ServiceList",
			"items": []any{resourceItem("Service", 0, map[string]any{
				"ports": ports,
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = NormalizeServiceListJSON(data, redact.New())
		if err == nil || !strings.Contains(err.Error(), "port must be between 1 and 65535") {
			t.Fatalf("expected bounded Service port validation error, got %v", err)
		}
	})
	t.Run("new validations after record limits", func(t *testing.T) {
		tests := []struct {
			name      string
			listKind  string
			maximum   int
			validItem func(int) map[string]any
			mutate    func(map[string]any)
			normalize func([]byte) error
			wantError string
		}{
			{
				name:     "Service missing spec",
				listKind: "ServiceList",
				maximum:  maxServices,
				validItem: func(index int) map[string]any {
					return resourceItem("Service", index, map[string]any{})
				},
				mutate: func(item map[string]any) {
					delete(item, "spec")
				},
				normalize: func(data []byte) error {
					_, err := NormalizeServiceListJSON(data, redact.New())
					return err
				},
				wantError: "spec is required",
			},
			{
				name:     "EndpointSlice missing addresses",
				listKind: "EndpointSliceList",
				maximum:  maxEndpointSlices,
				validItem: func(index int) map[string]any {
					item := resourceItem("EndpointSlice", index, nil)
					item["addressType"] = "IPv4"
					item["endpoints"] = []any{map[string]any{"addresses": []string{"10.0.0.1"}}}
					return item
				},
				mutate: func(item map[string]any) {
					item["endpoints"] = []any{map[string]any{}}
				},
				normalize: func(data []byte) error {
					_, err := NormalizeEndpointSliceListJSON(data, redact.New())
					return err
				},
				wantError: "endpoint addresses are required",
			},
			{
				name:     "HPA invalid max replicas",
				listKind: "HorizontalPodAutoscalerList",
				maximum:  maxAutoscalers,
				validItem: func(index int) map[string]any {
					return resourceItem("HorizontalPodAutoscaler", index, map[string]any{
						"scaleTargetRef": map[string]any{"kind": "Deployment", "name": "api"},
						"maxReplicas":    10,
					})
				},
				mutate: func(item map[string]any) {
					item["spec"].(map[string]any)["maxReplicas"] = 0
				},
				normalize: func(data []byte) error {
					_, err := NormalizeHorizontalPodAutoscalerListJSON(data, redact.New())
					return err
				},
				wantError: "maxReplicas must be greater than zero",
			},
			{
				name:     "PVC missing spec",
				listKind: "PersistentVolumeClaimList",
				maximum:  maxStorageClaims,
				validItem: func(index int) map[string]any {
					return resourceItem("PersistentVolumeClaim", index, map[string]any{})
				},
				mutate: func(item map[string]any) {
					delete(item, "spec")
				},
				normalize: func(data []byte) error {
					_, err := NormalizePersistentVolumeClaimListJSON(data, redact.New())
					return err
				},
				wantError: "spec is required",
			},
		}
		for _, test := range tests {
			items := make([]map[string]any, test.maximum+1)
			for index := range items {
				items[index] = test.validItem(index)
			}
			test.mutate(items[test.maximum])
			data, err := json.Marshal(map[string]any{
				"kind":  test.listKind,
				"items": items,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = test.normalize(data)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("%s: expected %q, got %v", test.name, test.wantError, err)
			}
		}
	})
}

func TestNormalizeResourceListsRequireKubernetesStructure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		kind      string
		input     string
		wantError string
	}{
		{
			name:      "Service items missing",
			kind:      "Service",
			input:     `{"kind":"ServiceList"}`,
			wantError: "items are required",
		},
		{
			name:      "Service items null",
			kind:      "Service",
			input:     `{"kind":"ServiceList","items":null}`,
			wantError: "required list must not be null",
		},
		{
			name:      "EndpointSlice items missing",
			kind:      "EndpointSlice",
			input:     `{"kind":"EndpointSliceList"}`,
			wantError: "items are required",
		},
		{
			name:      "EndpointSlice items null",
			kind:      "EndpointSlice",
			input:     `{"kind":"EndpointSliceList","items":null}`,
			wantError: "required list must not be null",
		},
		{
			name:      "HPA items missing",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList"}`,
			wantError: "items are required",
		},
		{
			name:      "HPA items null",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":null}`,
			wantError: "required list must not be null",
		},
		{
			name:      "PVC items missing",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList"}`,
			wantError: "items are required",
		},
		{
			name:      "PVC items null",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList","items":null}`,
			wantError: "required list must not be null",
		},
		{
			name:      "Service metadata missing",
			kind:      "Service",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","spec":{}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "Service metadata null",
			kind:      "Service",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","metadata":null,"spec":{}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "Service spec missing",
			kind:      "Service",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","metadata":{"name":"api","namespace":"platform"}}]}`,
			wantError: "spec is required",
		},
		{
			name:      "Service spec null",
			kind:      "Service",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","metadata":{"name":"api","namespace":"platform"},"spec":null}]}`,
			wantError: "spec is required",
		},
		{
			name:      "EndpointSlice metadata missing",
			kind:      "EndpointSlice",
			input:     `{"kind":"EndpointSliceList","items":[{"kind":"EndpointSlice","addressType":"IPv4","endpoints":[]}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "EndpointSlice metadata null",
			kind:      "EndpointSlice",
			input:     `{"kind":"EndpointSliceList","items":[{"kind":"EndpointSlice","metadata":null,"addressType":"IPv4","endpoints":[]}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "HPA metadata missing",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","spec":{"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":10}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "HPA metadata null",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":null,"spec":{"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":10}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "HPA spec missing",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"}}]}`,
			wantError: "spec is required",
		},
		{
			name:      "HPA spec null",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"},"spec":null}]}`,
			wantError: "spec is required",
		},
		{
			name:      "HPA target missing",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"},"spec":{"maxReplicas":10}}]}`,
			wantError: "scaleTargetRef is required",
		},
		{
			name:      "HPA target null",
			kind:      "HorizontalPodAutoscaler",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"},"spec":{"scaleTargetRef":null,"maxReplicas":10}}]}`,
			wantError: "scaleTargetRef is required",
		},
		{
			name:      "PVC metadata missing",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList","items":[{"kind":"PersistentVolumeClaim","spec":{}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "PVC metadata null",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList","items":[{"kind":"PersistentVolumeClaim","metadata":null,"spec":{}}]}`,
			wantError: "metadata is required",
		},
		{
			name:      "PVC spec missing",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList","items":[{"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"platform"}}]}`,
			wantError: "spec is required",
		},
		{
			name:      "PVC spec null",
			kind:      "PersistentVolumeClaim",
			input:     `{"kind":"PersistentVolumeClaimList","items":[{"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"platform"},"spec":null}]}`,
			wantError: "spec is required",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := normalizeResourceKind(test.kind, []byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestNormalizeEndpointSliceRequiredFields(t *testing.T) {
	t.Parallel()
	validMetadata := `"metadata":{"name":"api-a","namespace":"platform"}`
	tests := []struct {
		name      string
		fields    string
		wantError string
	}{
		{
			name:      "address type missing",
			fields:    validMetadata + `,"endpoints":[]`,
			wantError: "addressType is required and must not be empty",
		},
		{
			name:      "address type null",
			fields:    validMetadata + `,"addressType":null,"endpoints":[]`,
			wantError: "required string must not be null",
		},
		{
			name:      "address type empty",
			fields:    validMetadata + `,"addressType":"","endpoints":[]`,
			wantError: "addressType is required and must not be empty",
		},
		{
			name:      "address type removed by sanitization",
			fields:    validMetadata + `,"addressType":"\u0000","endpoints":[]`,
			wantError: "addressType must survive sanitization",
		},
		{
			name:      "endpoints missing",
			fields:    validMetadata + `,"addressType":"IPv4"`,
			wantError: "endpoints are required",
		},
		{
			name:      "endpoints null",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":null`,
			wantError: "required list must not be null",
		},
		{
			name:      "endpoint addresses missing",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{}]`,
			wantError: "endpoint addresses are required",
		},
		{
			name:      "endpoint addresses null",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{"addresses":null}]`,
			wantError: "endpoint addresses must not be null",
		},
		{
			name:      "endpoint addresses empty",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{"addresses":[]}]`,
			wantError: "endpoint addresses must not be empty",
		},
		{
			name:      "endpoint addresses not an array",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{"addresses":{}}]`,
			wantError: "endpoint addresses must be an array",
		},
		{
			name:      "endpoint address empty",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{"addresses":[""]}]`,
			wantError: "endpoint address 0 must not be empty",
		},
		{
			name:      "endpoint address not a string",
			fields:    validMetadata + `,"addressType":"IPv4","endpoints":[{"addresses":[1]}]`,
			wantError: "decode endpoint address 0",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := `{"kind":"EndpointSliceList","items":[{"kind":"EndpointSlice",` +
				test.fields + `}]}`
			_, err := NormalizeEndpointSliceListJSON([]byte(input), redact.New())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}

	t.Run("empty endpoints are valid", func(t *testing.T) {
		input := `{"kind":"EndpointSliceList","items":[{"kind":"EndpointSlice",` +
			validMetadata + `,"addressType":"IPv4","endpoints":[]}]}`
		result, err := NormalizeEndpointSliceListJSON([]byte(input), redact.New())
		if err != nil {
			t.Fatal(err)
		}
		if len(result.EndpointSlices) != 1 ||
			result.EndpointSlices[0].Ready != 0 ||
			result.EndpointSlices[0].Unknown != 0 {
			t.Fatalf("unexpected empty EndpointSlice: %+v", result)
		}
	})
}

func TestNormalizeHorizontalPodAutoscalerReplicaValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		spec      string
		status    string
		wantError string
	}{
		{
			name:      "max replicas missing",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"}`,
			wantError: "maxReplicas is required",
		},
		{
			name:      "max replicas null",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":null`,
			wantError: "maxReplicas is required",
		},
		{
			name:      "max replicas zero",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":0`,
			wantError: "maxReplicas must be greater than zero",
		},
		{
			name:      "max replicas negative",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":-1`,
			wantError: "maxReplicas must be greater than zero",
		},
		{
			name:      "min replicas negative",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"minReplicas":-1,"maxReplicas":10`,
			wantError: "minReplicas must not be negative",
		},
		{
			name:      "min exceeds max",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"minReplicas":11,"maxReplicas":10`,
			wantError: "minReplicas must not exceed maxReplicas",
		},
		{
			name:      "current replicas negative",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":10`,
			status:    `"currentReplicas":-1`,
			wantError: "currentReplicas and desiredReplicas must not be negative",
		},
		{
			name:      "desired replicas negative",
			spec:      `"scaleTargetRef":{"kind":"Deployment","name":"api"},"maxReplicas":10`,
			status:    `"desiredReplicas":-1`,
			wantError: "currentReplicas and desiredReplicas must not be negative",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := `{"kind":"HorizontalPodAutoscalerList","items":[{` +
				`"kind":"HorizontalPodAutoscaler",` +
				`"metadata":{"name":"api","namespace":"platform"},` +
				`"spec":{` + test.spec + `},` +
				`"status":{` + test.status + `}` +
				`}]}`
			_, err := NormalizeHorizontalPodAutoscalerListJSON([]byte(input), redact.New())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestNormalizeResourceListsRejectMalformedAndAmbiguousInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		wantError string
		normalize func([]byte, *redact.Redactor) error
	}{
		{
			name:      "Service duplicate struct key",
			input:     `{"kind":"ServiceList","kind":"ServiceList","items":[]}`,
			wantError: "duplicate object keys",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeServiceListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "Service struct keys collide by case",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","Kind":"Job","metadata":{"name":"api","namespace":"platform"},"spec":{"ports":[{"port":80}]}}]}`,
			wantError: "match case-insensitively",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeServiceListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "Service malformed target port",
			input:     `{"kind":"ServiceList","items":[{"kind":"Service","metadata":{"name":"api","namespace":"platform"},"spec":{"ports":[{"port":80,"targetPort":{}}]}}]}`,
			wantError: "numeric value must be a base-10 integer",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeServiceListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "EndpointSlice null endpoint",
			input:     `{"kind":"EndpointSliceList","items":[{"kind":"EndpointSlice","metadata":{"name":"api-a","namespace":"platform"},"addressType":"IPv4","endpoints":[null]}]}`,
			wantError: "endpoint 0 must be an object",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeEndpointSliceListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "HPA target keys collide by case",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"},"spec":{"scaleTargetRef":{"kind":"Deployment","Kind":"Job","name":"api"},"maxReplicas":10}}]}`,
			wantError: "match case-insensitively",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeHorizontalPodAutoscalerListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "HPA target identity missing",
			input:     `{"kind":"HorizontalPodAutoscalerList","items":[{"kind":"HorizontalPodAutoscaler","metadata":{"name":"api","namespace":"platform"},"spec":{"scaleTargetRef":{},"maxReplicas":10}}]}`,
			wantError: "target kind and name are required",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizeHorizontalPodAutoscalerListJSON(data, redactor)
				return err
			},
		},
		{
			name:      "PVC storage quantity has wrong type",
			input:     `{"kind":"PersistentVolumeClaimList","items":[{"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"platform"},"spec":{"resources":{"requests":{"storage":20}}}}]}`,
			wantError: "cannot unmarshal number",
			normalize: func(data []byte, redactor *redact.Redactor) error {
				_, err := NormalizePersistentVolumeClaimListJSON(data, redactor)
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.normalize([]byte(test.input), redact.New())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func TestNormalizeResourceListsRequireConfiguredRedactor(t *testing.T) {
	t.Parallel()
	tests := []func(*redact.Redactor) error{
		func(redactor *redact.Redactor) error {
			_, err := NormalizeServiceListJSON([]byte(`{"kind":"ServiceList","items":[]}`), redactor)
			return err
		},
		func(redactor *redact.Redactor) error {
			_, err := NormalizeEndpointSliceListJSON(
				[]byte(`{"kind":"EndpointSliceList","items":[]}`),
				redactor,
			)
			return err
		},
		func(redactor *redact.Redactor) error {
			_, err := NormalizeHorizontalPodAutoscalerListJSON(
				[]byte(`{"kind":"HorizontalPodAutoscalerList","items":[]}`),
				redactor,
			)
			return err
		},
		func(redactor *redact.Redactor) error {
			_, err := NormalizePersistentVolumeClaimListJSON(
				[]byte(`{"kind":"PersistentVolumeClaimList","items":[]}`),
				redactor,
			)
			return err
		},
	}
	for index, normalize := range tests {
		for name, redactor := range map[string]*redact.Redactor{
			"nil":        nil,
			"zero value": {},
		} {
			err := normalize(redactor)
			if err == nil || !strings.Contains(err.Error(), "configured redactor is required") {
				t.Fatalf(
					"normalizer %d with %s redactor: expected configuration error, got %v",
					index,
					name,
					err,
				)
			}
		}
	}
}

func TestNormalizeResourceListsRejectInvalidUTF8(t *testing.T) {
	t.Parallel()
	input := append(
		[]byte(`{"kind":"ServiceList","items":[],"unknown":"`),
		0xff,
	)
	input = append(input, []byte(`"}`)...)
	_, err := NormalizeServiceListJSON(input, redact.New())
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("expected invalid UTF-8 error, got %v", err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func normalizeResourceKind(kind string, data []byte) error {
	switch kind {
	case "Service":
		_, err := NormalizeServiceListJSON(data, redact.New())
		return err
	case "EndpointSlice":
		_, err := NormalizeEndpointSliceListJSON(data, redact.New())
		return err
	case "HorizontalPodAutoscaler":
		_, err := NormalizeHorizontalPodAutoscalerListJSON(data, redact.New())
		return err
	case "PersistentVolumeClaim":
		_, err := NormalizePersistentVolumeClaimListJSON(data, redact.New())
		return err
	default:
		return fmt.Errorf("unsupported test resource kind %q", kind)
	}
}

func resourceItem(kind string, index int, spec map[string]any) map[string]any {
	if spec == nil {
		spec = map[string]any{}
	}
	return map[string]any{
		"kind": kind,
		"metadata": map[string]any{
			"name":      fmt.Sprintf("resource-%03d", index),
			"namespace": "platform",
		},
		"spec": spec,
	}
}
