package workload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// These types intentionally model only fields approved for normalized
// support-bundle artifacts. They must not grow into general Kubernetes types.

type rawServiceList struct {
	Kind     string                       `json:"kind"`
	Metadata rawListMetadata              `json:"metadata"`
	Items    rawRequiredSlice[rawService] `json:"items"`
}

type rawService struct {
	Kind     string          `json:"kind"`
	Metadata *rawMetadata    `json:"metadata"`
	Spec     *rawServiceSpec `json:"spec"`
}

type rawServiceSpec struct {
	Type     string            `json:"type"`
	Selector map[string]string `json:"selector"`
	Ports    []rawServicePort  `json:"ports"`
}

type rawServicePort struct {
	Name       string         `json:"name"`
	Protocol   string         `json:"protocol"`
	Port       int32          `json:"port"`
	TargetPort rawIntOrString `json:"targetPort"`
}

type rawEndpointSliceList struct {
	Kind     string                             `json:"kind"`
	Metadata rawListMetadata                    `json:"metadata"`
	Items    rawRequiredSlice[rawEndpointSlice] `json:"items"`
}

type rawEndpointSlice struct {
	Kind        string               `json:"kind"`
	Metadata    *rawMetadata         `json:"metadata"`
	AddressType rawRequiredString    `json:"addressType"`
	Endpoints   rawRequiredEndpoints `json:"endpoints"`
}

type rawEndpoint struct {
	Conditions rawEndpointConditions `json:"conditions"`
}

func (endpoint *rawEndpoint) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("endpoint must be an object")
	}
	addressesSet := false
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("endpoint field name must be a string")
		}
		switch {
		case strings.EqualFold(key, "addresses"):
			if _, err := validateEndpointAddresses(decoder); err != nil {
				return err
			}
			addressesSet = true
		case strings.EqualFold(key, "conditions"):
			if err := decoder.Decode(&endpoint.Conditions); err != nil {
				return fmt.Errorf("decode endpoint conditions: %w", err)
			}
		default:
			if err := scanJSONValue(decoder, 0, caseSensitiveJSONMap(key)); err != nil {
				return fmt.Errorf("skip endpoint field %q: %w", key, err)
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if !addressesSet {
		return errors.New("endpoint addresses are required")
	}
	return nil
}

type rawEndpointConditions struct {
	Ready       *bool `json:"ready"`
	Serving     *bool `json:"serving"`
	Terminating *bool `json:"terminating"`
}

type rawHorizontalPodAutoscalerList struct {
	Kind     string                                       `json:"kind"`
	Metadata rawListMetadata                              `json:"metadata"`
	Items    rawRequiredSlice[rawHorizontalPodAutoscaler] `json:"items"`
}

type rawHorizontalPodAutoscaler struct {
	Kind     string                           `json:"kind"`
	Metadata *rawMetadata                     `json:"metadata"`
	Spec     *rawHorizontalPodAutoscalerSpec  `json:"spec"`
	Status   rawHorizontalPodAutoscalerStatus `json:"status"`
}

type rawHorizontalPodAutoscalerSpec struct {
	ScaleTargetRef *rawCrossVersionObjectReference `json:"scaleTargetRef"`
	MinReplicas    *int32                          `json:"minReplicas"`
	MaxReplicas    *int32                          `json:"maxReplicas"`
}

type rawHorizontalPodAutoscalerStatus struct {
	CurrentReplicas int32 `json:"currentReplicas"`
	DesiredReplicas int32 `json:"desiredReplicas"`
}

type rawCrossVersionObjectReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

type rawPersistentVolumeClaimList struct {
	Kind     string                                     `json:"kind"`
	Metadata rawListMetadata                            `json:"metadata"`
	Items    rawRequiredSlice[rawPersistentVolumeClaim] `json:"items"`
}

type rawPersistentVolumeClaim struct {
	Kind     string                         `json:"kind"`
	Metadata *rawMetadata                   `json:"metadata"`
	Spec     *rawPersistentVolumeClaimSpec  `json:"spec"`
	Status   rawPersistentVolumeClaimStatus `json:"status"`
}

type rawPersistentVolumeClaimSpec struct {
	AccessModes      []string                  `json:"accessModes"`
	Resources        rawVolumeResourceRequests `json:"resources"`
	StorageClassName *string                   `json:"storageClassName"`
	VolumeMode       string                    `json:"volumeMode"`
}

type rawVolumeResourceRequests struct {
	Requests rawStorageQuantity `json:"requests"`
}

type rawPersistentVolumeClaimStatus struct {
	Phase    string             `json:"phase"`
	Capacity rawStorageQuantity `json:"capacity"`
}

type rawStorageQuantity struct {
	storage string
}

func (quantity *rawStorageQuantity) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return errors.New("storage quantity must not be null")
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	rawStorage, exists := decoded["storage"]
	if !exists {
		quantity.storage = ""
		return nil
	}
	if bytes.Equal(rawStorage, []byte("null")) {
		return errors.New("storage quantity value must not be null")
	}
	var storage string
	if err := json.Unmarshal(rawStorage, &storage); err != nil {
		return fmt.Errorf("decode storage quantity: %w", err)
	}
	if storage == "" {
		return errors.New("storage quantity value must not be empty")
	}
	quantity.storage = storage
	return nil
}

type rawRequiredEndpoints struct {
	values []*rawEndpoint
	set    bool
}

func (endpoints *rawRequiredEndpoints) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return errors.New("required endpoint list must not be null")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return errors.New("endpoints must be an array")
	}
	values := make([]*rawEndpoint, 0)
	for decoder.More() {
		if len(values) >= maxSliceEndpoints {
			return fmt.Errorf("endpoint count exceeds %d", maxSliceEndpoints)
		}
		var endpoint *rawEndpoint
		if err := decoder.Decode(&endpoint); err != nil {
			return err
		}
		values = append(values, endpoint)
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	endpoints.values = values
	endpoints.set = true
	return nil
}

type rawRequiredSlice[T any] struct {
	values []T
	set    bool
}

func (slice *rawRequiredSlice[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return errors.New("required list must not be null")
	}
	var values []T
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	slice.values = values
	slice.set = true
	return nil
}

type rawRequiredString struct {
	value string
	set   bool
}

func (value *rawRequiredString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return errors.New("required string must not be null")
	}
	var decoded string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	value.value = decoded
	value.set = true
	return nil
}

func validateEndpointAddresses(decoder *json.Decoder) (int, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, fmt.Errorf("decode endpoint addresses: %w", err)
	}
	if token == nil {
		return 0, errors.New("endpoint addresses must not be null")
	}
	if token != json.Delim('[') {
		return 0, errors.New("endpoint addresses must be an array")
	}
	count := 0
	for decoder.More() {
		if count >= maxEndpointAddrs {
			return 0, fmt.Errorf("endpoint address count exceeds %d", maxEndpointAddrs)
		}
		var address string
		if err := decoder.Decode(&address); err != nil {
			return 0, fmt.Errorf("decode endpoint address %d: %w", count, err)
		}
		if address == "" {
			return 0, fmt.Errorf("endpoint address %d must not be empty", count)
		}
		count++
	}
	if _, err := decoder.Token(); err != nil {
		return 0, fmt.Errorf("close endpoint addresses: %w", err)
	}
	if count == 0 {
		return 0, errors.New("endpoint addresses must not be empty")
	}
	return count, nil
}

type rawIntOrString struct {
	value string
	set   bool
}

func (value *rawIntOrString) UnmarshalJSON(data []byte) error {
	if value == nil {
		return errors.New("nil integer-or-string value")
	}
	*value = rawIntOrString{}
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return errors.New("value must be an integer or string")
	}
	if data[0] == '"' {
		var decoded string
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("decode string value: %w", err)
		}
		if decoded == "" {
			return errors.New("string value must not be empty")
		}
		value.value = decoded
		value.set = true
		return nil
	}
	for _, character := range data {
		if character < '0' || character > '9' {
			return errors.New("numeric value must be a base-10 integer")
		}
	}
	number, err := strconv.ParseInt(string(data), 10, 32)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("numeric value must be between 1 and 65535")
	}
	value.value = strconv.FormatInt(number, 10)
	value.set = true
	return nil
}
