package workload

import (
	"fmt"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

const (
	maxServices       = 100
	maxEndpointSlices = 100
	maxAutoscalers    = 100
	maxStorageClaims  = 100
	maxServicePorts   = 32
	maxAccessModes    = 16
	maxSliceEndpoints = 1000
	maxEndpointAddrs  = 100
)

// ServiceNormalizationResult contains bounded normalized Services.
type ServiceNormalizationResult struct {
	Services  []Service
	Truncated bool
}

// EndpointSliceNormalizationResult contains bounded normalized EndpointSlices.
type EndpointSliceNormalizationResult struct {
	EndpointSlices []EndpointSlice
	Truncated      bool
}

// AutoscalerNormalizationResult contains bounded normalized HPAs.
type AutoscalerNormalizationResult struct {
	Autoscalers []Autoscaler
	Truncated   bool
}

// StorageNormalizationResult contains bounded normalized PVCs.
type StorageNormalizationResult struct {
	Storage   []Storage
	Truncated bool
}

// NormalizeServiceListJSON decodes a ServiceList into its approved routing
// fields. Unknown fields are ignored and never retained.
func NormalizeServiceListJSON(
	data []byte,
	redactor *redact.Redactor,
) (ServiceNormalizationResult, error) {
	normalizer, err := newNormalizer(data, redactor, "Service")
	if err != nil {
		return ServiceNormalizationResult{}, err
	}
	var list rawServiceList
	if err := decodeList(data, serviceKind, &list); err != nil {
		return ServiceNormalizationResult{}, err
	}
	if err := validateListKind(list.Kind, serviceKind); err != nil {
		return ServiceNormalizationResult{}, err
	}
	if !list.Items.set {
		return ServiceNormalizationResult{}, fmt.Errorf("decode Service list: items are required")
	}
	services, err := normalizeRecords(
		normalizer,
		list.Items.values,
		maxServices,
		normalizeServiceItem,
	)
	if err != nil {
		return ServiceNormalizationResult{}, err
	}
	return ServiceNormalizationResult{
		Services:  services,
		Truncated: normalizer.truncated,
	}, nil
}

// NormalizeEndpointSliceListJSON decodes an EndpointSliceList and emits only
// endpoint condition counts; endpoint addresses are never decoded.
func NormalizeEndpointSliceListJSON(
	data []byte,
	redactor *redact.Redactor,
) (EndpointSliceNormalizationResult, error) {
	normalizer, err := newNormalizer(data, redactor, "EndpointSlice")
	if err != nil {
		return EndpointSliceNormalizationResult{}, err
	}
	var list rawEndpointSliceList
	if err := decodeList(data, endpointSliceKind, &list); err != nil {
		return EndpointSliceNormalizationResult{}, err
	}
	if err := validateListKind(list.Kind, endpointSliceKind); err != nil {
		return EndpointSliceNormalizationResult{}, err
	}
	if !list.Items.set {
		return EndpointSliceNormalizationResult{}, fmt.Errorf(
			"decode EndpointSlice list: items are required",
		)
	}
	slices, err := normalizeRecords(
		normalizer,
		list.Items.values,
		maxEndpointSlices,
		normalizeEndpointSliceItem,
	)
	if err != nil {
		return EndpointSliceNormalizationResult{}, err
	}
	return EndpointSliceNormalizationResult{
		EndpointSlices: slices,
		Truncated:      normalizer.truncated,
	}, nil
}

// NormalizeHorizontalPodAutoscalerListJSON decodes an HPA list into approved
// target and replica fields.
func NormalizeHorizontalPodAutoscalerListJSON(
	data []byte,
	redactor *redact.Redactor,
) (AutoscalerNormalizationResult, error) {
	normalizer, err := newNormalizer(data, redactor, "HorizontalPodAutoscaler")
	if err != nil {
		return AutoscalerNormalizationResult{}, err
	}
	var list rawHorizontalPodAutoscalerList
	if err := decodeList(data, horizontalPodAutoscalerKind, &list); err != nil {
		return AutoscalerNormalizationResult{}, err
	}
	if err := validateListKind(list.Kind, horizontalPodAutoscalerKind); err != nil {
		return AutoscalerNormalizationResult{}, err
	}
	if !list.Items.set {
		return AutoscalerNormalizationResult{}, fmt.Errorf(
			"decode HorizontalPodAutoscaler list: items are required",
		)
	}
	autoscalers, err := normalizeRecords(
		normalizer,
		list.Items.values,
		maxAutoscalers,
		normalizeAutoscalerItem,
	)
	if err != nil {
		return AutoscalerNormalizationResult{}, err
	}
	return AutoscalerNormalizationResult{
		Autoscalers: autoscalers,
		Truncated:   normalizer.truncated,
	}, nil
}

// NormalizePersistentVolumeClaimListJSON decodes a PVC list into approved
// storage request, capacity, mode, class, and phase fields.
func NormalizePersistentVolumeClaimListJSON(
	data []byte,
	redactor *redact.Redactor,
) (StorageNormalizationResult, error) {
	normalizer, err := newNormalizer(data, redactor, "PersistentVolumeClaim")
	if err != nil {
		return StorageNormalizationResult{}, err
	}
	var list rawPersistentVolumeClaimList
	if err := decodeList(data, persistentVolumeClaimKind, &list); err != nil {
		return StorageNormalizationResult{}, err
	}
	if err := validateListKind(list.Kind, persistentVolumeClaimKind); err != nil {
		return StorageNormalizationResult{}, err
	}
	if !list.Items.set {
		return StorageNormalizationResult{}, fmt.Errorf(
			"decode PersistentVolumeClaim list: items are required",
		)
	}
	storage, err := normalizeRecords(
		normalizer,
		list.Items.values,
		maxStorageClaims,
		normalizeStorageItem,
	)
	if err != nil {
		return StorageNormalizationResult{}, err
	}
	return StorageNormalizationResult{
		Storage:   storage,
		Truncated: normalizer.truncated,
	}, nil
}

func normalizeRecords[Raw any, Output any](
	normalizer *normalizer,
	items []Raw,
	maximum int,
	normalize func(*normalizer, Raw, int) (Output, error),
) ([]Output, error) {
	validator := normalizer.validator()
	for index := range items {
		if _, err := normalize(validator, items[index], index); err != nil {
			return nil, err
		}
	}
	count := normalizer.boundedLength(len(items), maximum)
	output := make([]Output, 0, count)
	for index := 0; index < count; index++ {
		item, err := normalize(normalizer, items[index], index)
		if err != nil {
			return nil, err
		}
		output = append(output, item)
	}
	return output, nil
}

func normalizeServiceItem(
	normalizer *normalizer,
	item rawService,
	index int,
) (Service, error) {
	if err := validateItemKind(item.Kind, serviceKind, index); err != nil {
		return Service{}, err
	}
	if item.Metadata == nil {
		return Service{}, fmt.Errorf("normalize Service item %d: metadata is required", index)
	}
	if item.Spec == nil {
		return Service{}, fmt.Errorf("normalize Service item %d: spec is required", index)
	}
	resource, err := normalizer.resource(serviceKind, *item.Metadata)
	if err != nil {
		return Service{}, fmt.Errorf("normalize Service item %d: %w", index, err)
	}
	selectors, err := normalizer.stringMap(item.Spec.Selector)
	if err != nil {
		return Service{}, fmt.Errorf("normalize Service item %d selector: %w", index, err)
	}
	portCount := normalizer.boundedLength(len(item.Spec.Ports), maxServicePorts)
	ports := make([]ServicePort, 0, portCount)
	for portIndex := 0; portIndex < portCount; portIndex++ {
		input := item.Spec.Ports[portIndex]
		if input.Port < 1 || input.Port > 65535 {
			return Service{}, fmt.Errorf(
				"normalize Service item %d port %d: port must be between 1 and 65535",
				index,
				portIndex,
			)
		}
		targetPort := ""
		if input.TargetPort.set {
			targetPort = normalizer.string(input.TargetPort.value)
			if targetPort == "" {
				return Service{}, fmt.Errorf(
					"normalize Service item %d port %d: target port must survive sanitization",
					index,
					portIndex,
				)
			}
		}
		ports = append(ports, ServicePort{
			Name:       normalizer.string(input.Name),
			Protocol:   normalizer.string(input.Protocol),
			Port:       input.Port,
			TargetPort: targetPort,
		})
	}
	return Service{
		Resource:  resource,
		Type:      normalizer.string(item.Spec.Type),
		Selectors: selectors,
		Ports:     ports,
	}, nil
}

func normalizeEndpointSliceItem(
	normalizer *normalizer,
	item rawEndpointSlice,
	index int,
) (EndpointSlice, error) {
	if err := validateItemKind(item.Kind, endpointSliceKind, index); err != nil {
		return EndpointSlice{}, err
	}
	if item.Metadata == nil {
		return EndpointSlice{}, fmt.Errorf(
			"normalize EndpointSlice item %d: metadata is required",
			index,
		)
	}
	if !item.AddressType.set || item.AddressType.value == "" {
		return EndpointSlice{}, fmt.Errorf(
			"normalize EndpointSlice item %d: addressType is required and must not be empty",
			index,
		)
	}
	if !item.Endpoints.set {
		return EndpointSlice{}, fmt.Errorf(
			"normalize EndpointSlice item %d: endpoints are required",
			index,
		)
	}
	resource, err := normalizer.resource(endpointSliceKind, *item.Metadata)
	if err != nil {
		return EndpointSlice{}, fmt.Errorf("normalize EndpointSlice item %d: %w", index, err)
	}
	addressType := normalizer.string(item.AddressType.value)
	if addressType == "" {
		return EndpointSlice{}, fmt.Errorf(
			"normalize EndpointSlice item %d: addressType must survive sanitization",
			index,
		)
	}
	output := EndpointSlice{
		Resource:    resource,
		ServiceName: normalizer.string(item.Metadata.Labels[endpointSliceServiceNameLabel]),
		AddressType: addressType,
	}
	for endpointIndex, endpoint := range item.Endpoints.values {
		if endpoint == nil {
			return EndpointSlice{}, fmt.Errorf(
				"normalize EndpointSlice item %d: endpoint %d must be an object",
				index,
				endpointIndex,
			)
		}
		switch {
		case endpoint.Conditions.Ready == nil:
			output.Unknown++
		case *endpoint.Conditions.Ready:
			output.Ready++
		default:
			output.NotReady++
		}
		if endpoint.Conditions.Serving != nil && *endpoint.Conditions.Serving {
			output.Serving++
		}
		if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
			output.Terminating++
		}
	}
	return output, nil
}

func normalizeAutoscalerItem(
	normalizer *normalizer,
	item rawHorizontalPodAutoscaler,
	index int,
) (Autoscaler, error) {
	if err := validateItemKind(item.Kind, horizontalPodAutoscalerKind, index); err != nil {
		return Autoscaler{}, err
	}
	if item.Metadata == nil {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: metadata is required",
			index,
		)
	}
	if item.Spec == nil {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: spec is required",
			index,
		)
	}
	if item.Spec.ScaleTargetRef == nil {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: scaleTargetRef is required",
			index,
		)
	}
	if item.Spec.MaxReplicas == nil {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: maxReplicas is required",
			index,
		)
	}
	if *item.Spec.MaxReplicas <= 0 {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: maxReplicas must be greater than zero",
			index,
		)
	}
	if item.Spec.MinReplicas != nil && *item.Spec.MinReplicas < 0 {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: minReplicas must not be negative",
			index,
		)
	}
	if item.Status.CurrentReplicas < 0 || item.Status.DesiredReplicas < 0 {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: currentReplicas and desiredReplicas must not be negative",
			index,
		)
	}
	if item.Spec.MinReplicas != nil && *item.Spec.MinReplicas > *item.Spec.MaxReplicas {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: minReplicas must not exceed maxReplicas",
			index,
		)
	}
	resource, err := normalizer.resource(horizontalPodAutoscalerKind, *item.Metadata)
	if err != nil {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: %w",
			index,
			err,
		)
	}
	if item.Spec.ScaleTargetRef.Kind == "" || item.Spec.ScaleTargetRef.Name == "" {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: target kind and name are required",
			index,
		)
	}
	targetKind := normalizer.string(item.Spec.ScaleTargetRef.Kind)
	targetName := normalizer.string(item.Spec.ScaleTargetRef.Name)
	if targetKind == "" || targetName == "" {
		return Autoscaler{}, fmt.Errorf(
			"normalize HorizontalPodAutoscaler item %d: target kind and name must survive sanitization",
			index,
		)
	}
	return Autoscaler{
		Resource: resource,
		Target: TargetReference{
			APIVersion: normalizer.string(item.Spec.ScaleTargetRef.APIVersion),
			Kind:       targetKind,
			Name:       targetName,
		},
		CurrentReplicas: item.Status.CurrentReplicas,
		DesiredReplicas: item.Status.DesiredReplicas,
		MinimumReplicas: copyInt32(item.Spec.MinReplicas),
		MaximumReplicas: *item.Spec.MaxReplicas,
	}, nil
}

func normalizeStorageItem(
	normalizer *normalizer,
	item rawPersistentVolumeClaim,
	index int,
) (Storage, error) {
	if err := validateItemKind(item.Kind, persistentVolumeClaimKind, index); err != nil {
		return Storage{}, err
	}
	if item.Metadata == nil {
		return Storage{}, fmt.Errorf(
			"normalize PersistentVolumeClaim item %d: metadata is required",
			index,
		)
	}
	if item.Spec == nil {
		return Storage{}, fmt.Errorf(
			"normalize PersistentVolumeClaim item %d: spec is required",
			index,
		)
	}
	resource, err := normalizer.resource(persistentVolumeClaimKind, *item.Metadata)
	if err != nil {
		return Storage{}, fmt.Errorf(
			"normalize PersistentVolumeClaim item %d: %w",
			index,
			err,
		)
	}
	accessModeCount := normalizer.boundedLength(len(item.Spec.AccessModes), maxAccessModes)
	accessModes := make([]string, 0, accessModeCount)
	for modeIndex := 0; modeIndex < accessModeCount; modeIndex++ {
		accessModes = append(accessModes, normalizer.string(item.Spec.AccessModes[modeIndex]))
	}
	var storageClassName *string
	if item.Spec.StorageClassName != nil {
		value := normalizer.string(*item.Spec.StorageClassName)
		storageClassName = &value
	}
	return Storage{
		Resource:          resource,
		Phase:             normalizer.string(item.Status.Phase),
		RequestedCapacity: normalizer.string(item.Spec.Resources.Requests.storage),
		Capacity:          normalizer.string(item.Status.Capacity.storage),
		AccessModes:       accessModes,
		StorageClassName:  storageClassName,
		VolumeMode:        normalizer.string(item.Spec.VolumeMode),
	}, nil
}
