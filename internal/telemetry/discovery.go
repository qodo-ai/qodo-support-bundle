package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
)

const endpointSliceServiceLabel = "kubernetes.io/service-name"

var (
	dnsLabelPattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	labelNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)
)

type listEnvelope struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Items      json.RawMessage `json:"items"`
}

type serviceItem struct {
	Metadata discoveryMetadata `json:"metadata"`
	Spec     struct {
		Ports []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
}

type endpointSliceItem struct {
	Metadata  discoveryMetadata `json:"metadata"`
	Endpoints []struct {
		Addresses  addressPresence `json:"addresses"`
		Conditions struct {
			Ready *bool `json:"ready"`
		} `json:"conditions"`
	} `json:"endpoints"`
}

type discoveryMetadata struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// addressPresence records only whether the response included an address. It
// deliberately discards address values while decoding.
type addressPresence bool

func (presence *addressPresence) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return errors.New("addresses must be an array")
	}
	found := false
	for decoder.More() {
		var address string
		if err := decoder.Decode(&address); err != nil {
			return err
		}
		if net.ParseIP(address) == nil && !validDNSSubdomain(address) {
			return errors.New("endpoint address is invalid")
		}
		found = true
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	*presence = addressPresence(found)
	return nil
}

// Discover finds the one approved, ready telemetry service in a namespace.
func Discover(
	ctx context.Context,
	config DiscoveryConfig,
	runner kubernetes.Runner,
) (Target, error) {
	if err := validateDiscoveryConfig(config, runner); err != nil {
		return Target{}, err
	}

	discoveryContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	baseArguments := globalArguments(config.Kubeconfig, config.Context)

	serviceData, err := runDiscoveryQuery(
		discoveryContext,
		ctx,
		runner,
		config.MaxResponseBytes,
		append(baseArguments,
			"get", "services",
			"--namespace", config.Namespace,
			"--output", "json",
		)...,
	)
	if err != nil {
		return Target{}, err
	}
	services, err := decodeServices(serviceData, config.Namespace)
	if err != nil {
		return Target{}, err
	}

	matching := make(map[string]struct{})
	for index := range services {
		service := &services[index]
		if labelsMatch(service.Metadata.Labels, config.LabelMatchers) &&
			hasExpectedPort(*service, config.ExpectedPort) {
			matching[service.Metadata.Name] = struct{}{}
		}
		service.Metadata.Labels = nil
	}
	services = nil
	serviceData = nil
	if len(matching) == 0 {
		return Target{}, ErrNoMatchingService
	}

	sliceData, err := runDiscoveryQuery(
		discoveryContext,
		ctx,
		runner,
		config.MaxResponseBytes,
		append(baseArguments,
			"get", "endpointslices.discovery.k8s.io",
			"--namespace", config.Namespace,
			"--output", "json",
		)...,
	)
	if err != nil {
		return Target{}, err
	}
	slices, err := decodeEndpointSlices(sliceData, config.Namespace)
	if err != nil {
		return Target{}, err
	}

	ready := make(map[string]struct{})
	for index := range slices {
		slice := &slices[index]
		serviceName := slice.Metadata.Labels[endpointSliceServiceLabel]
		if _, approved := matching[serviceName]; !approved {
			slice.Metadata.Labels = nil
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil &&
				*endpoint.Conditions.Ready &&
				bool(endpoint.Addresses) {
				ready[serviceName] = struct{}{}
				break
			}
		}
		slice.Metadata.Labels = nil
	}
	switch len(ready) {
	case 0:
		return Target{}, ErrServiceNotReady
	case 1:
		for serviceName := range ready {
			return Target{Service: serviceName, Port: config.ExpectedPort}, nil
		}
	default:
		return Target{}, ErrAmbiguousService
	}
	panic("unreachable")
}

func validateDiscoveryConfig(config DiscoveryConfig, runner kubernetes.Runner) error {
	switch {
	case runner == nil:
		return fmt.Errorf("%w: runner is required", ErrInvalidConfig)
	case !validDNSLabel(config.Namespace):
		return fmt.Errorf("%w: namespace must be a DNS label", ErrInvalidConfig)
	case config.Timeout <= 0:
		return fmt.Errorf("%w: timeout must be positive", ErrInvalidConfig)
	case config.MaxResponseBytes <= 0:
		return fmt.Errorf("%w: response limit must be positive", ErrInvalidConfig)
	case config.ExpectedPort < 1 || config.ExpectedPort > 65535:
		return fmt.Errorf("%w: expected port is out of range", ErrInvalidConfig)
	case len(config.LabelMatchers) == 0:
		return fmt.Errorf("%w: at least one label matcher is required", ErrInvalidConfig)
	}
	for key, value := range config.LabelMatchers {
		if !validLabelKey(key) || !validLabelValue(value) {
			return fmt.Errorf("%w: label matcher is invalid", ErrInvalidConfig)
		}
	}
	return nil
}

func runDiscoveryQuery(
	ctx context.Context,
	parent context.Context,
	runner kubernetes.Runner,
	maxBytes int64,
	arguments ...string,
) ([]byte, error) {
	result, err := runner.Run(ctx, maxBytes, arguments...)
	if ctx.Err() != nil {
		if parent.Err() != nil {
			return nil, errors.Join(ErrDiscoveryCanceled, parent.Err())
		}
		return nil, errors.Join(ErrDiscoveryTimeout, ctx.Err())
	}
	if result.Truncated || int64(len(result.Stdout)) > maxBytes {
		return nil, ErrResponseTooLarge
	}
	if err != nil {
		return nil, ErrDiscoveryCommand
	}
	return result.Stdout, nil
}

func decodeServices(data []byte, namespace string) ([]serviceItem, error) {
	var services []serviceItem
	if err := decodeList(data, "v1", "ServiceList", &services); err != nil {
		return nil, ErrInvalidResponse
	}
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		if !validDNSLabel(service.Metadata.Name) ||
			service.Metadata.Namespace != namespace {
			return nil, ErrInvalidResponse
		}
		if _, duplicate := seen[service.Metadata.Name]; duplicate {
			return nil, ErrInvalidResponse
		}
		seen[service.Metadata.Name] = struct{}{}
		for _, port := range service.Spec.Ports {
			if port.Port < 1 || port.Port > 65535 {
				return nil, ErrInvalidResponse
			}
		}
	}
	return services, nil
}

func decodeEndpointSlices(data []byte, namespace string) ([]endpointSliceItem, error) {
	var slices []endpointSliceItem
	if err := decodeList(
		data,
		"discovery.k8s.io/v1",
		"EndpointSliceList",
		&slices,
	); err != nil {
		return nil, ErrInvalidResponse
	}
	seen := make(map[string]struct{}, len(slices))
	for _, slice := range slices {
		if !validDNSSubdomain(slice.Metadata.Name) ||
			slice.Metadata.Namespace != namespace {
			return nil, ErrInvalidResponse
		}
		if _, duplicate := seen[slice.Metadata.Name]; duplicate {
			return nil, ErrInvalidResponse
		}
		seen[slice.Metadata.Name] = struct{}{}
		serviceName := slice.Metadata.Labels[endpointSliceServiceLabel]
		if serviceName != "" && !validDNSLabel(serviceName) {
			return nil, ErrInvalidResponse
		}
	}
	return slices, nil
}

func decodeList(data []byte, apiVersion string, kind string, destination any) error {
	if len(data) == 0 {
		return errors.New("empty response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var envelope listEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if envelope.APIVersion != apiVersion ||
		envelope.Kind != kind ||
		len(envelope.Items) == 0 ||
		bytes.Equal(bytes.TrimSpace(envelope.Items), []byte("null")) {
		return errors.New("unexpected list shape")
	}
	if err := json.Unmarshal(envelope.Items, destination); err != nil {
		return err
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func labelsMatch(actual map[string]string, approved map[string]string) bool {
	for key, expected := range approved {
		value, exists := actual[key]
		if !exists || value != expected {
			return false
		}
	}
	return true
}

func hasExpectedPort(service serviceItem, expected int) bool {
	for _, port := range service.Spec.Ports {
		if port.Port == expected {
			return true
		}
	}
	return false
}

func globalArguments(kubeconfig string, contextName string) []string {
	arguments := make([]string, 0, 4)
	if kubeconfig != "" {
		arguments = append(arguments, "--kubeconfig", kubeconfig)
	}
	if contextName != "" {
		arguments = append(arguments, "--context", contextName)
	}
	return arguments
}

func validDNSLabel(value string) bool {
	return len(value) > 0 && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validLabelKey(value string) bool {
	if value == "" || len(value) > 317 {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 2 || !validLabelName(parts[len(parts)-1]) {
		return false
	}
	return len(parts) == 1 || validDNSSubdomain(parts[0])
}

func validLabelValue(value string) bool {
	return value == "" || validLabelName(value)
}

func validLabelName(value string) bool {
	return len(value) > 0 &&
		len(value) <= 63 &&
		labelNamePattern.MatchString(value)
}

func validDNSSubdomain(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}
