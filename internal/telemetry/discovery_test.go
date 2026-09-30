package telemetry

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
)

type discoveryCall struct {
	maxBytes  int64
	arguments []string
	deadline  time.Time
}

type discoveryRunner struct {
	calls   []discoveryCall
	service kubernetes.CommandResult
	slices  kubernetes.CommandResult
	err     error
}

func (runner *discoveryRunner) Run(
	ctx context.Context,
	maxBytes int64,
	arguments ...string,
) (kubernetes.CommandResult, error) {
	deadline, _ := ctx.Deadline()
	runner.calls = append(runner.calls, discoveryCall{
		maxBytes:  maxBytes,
		arguments: append([]string(nil), arguments...),
		deadline:  deadline,
	})
	if containsArgument(arguments, "services") {
		return runner.service, runner.err
	}
	return runner.slices, runner.err
}

func TestDiscoverValidServiceUsesNamespaceScopedBoundedQueries(t *testing.T) {
	t.Parallel()
	runner := &discoveryRunner{
		service: result(serviceList(
			serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			serviceJSON("wrong-label", "observability", "app", "other", 9090),
			serviceJSON("wrong-port", "observability", "app", "prometheus", 8080),
		)),
		slices: result(endpointSliceList(
			endpointSliceJSON(
				"prometheus-abcde",
				"observability",
				"prometheus",
				true,
				`["10.0.0.8"]`,
			),
		)),
	}
	config := validDiscoveryConfig()
	config.Context = "customer"
	config.Kubeconfig = "/tmp/kube config"

	target, err := Discover(context.Background(), config, runner)

	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if target != (Target{Service: "prometheus", Port: 9090}) {
		t.Fatalf("target = %+v", target)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	wantServiceArgs := []string{
		"--kubeconfig", "/tmp/kube config",
		"--context", "customer",
		"get", "services",
		"--namespace", "observability",
		"--output", "json",
	}
	if !reflect.DeepEqual(runner.calls[0].arguments, wantServiceArgs) {
		t.Fatalf("service arguments = %#v", runner.calls[0].arguments)
	}
	wantSliceArgs := []string{
		"--kubeconfig", "/tmp/kube config",
		"--context", "customer",
		"get", "endpointslices.discovery.k8s.io",
		"--namespace", "observability",
		"--output", "json",
	}
	if !reflect.DeepEqual(runner.calls[1].arguments, wantSliceArgs) {
		t.Fatalf("slice arguments = %#v", runner.calls[1].arguments)
	}
	for _, call := range runner.calls {
		if call.maxBytes != config.MaxResponseBytes {
			t.Fatalf("max bytes = %d", call.maxBytes)
		}
		if call.deadline.IsZero() || time.Until(call.deadline) > config.Timeout {
			t.Fatalf("unbounded deadline = %v", call.deadline)
		}
		joined := strings.Join(call.arguments, " ")
		if strings.Contains(joined, "secret") ||
			strings.Contains(joined, "configmap") ||
			strings.Contains(joined, "10.0.0.8") {
			t.Fatalf("unsafe discovery arguments = %q", joined)
		}
	}
}

func TestDiscoverAcceptsKubectlGenericListEnvelopes(t *testing.T) {
	t.Parallel()
	runner := &discoveryRunner{
		service: result(genericList(
			serviceJSON("phoenix", "observability", "app", "phoenix", 6006),
		)),
		slices: result(genericList(
			endpointSliceJSON(
				"phoenix-abcde",
				"observability",
				"phoenix",
				true,
				`["10.0.0.8"]`,
			),
		)),
	}
	config := validDiscoveryConfig()
	config.LabelMatchers = map[string]string{"app": "phoenix"}
	config.ExpectedPort = 6006

	target, err := Discover(context.Background(), config, runner)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if target != (Target{Service: "phoenix", Port: 6006}) {
		t.Fatalf("target = %+v", target)
	}
}

func TestDiscoverReturnsStableCandidateErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		services string
		slices   string
		want     error
	}{
		{
			name: "zero",
			services: serviceList(
				serviceJSON("other", "observability", "app", "other", 9090),
			),
			slices: endpointSliceList(),
			want:   ErrNoMatchingService,
		},
		{
			name: "not ready",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					false,
					`["private-address-canary"]`,
				),
			),
			want: ErrServiceNotReady,
		},
		{
			name: "ready but no addresses",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					true,
					`[]`,
				),
			),
			want: ErrServiceNotReady,
		},
		{
			name: "ambiguous",
			services: serviceList(
				serviceJSON("prometheus-a", "observability", "app", "prometheus", 9090),
				serviceJSON("prometheus-b", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-a-abcde",
					"observability",
					"prometheus-a",
					true,
					`["private-a"]`,
				),
				endpointSliceJSON(
					"prometheus-b-abcde",
					"observability",
					"prometheus-b",
					true,
					`["private-b"]`,
				),
			),
			want: ErrAmbiguousService,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &discoveryRunner{
				service: result(test.services),
				slices:  result(test.slices),
			}

			target, err := Discover(
				context.Background(),
				validDiscoveryConfig(),
				runner,
			)

			if target != (Target{}) || !errors.Is(err, test.want) {
				t.Fatalf("target=%+v error=%v, want %v", target, err, test.want)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatalf("error leaked endpoint data: %v", err)
			}
		})
	}
}

func TestDiscoverSelectsTheOnlyReadyApprovedService(t *testing.T) {
	t.Parallel()
	runner := &discoveryRunner{
		service: result(serviceList(
			serviceJSON("prometheus-a", "observability", "app", "prometheus", 9090),
			serviceJSON("prometheus-b", "observability", "app", "prometheus", 9090),
		)),
		slices: result(endpointSliceList(
			endpointSliceJSON(
				"prometheus-a-abcde",
				"observability",
				"prometheus-a",
				false,
				`["private-a"]`,
			),
			endpointSliceJSON(
				"prometheus-b-abcde",
				"observability",
				"prometheus-b",
				true,
				`["private-b"]`,
			),
		)),
	}

	target, err := Discover(
		context.Background(),
		validDiscoveryConfig(),
		runner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if target != (Target{Service: "prometheus-b", Port: 9090}) {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestDiscoverRejectsInvalidAndUnknownResponseShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		services string
		slices   string
	}{
		{
			name:     "malformed services",
			services: `{"apiVersion":"v1","kind":"ServiceList","items":[`,
		},
		{
			name: "wrong service kind",
			services: `{"apiVersion":"v1","kind":"SecretList",` +
				`"items":[]}`,
		},
		{
			name:     "missing service items",
			services: `{"apiVersion":"v1","kind":"ServiceList"}`,
		},
		{
			name: "wrong endpoint slice version",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: `{"apiVersion":"discovery.k8s.io/v9",` +
				`"kind":"EndpointSliceList","items":[]}`,
		},
		{
			name: "malformed addresses",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					true,
					`{"private":"canary"}`,
				),
			),
		},
		{
			name: "null address",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					true,
					`[null]`,
				),
			),
		},
		{
			name: "empty address",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					true,
					`[""]`,
				),
			),
		},
		{
			name: "invalid address",
			services: serviceList(
				serviceJSON("prometheus", "observability", "app", "prometheus", 9090),
			),
			slices: endpointSliceList(
				endpointSliceJSON(
					"prometheus-abcde",
					"observability",
					"prometheus",
					true,
					`["bad address"]`,
				),
			),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &discoveryRunner{
				service: result(test.services),
				slices:  result(test.slices),
			}

			_, err := Discover(context.Background(), validDiscoveryConfig(), runner)

			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "private") ||
				strings.Contains(err.Error(), "Secret") {
				t.Fatalf("error leaked response data: %v", err)
			}
		})
	}
}

func TestDiscoverRejectsTruncatedAndOversizedResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result kubernetes.CommandResult
	}{
		{
			name: "runner reported truncation",
			result: kubernetes.CommandResult{
				Stdout:    []byte(`{"private":"canary"}`),
				Truncated: true,
			},
		},
		{
			name: "runner exceeded bound",
			result: kubernetes.CommandResult{
				Stdout: []byte(strings.Repeat("x", 257)),
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validDiscoveryConfig()
			config.MaxResponseBytes = 256
			runner := &discoveryRunner{service: test.result}

			_, err := Discover(context.Background(), config, runner)

			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("error leaked response data: %v", err)
			}
		})
	}
}

func TestDiscoverValidatesNamespaceLabelsAndPortBeforeRunning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*DiscoveryConfig)
	}{
		{
			name: "invalid namespace",
			mutate: func(config *DiscoveryConfig) {
				config.Namespace = "../all"
			},
		},
		{
			name: "empty matchers",
			mutate: func(config *DiscoveryConfig) {
				config.LabelMatchers = nil
			},
		},
		{
			name: "invalid label",
			mutate: func(config *DiscoveryConfig) {
				config.LabelMatchers = map[string]string{"bad label": "value"}
			},
		},
		{
			name: "zero port",
			mutate: func(config *DiscoveryConfig) {
				config.ExpectedPort = 0
			},
		},
		{
			name: "large port",
			mutate: func(config *DiscoveryConfig) {
				config.ExpectedPort = 65536
			},
		},
		{
			name: "no timeout",
			mutate: func(config *DiscoveryConfig) {
				config.Timeout = 0
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validDiscoveryConfig()
			test.mutate(&config)
			runner := &discoveryRunner{}

			_, err := Discover(context.Background(), config, runner)

			if !errors.Is(err, ErrInvalidConfig) || len(runner.calls) != 0 {
				t.Fatalf("error=%v calls=%d", err, len(runner.calls))
			}
		})
	}
}

func validDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		Namespace:        "observability",
		Timeout:          time.Second,
		MaxResponseBytes: 1 << 20,
		LabelMatchers:    map[string]string{"app": "prometheus"},
		ExpectedPort:     9090,
	}
}

func result(data string) kubernetes.CommandResult {
	return kubernetes.CommandResult{Stdout: []byte(data)}
}

func serviceList(items ...string) string {
	return `{"apiVersion":"v1","kind":"ServiceList","items":[` +
		strings.Join(items, ",") + `]}`
}

func serviceJSON(
	name string,
	namespace string,
	labelKey string,
	labelValue string,
	port int,
) string {
	return `{"metadata":{"name":"` + name +
		`","namespace":"` + namespace +
		`","labels":{"` + labelKey + `":"` + labelValue +
		`"}},"spec":{"ports":[{"port":` +
		strconvItoa(port) + `}]}}`
}

func endpointSliceList(items ...string) string {
	return `{"apiVersion":"discovery.k8s.io/v1",` +
		`"kind":"EndpointSliceList","items":[` +
		strings.Join(items, ",") + `]}`
}

func genericList(items ...string) string {
	return `{"apiVersion":"v1","kind":"List","items":[` +
		strings.Join(items, ",") + `]}`
}

func endpointSliceJSON(
	name string,
	namespace string,
	service string,
	ready bool,
	addresses string,
) string {
	return `{"metadata":{"name":"` + name +
		`","namespace":"` + namespace +
		`","labels":{"kubernetes.io/service-name":"` + service +
		`"}},"endpoints":[{"conditions":{"ready":` +
		strconvBool(ready) + `},"addresses":` + addresses + `}]}`
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}

func strconvItoa(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = digits[value%10]
		value /= 10
	}
	return string(buffer[index:])
}

func strconvBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
