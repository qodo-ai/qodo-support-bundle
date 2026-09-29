// Package telemetry discovers in-cluster telemetry services and opens
// loopback-only kubectl port-forward tunnels to them.
package telemetry

import (
	"context"
	"errors"
	"time"
)

var (
	// Discovery errors are stable categories and never contain Kubernetes
	// response data, labels, endpoint addresses, or command output.
	ErrInvalidConfig      = errors.New("telemetry: invalid configuration")
	ErrDiscoveryCommand   = errors.New("telemetry: discovery command failed")
	ErrDiscoveryTimeout   = errors.New("telemetry: discovery timed out")
	ErrDiscoveryCanceled  = errors.New("telemetry: discovery canceled")
	ErrResponseTooLarge   = errors.New("telemetry: discovery response too large")
	ErrInvalidResponse    = errors.New("telemetry: invalid discovery response")
	ErrNoMatchingService  = errors.New("telemetry: no matching service")
	ErrAmbiguousService   = errors.New("telemetry: ambiguous matching services")
	ErrServiceNotReady    = errors.New("telemetry: matching service is not ready")
	ErrForwardStart       = errors.New("telemetry: port-forward failed to start")
	ErrForwardExited      = errors.New("telemetry: port-forward exited before readiness")
	ErrForwardTimeout     = errors.New("telemetry: port-forward readiness timed out")
	ErrForwardCanceled    = errors.New("telemetry: port-forward canceled")
	ErrForwardOutputLimit = errors.New("telemetry: port-forward output limit reached")
	ErrForwardCleanup     = errors.New("telemetry: port-forward cleanup failed")
	ErrForwardUnavailable = errors.New("telemetry: port-forward is unavailable")
)

// DiscoveryConfig identifies an approved service shape in one namespace.
// LabelMatchers are compared locally and are never interpolated into kubectl
// arguments.
type DiscoveryConfig struct {
	Namespace        string
	Context          string
	Kubeconfig       string
	Timeout          time.Duration
	MaxResponseBytes int64
	LabelMatchers    map[string]string
	ExpectedPort     int
}

// Target is the minimum non-sensitive result needed to open a tunnel.
type Target struct {
	Service string
	Port    int
}

// ForwardConfig controls a loopback-only kubectl port-forward.
type ForwardConfig struct {
	Namespace        string
	Context          string
	Kubeconfig       string
	ReadinessTimeout time.Duration
	MaxOutputBytes   int64
}

// Forwarder is injectable by collectors. Implementations must return only
// loopback endpoints and must tie tunnel lifetime to ctx.
type Forwarder interface {
	Forward(ctx context.Context, target Target) (*Tunnel, error)
}
