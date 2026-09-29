package app

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

func validatePrometheusFlags(
	enabled bool,
	visited map[string]bool,
	namespaces []string,
	allNamespaces bool,
	prometheusNamespace *string,
) error {
	if !enabled {
		if visited["prometheus-namespace"] {
			return errors.New("--prometheus-namespace requires --collect-prometheus")
		}
		return nil
	}
	if *prometheusNamespace == "" {
		if allNamespaces || len(namespaces) != 1 {
			return errors.New(
				"--prometheus-namespace is required when --collect-prometheus uses multiple or all namespaces",
			)
		}
		*prometheusNamespace = namespaces[0]
	}
	if !validDNSLabel(*prometheusNamespace) {
		return errors.New("--prometheus-namespace must be a Kubernetes DNS label")
	}
	return nil
}

func validateProbeFlags(
	enabled bool,
	visited map[string]bool,
	namespaces []string,
	allNamespaces bool,
	platformNamespace *string,
	pod string,
	container string,
	timeout time.Duration,
) error {
	targetVisited := visited["platform-namespace"] ||
		visited["platform-pod"] ||
		visited["platform-container"] ||
		visited["probe-timeout"]
	if !enabled {
		if targetVisited {
			return errors.New("Zitadel target flags require --check-zitadel")
		}
		return nil
	}
	if *platformNamespace == "" && !allNamespaces && len(namespaces) == 1 {
		*platformNamespace = namespaces[0]
	}
	if *platformNamespace == "" || pod == "" || container == "" {
		return errors.New(
			"--check-zitadel requires --platform-namespace, --platform-pod, and --platform-container; platform namespace is inferred only from one explicit namespace",
		)
	}
	if !validDNSLabel(*platformNamespace) {
		return errors.New("--platform-namespace must be a Kubernetes DNS label")
	}
	if !validDNSName(pod, 253) {
		return errors.New("--platform-pod must be a DNS-compatible Kubernetes name")
	}
	if !validDNSLabel(container) {
		return errors.New("--platform-container must be a Kubernetes DNS label")
	}
	if timeout <= time.Second || timeout > maxCommandTimeout {
		return fmt.Errorf("--probe-timeout must be greater than 1s and not exceed %s", maxCommandTimeout)
	}
	if !allNamespaces && !containsString(namespaces, *platformNamespace) {
		return errors.New("--platform-namespace must be included in the collection scope")
	}
	return nil
}

func validateCollectFlags(
	namespaces []string,
	allNamespaces bool,
	since time.Duration,
	timeout time.Duration,
	maxMetadataBytes int64,
	maxLogBytes int64,
	maxTotalLogBytes int64,
	logWorkers int,
	activity string,
	problem string,
) error {
	switch {
	case !allNamespaces && len(namespaces) == 0:
		return errors.New("at least one namespace is required")
	case since <= 0:
		return errors.New("--since must be positive")
	case timeout <= 0:
		return errors.New("--command-timeout must be positive")
	case timeout > maxCommandTimeout:
		return fmt.Errorf("--command-timeout must not exceed %s", maxCommandTimeout)
	case maxMetadataBytes <= 0:
		return errors.New("--max-metadata-bytes must be positive")
	case maxMetadataBytes > maxMetadataLimit:
		return fmt.Errorf(
			"--max-metadata-bytes must not exceed %d bytes",
			maxMetadataLimit,
		)
	case maxLogBytes <= 0:
		return errors.New("--max-log-bytes must be positive")
	case maxLogBytes > maxLogLimit:
		return fmt.Errorf("--max-log-bytes must not exceed %d bytes", maxLogLimit)
	case maxTotalLogBytes <= 0:
		return errors.New("--max-total-log-bytes must be positive")
	case maxTotalLogBytes > maxTotalLogLimit:
		return fmt.Errorf("--max-total-log-bytes must not exceed %d bytes", maxTotalLogLimit)
	case maxLogBytes > maxTotalLogBytes:
		return errors.New("--max-log-bytes must not exceed --max-total-log-bytes")
	case logWorkers <= 0:
		return errors.New("--log-workers must be positive")
	case logWorkers > maxLogWorkers:
		return fmt.Errorf("--log-workers must not exceed %d", maxLogWorkers)
	case len(activity) > maxCustomerContextLength || len(problem) > maxCustomerContextLength:
		return fmt.Errorf("activity and problem must not exceed %d characters", maxCustomerContextLength)
	}
	for _, namespace := range namespaces {
		if !validDNSLabel(namespace) {
			return fmt.Errorf("namespace %q must be a Kubernetes DNS label", namespace)
		}
	}
	return nil
}

func parseNamespaces(namespace string, namespaces string) ([]string, error) {
	value := namespace
	if namespaces != "" {
		value = namespaces
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, errors.New("namespace list contains an empty value")
		}
		if _, duplicate := seen[trimmed]; duplicate {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result, nil
}

func validDNSLabel(value string) bool {
	return len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validDNSName(value string, maxLength int) bool {
	if len(value) > maxLength {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
