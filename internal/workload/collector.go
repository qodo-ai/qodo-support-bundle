package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

const (
	// DefaultMaxResponseBytes bounds every Kubernetes API response before JSON parsing.
	DefaultMaxResponseBytes int64 = 8 << 20
	// DefaultMaxSourceBytes bounds normalized JSONL retained for one resource kind.
	DefaultMaxSourceBytes int64 = 4 << 20
	// DefaultMaxTotalBytes bounds all normalized workload-context JSONL artifacts.
	DefaultMaxTotalBytes int64 = 16 << 20
	// DefaultMaxNamespaces bounds namespace source matrices requested per bundle.
	DefaultMaxNamespaces = 100
	// DefaultMaxCollectionDuration bounds all workload API requests together.
	DefaultMaxCollectionDuration = 5 * time.Minute

	MaximumResponseBytes      int64 = 64 << 20
	MaximumSourceBytes        int64 = 64 << 20
	MaximumTotalBytes         int64 = 256 << 20
	MaximumNamespaces               = 1000
	MaximumCollectionDuration       = 30 * time.Minute

	apiRecordLimit = 101
)

const (
	WorkloadsArtifactPath   = "kubernetes/workloads.jsonl"
	ServicesArtifactPath    = "kubernetes/services.jsonl"
	AutoscalersArtifactPath = "kubernetes/autoscalers.jsonl"
	StorageArtifactPath     = "kubernetes/storage.jsonl"
)

// Runner is the existing bounded kubectl transport.
type Runner = kubernetes.Runner

// CommandResult is a bounded kubectl response.
type CommandResult = kubernetes.CommandResult

// Sink is the established bundle staging seam.
type Sink = kubernetes.Sink

// Config controls namespace-scoped workload collection.
type Config struct {
	Namespaces       []string
	Context          string
	Kubeconfig       string
	Timeout          time.Duration
	MaxResponseBytes int64
	MaxSourceBytes   int64
	MaxTotalBytes    int64
	MaxNamespaces    int
	MaxDuration      time.Duration
}

// CoverageState describes one namespace/resource API collection result.
type CoverageState string

const (
	CoverageCollected CoverageState = "collected"
	CoveragePartial   CoverageState = "partial"
	CoverageSkipped   CoverageState = "skipped"
	CoverageFailed    CoverageState = "failed"
)

const (
	reasonRequestFailed         = "request_failed"
	reasonResponseLimit         = "response_byte_limit_exceeded"
	reasonNormalizationFailed   = "normalization_failed"
	reasonNamespaceScope        = "namespace_scope_violation"
	reasonRecordLimit           = "record_limit_exceeded"
	reasonSourceBudget          = "source_artifact_budget_exceeded"
	reasonSourceBudgetExhausted = "source_artifact_budget_exhausted"
	reasonTotalBudget           = "total_artifact_budget_exceeded"
	reasonTotalBudgetExhausted  = "total_artifact_budget_exhausted"
	reasonArtifactStaging       = "artifact_staging_failed"
	reasonNamespaceLimit        = "namespace_request_limit_exceeded"
	reasonCollectionDeadline    = "collection_deadline_exceeded"
)

// Coverage records deterministic retained counts and truncation for one API response.
type Coverage struct {
	Namespace       string        `json:"namespace"`
	Source          string        `json:"source"`
	State           CoverageState `json:"state"`
	ArtifactPath    string        `json:"artifact_path"`
	ResponseBytes   int64         `json:"response_bytes"`
	RecordsFound    int           `json:"records_found"`
	RecordsRetained int           `json:"records_retained"`
	RetainedBytes   int64         `json:"retained_bytes"`
	Truncated       bool          `json:"truncated"`
	Reason          string        `json:"reason,omitempty"`
	Diagnostic      string        `json:"diagnostic,omitempty"`
}

// Artifact reports one staged normalized JSONL file.
type Artifact struct {
	Path    string `json:"path"`
	Records int    `json:"records"`
	Bytes   int64  `json:"bytes"`
}

// Report summarizes workload-context collection without retaining raw responses.
type Report struct {
	Namespaces       []string   `json:"namespaces"`
	Coverage         []Coverage `json:"coverage"`
	Artifacts        []Artifact `json:"artifacts,omitempty"`
	MaxResponseBytes int64      `json:"max_response_bytes"`
	MaxSourceBytes   int64      `json:"max_source_bytes"`
	MaxTotalBytes    int64      `json:"max_total_bytes"`
	MaxNamespaces    int        `json:"max_namespaces"`
	MaxDuration      string     `json:"max_duration"`
	RetainedRecords  int        `json:"retained_records"`
	RetainedBytes    int64      `json:"retained_bytes"`
	Truncated        bool       `json:"truncated"`
}

type normalizedRecord struct {
	key  string
	data []byte
}

type normalizeSource func([]byte, *redact.Redactor) ([]normalizedRecord, int, bool, error)

type sourceSpec struct {
	name         string
	apiPath      func(string) string
	artifactPath string
	normalize    normalizeSource
}

// Collect reads the approved namespaced Kubernetes APIs, normalizes and redacts
// their responses, and stages only bounded JSONL artifacts.
func Collect(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
) (Report, error) {
	report, namespaces, err := validateCollection(ctx, config, runner, sink, redactor)
	if err != nil {
		return report, err
	}
	collectionCtx, cancel := context.WithTimeout(ctx, config.MaxDuration)
	defer cancel()

	specs := sourceSpecs()
	sourceRemaining := make(map[string]int64, len(specs))
	for _, spec := range specs {
		sourceRemaining[spec.name] = config.MaxSourceBytes
	}
	totalRemaining := config.MaxTotalBytes
	recordsByArtifact := make(map[string][]normalizedRecord, 4)

	for namespaceIndex, namespace := range namespaces {
		for _, spec := range specs {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			coverage := Coverage{
				Namespace:    namespace,
				Source:       spec.name,
				ArtifactPath: spec.artifactPath,
			}
			if namespaceIndex >= config.MaxNamespaces {
				coverage.State = CoverageSkipped
				coverage.Truncated = true
				coverage.Reason = reasonNamespaceLimit
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			if collectionCtx.Err() != nil {
				coverage.State = CoverageSkipped
				coverage.Truncated = true
				coverage.Reason = reasonCollectionDeadline
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			if sourceRemaining[spec.name] == 0 {
				coverage.State = CoverageSkipped
				coverage.Truncated = true
				coverage.Reason = reasonSourceBudgetExhausted
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			if totalRemaining == 0 {
				coverage.State = CoverageSkipped
				coverage.Truncated = true
				coverage.Reason = reasonTotalBudgetExhausted
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}

			result, runErr := runAPIRequest(
				collectionCtx,
				config,
				runner,
				spec.apiPath(namespace),
			)
			coverage.ResponseBytes = int64(len(result.Stdout))
			if err := ctx.Err(); err != nil {
				return report, err
			}
			if collectionCtx.Err() != nil {
				coverage.State = CoverageFailed
				coverage.Truncated = true
				coverage.Reason = reasonCollectionDeadline
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			if result.Truncated {
				coverage.State = CoverageFailed
				coverage.Truncated = true
				coverage.Reason = reasonResponseLimit
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			if runErr != nil {
				coverage.State = CoverageFailed
				coverage.Reason = reasonRequestFailed
				coverage.Diagnostic = requestDiagnostic(result, runErr)
				report.Coverage = append(report.Coverage, coverage)
				continue
			}

			records, recordsFound, normalizedTruncated, normalizeErr := spec.normalize(
				result.Stdout,
				redactor,
			)
			if normalizeErr != nil {
				coverage.State = CoverageFailed
				coverage.Reason = reasonNormalizationFailed
				report.Coverage = append(report.Coverage, coverage)
				continue
			}
			if collectionCtx.Err() != nil {
				coverage.State = CoverageFailed
				coverage.Truncated = true
				coverage.Reason = reasonCollectionDeadline
				report.Coverage = append(report.Coverage, coverage)
				report.Truncated = true
				continue
			}
			sort.Slice(records, func(left, right int) bool {
				return records[left].key < records[right].key
			})
			coverage.RecordsFound = recordsFound
			if !recordsInNamespace(records, namespace) {
				coverage.State = CoverageFailed
				coverage.Reason = reasonNamespaceScope
				report.Coverage = append(report.Coverage, coverage)
				continue
			}

			coverage.State = CoverageCollected
			if normalizedTruncated {
				coverage.State = CoveragePartial
				coverage.Truncated = true
				coverage.Reason = reasonRecordLimit
			}
			for _, record := range records {
				if collectionCtx.Err() != nil {
					coverage.State = CoveragePartial
					coverage.Truncated = true
					coverage.Reason = reasonCollectionDeadline
					break
				}
				recordBytes := int64(len(record.data))
				switch {
				case recordBytes > sourceRemaining[spec.name]:
					coverage.State = CoveragePartial
					coverage.Truncated = true
					coverage.Reason = reasonSourceBudget
				case recordBytes > totalRemaining:
					coverage.State = CoveragePartial
					coverage.Truncated = true
					coverage.Reason = reasonTotalBudget
				default:
					recordsByArtifact[spec.artifactPath] = append(
						recordsByArtifact[spec.artifactPath],
						record,
					)
					sourceRemaining[spec.name] -= recordBytes
					totalRemaining -= recordBytes
					coverage.RecordsRetained++
					coverage.RetainedBytes += recordBytes
					report.RetainedRecords++
					report.RetainedBytes += recordBytes
					continue
				}
				break
			}
			if coverage.Truncated {
				report.Truncated = true
			}
			report.Coverage = append(report.Coverage, coverage)
		}
	}

	if err := stageArtifacts(collectionCtx, sink, recordsByArtifact, &report); err != nil {
		return report, err
	}
	return report, nil
}

func validateCollection(
	ctx context.Context,
	config Config,
	runner Runner,
	sink Sink,
	redactor *redact.Redactor,
) (Report, []string, error) {
	report := Report{
		MaxResponseBytes: config.MaxResponseBytes,
		MaxSourceBytes:   config.MaxSourceBytes,
		MaxTotalBytes:    config.MaxTotalBytes,
		MaxNamespaces:    config.MaxNamespaces,
		MaxDuration:      config.MaxDuration.String(),
	}
	switch {
	case ctx == nil:
		return report, nil, errors.New("collection context is required")
	case ctx.Err() != nil:
		return report, nil, ctx.Err()
	case runner == nil:
		return report, nil, errors.New("Kubernetes runner is required")
	case sink == nil:
		return report, nil, errors.New("bundle sink is required")
	case redactor == nil || !redactor.Ready():
		return report, nil, errors.New("configured redactor is required")
	case config.Timeout <= 0:
		return report, nil, errors.New("request timeout must be positive")
	case config.MaxResponseBytes <= 0 || config.MaxResponseBytes > MaximumResponseBytes:
		return report, nil, fmt.Errorf(
			"max response bytes must be between 1 and %d",
			MaximumResponseBytes,
		)
	case config.MaxSourceBytes <= 0 || config.MaxSourceBytes > MaximumSourceBytes:
		return report, nil, fmt.Errorf(
			"max source bytes must be between 1 and %d",
			MaximumSourceBytes,
		)
	case config.MaxTotalBytes <= 0 || config.MaxTotalBytes > MaximumTotalBytes:
		return report, nil, fmt.Errorf(
			"max total bytes must be between 1 and %d",
			MaximumTotalBytes,
		)
	case config.MaxSourceBytes > config.MaxTotalBytes:
		return report, nil, errors.New("max source bytes must not exceed max total bytes")
	case config.MaxNamespaces <= 0 || config.MaxNamespaces > MaximumNamespaces:
		return report, nil, fmt.Errorf(
			"max namespaces must be between 1 and %d",
			MaximumNamespaces,
		)
	case config.MaxDuration <= 0 || config.MaxDuration > MaximumCollectionDuration:
		return report, nil, fmt.Errorf(
			"max collection duration must be between 1ns and %s",
			MaximumCollectionDuration,
		)
	}

	namespaces, err := normalizedNamespaces(config.Namespaces)
	if err != nil {
		return report, nil, err
	}
	report.Namespaces = append([]string(nil), namespaces...)
	return report, namespaces, nil
}

func normalizedNamespaces(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one namespace is required")
	}
	seen := make(map[string]struct{}, len(values))
	namespaces := make([]string, 0, len(values))
	for _, value := range values {
		namespace := strings.TrimSpace(value)
		if !validDNSSubdomain(namespace) {
			return nil, fmt.Errorf("invalid Kubernetes namespace %q", namespace)
		}
		if _, exists := seen[namespace]; exists {
			continue
		}
		seen[namespace] = struct{}{}
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

func validDNSSubdomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!asciiLowerOrDigit(label[0]) ||
			!asciiLowerOrDigit(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiLowerOrDigit(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiLowerOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func runAPIRequest(
	parent context.Context,
	config Config,
	runner Runner,
	apiPath string,
) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(parent, config.Timeout)
	defer cancel()
	arguments := make([]string, 0, 7)
	if config.Kubeconfig != "" {
		arguments = append(arguments, "--kubeconfig", config.Kubeconfig)
	}
	if config.Context != "" {
		arguments = append(arguments, "--context", config.Context)
	}
	arguments = append(arguments, "get", "--raw", apiPath)
	result, err := runner.Run(ctx, config.MaxResponseBytes, arguments...)
	if parent.Err() != nil {
		return result, parent.Err()
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("Kubernetes API request timed out after %s: %w", config.Timeout, ctx.Err())
	}
	return result, err
}

func requestDiagnostic(
	result CommandResult,
	requestErr error,
) string {
	message := strings.TrimSpace(string(result.Stderr))
	if message == "" && requestErr != nil {
		message = requestErr.Error()
	}
	message = strings.ToLower(strings.ToValidUTF8(message, " "))
	switch {
	case strings.Contains(message, "forbidden"),
		strings.Contains(message, "permission denied"),
		strings.Contains(message, "access denied"):
		return "access forbidden"
	case strings.Contains(message, "unauthorized"),
		strings.Contains(message, "authentication required"):
		return "authentication required"
	case strings.Contains(message, "too many requests"),
		strings.Contains(message, "rate limit"):
		return "Kubernetes API rate limited"
	case strings.Contains(message, "deadline exceeded"),
		strings.Contains(message, "timed out"),
		strings.Contains(message, "timeout"):
		return "request timed out"
	case strings.Contains(message, "not found"),
		strings.Contains(message, "the server could not find the requested resource"):
		return "resource or API not found"
	case strings.Contains(message, "connection refused"),
		strings.Contains(message, "no route to host"),
		strings.Contains(message, "service unavailable"):
		return "Kubernetes API unavailable"
	case strings.Contains(message, "x509"),
		strings.Contains(message, "tls handshake"):
		return "Kubernetes API TLS verification failed"
	default:
		return "request failed"
	}
}

func sourceSpecs() []sourceSpec {
	namespaced := func(groupPath string) func(string) string {
		return func(namespace string) string {
			return fmt.Sprintf(
				"%s/namespaces/%s?limit=%d",
				groupPath,
				url.PathEscape(namespace),
				apiRecordLimit,
			)
		}
	}
	return []sourceSpec{
		workloadSource("deployments", namespaced("/apis/apps/v1"), "deployments", DeploymentKind),
		workloadSource("statefulsets", namespaced("/apis/apps/v1"), "statefulsets", StatefulSetKind),
		workloadSource("daemonsets", namespaced("/apis/apps/v1"), "daemonsets", DaemonSetKind),
		workloadSource("jobs", namespaced("/apis/batch/v1"), "jobs", JobKind),
		workloadSource("cronjobs", namespaced("/apis/batch/v1"), "cronjobs", CronJobKind),
		{
			name:         "services",
			apiPath:      resourcePath(namespaced("/api/v1"), "services"),
			artifactPath: ServicesArtifactPath,
			normalize: func(data []byte, redactor *redact.Redactor) ([]normalizedRecord, int, bool, error) {
				result, err := NormalizeServiceListJSON(data, redactor)
				return marshalNormalized(
					result.Services,
					result.RecordsFound,
					result.Truncated,
					err,
				)
			},
		},
		{
			name: "endpointslices",
			apiPath: resourcePath(
				namespaced("/apis/discovery.k8s.io/v1"),
				"endpointslices",
			),
			artifactPath: ServicesArtifactPath,
			normalize: func(data []byte, redactor *redact.Redactor) ([]normalizedRecord, int, bool, error) {
				result, err := NormalizeEndpointSliceListJSON(data, redactor)
				return marshalNormalized(
					result.EndpointSlices,
					result.RecordsFound,
					result.Truncated,
					err,
				)
			},
		},
		{
			name: "horizontalpodautoscalers",
			apiPath: resourcePath(
				namespaced("/apis/autoscaling/v2"),
				"horizontalpodautoscalers",
			),
			artifactPath: AutoscalersArtifactPath,
			normalize: func(data []byte, redactor *redact.Redactor) ([]normalizedRecord, int, bool, error) {
				result, err := NormalizeHorizontalPodAutoscalerListJSON(data, redactor)
				return marshalNormalized(
					result.Autoscalers,
					result.RecordsFound,
					result.Truncated,
					err,
				)
			},
		},
		{
			name:         "persistentvolumeclaims",
			apiPath:      resourcePath(namespaced("/api/v1"), "persistentvolumeclaims"),
			artifactPath: StorageArtifactPath,
			normalize: func(data []byte, redactor *redact.Redactor) ([]normalizedRecord, int, bool, error) {
				result, err := NormalizePersistentVolumeClaimListJSON(data, redactor)
				return marshalNormalized(
					result.Storage,
					result.RecordsFound,
					result.Truncated,
					err,
				)
			},
		},
	}
}

// ValidateCompleteCoverage requires exactly one successful, nontruncated entry
// for every requested namespace and supported workload-context API source.
func ValidateCompleteCoverage(report Report) error {
	if report.Truncated {
		return errors.New("workload report is truncated")
	}
	namespaces := make(map[string]struct{}, len(report.Namespaces))
	for _, namespace := range report.Namespaces {
		if !validDNSSubdomain(namespace) {
			return fmt.Errorf("invalid report namespace %q", namespace)
		}
		if _, duplicate := namespaces[namespace]; duplicate {
			return fmt.Errorf("duplicate report namespace %q", namespace)
		}
		namespaces[namespace] = struct{}{}
	}
	if len(namespaces) == 0 {
		return errors.New("workload report has no namespaces")
	}

	specs := sourceSpecs()
	expectedSources := make(map[string]string, len(specs))
	for _, spec := range specs {
		expectedSources[spec.name] = spec.artifactPath
	}
	expectedEntries := len(namespaces) * len(expectedSources)
	if len(report.Coverage) != expectedEntries {
		return fmt.Errorf(
			"workload coverage has %d entries, want %d",
			len(report.Coverage),
			expectedEntries,
		)
	}

	seen := make(map[string]struct{}, expectedEntries)
	retainedRecords := 0
	var retainedBytes int64
	for _, entry := range report.Coverage {
		if _, expected := namespaces[entry.Namespace]; !expected {
			return fmt.Errorf("unknown workload coverage namespace %q", entry.Namespace)
		}
		artifactPath, expected := expectedSources[entry.Source]
		if !expected {
			return fmt.Errorf("unknown workload coverage source %q", entry.Source)
		}
		pair := entry.Namespace + "\x00" + entry.Source
		if _, duplicate := seen[pair]; duplicate {
			return fmt.Errorf(
				"duplicate workload coverage pair %q/%q",
				entry.Namespace,
				entry.Source,
			)
		}
		seen[pair] = struct{}{}
		if entry.ArtifactPath != artifactPath {
			return fmt.Errorf(
				"workload coverage artifact for %q is %q, want %q",
				entry.Source,
				entry.ArtifactPath,
				artifactPath,
			)
		}
		if entry.State != CoverageCollected ||
			entry.Truncated ||
			entry.Reason != "" ||
			entry.Diagnostic != "" {
			return fmt.Errorf(
				"incomplete workload coverage for %q/%q",
				entry.Namespace,
				entry.Source,
			)
		}
		if entry.RecordsFound < 0 ||
			entry.RecordsRetained < 0 ||
			entry.RecordsRetained != entry.RecordsFound ||
			entry.RetainedBytes < 0 ||
			entry.RecordsRetained == 0 && entry.RetainedBytes != 0 {
			return fmt.Errorf(
				"invalid workload coverage counts for %q/%q",
				entry.Namespace,
				entry.Source,
			)
		}
		retainedRecords += entry.RecordsRetained
		retainedBytes += entry.RetainedBytes
	}
	if report.RetainedRecords != retainedRecords ||
		int64(report.RetainedBytes) != retainedBytes {
		return fmt.Errorf(
			"workload report retained totals are %d records/%d bytes, want %d records/%d bytes",
			report.RetainedRecords,
			report.RetainedBytes,
			retainedRecords,
			retainedBytes,
		)
	}
	return nil
}

func resourcePath(base func(string) string, resource string) func(string) string {
	return func(namespace string) string {
		value := base(namespace)
		query := strings.IndexByte(value, '?')
		return value[:query] + "/" + resource + value[query:]
	}
}

func workloadSource(
	name string,
	base func(string) string,
	resource string,
	kind Kind,
) sourceSpec {
	return sourceSpec{
		name:         name,
		apiPath:      resourcePath(base, resource),
		artifactPath: WorkloadsArtifactPath,
		normalize: func(data []byte, redactor *redact.Redactor) ([]normalizedRecord, int, bool, error) {
			result, err := NormalizeListJSON(kind, data, redactor)
			return marshalNormalized(
				result.Workloads,
				result.RecordsFound,
				result.Truncated,
				err,
			)
		},
	}
}

func marshalNormalized[T interface{ resourceIdentity() Resource }](
	values []T,
	recordsFound int,
	truncated bool,
	normalizeErr error,
) ([]normalizedRecord, int, bool, error) {
	if normalizeErr != nil {
		return nil, 0, false, normalizeErr
	}
	records := make([]normalizedRecord, 0, len(values))
	for _, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, 0, false, fmt.Errorf("encode normalized record: %w", err)
		}
		data = append(data, '\n')
		resource := value.resourceIdentity()
		records = append(records, normalizedRecord{
			key:  resource.Kind + "\x00" + resource.Namespace + "\x00" + resource.Name,
			data: data,
		})
	}
	return records, recordsFound, truncated, nil
}

func recordsInNamespace(records []normalizedRecord, namespace string) bool {
	marker := "\x00" + namespace + "\x00"
	for _, record := range records {
		if !strings.Contains(record.key, marker) {
			return false
		}
	}
	return true
}

func stageArtifacts(
	ctx context.Context,
	sink Sink,
	recordsByArtifact map[string][]normalizedRecord,
	report *Report,
) error {
	paths := []string{
		WorkloadsArtifactPath,
		ServicesArtifactPath,
		AutoscalersArtifactPath,
		StorageArtifactPath,
	}
	staged := make(map[string]struct{}, len(paths))
	for pathIndex, artifactPath := range paths {
		if err := ctx.Err(); err != nil {
			reconcileUnstagedArtifacts(report, paths[pathIndex:])
			return err
		}
		if err := validateArtifactPath(artifactPath); err != nil {
			reconcileUnstagedArtifacts(report, paths[pathIndex:])
			return err
		}
		if _, duplicate := staged[artifactPath]; duplicate {
			reconcileUnstagedArtifacts(report, paths[pathIndex:])
			return fmt.Errorf("duplicate workload artifact path %q", artifactPath)
		}
		staged[artifactPath] = struct{}{}
		records := recordsByArtifact[artifactPath]
		if len(records) == 0 {
			continue
		}
		sort.Slice(records, func(left, right int) bool {
			return records[left].key < records[right].key
		})
		var data bytes.Buffer
		for _, record := range records {
			_, _ = data.Write(record.data)
		}
		if err := sink.Add(artifactPath, data.Bytes()); err != nil {
			reconcileUnstagedArtifacts(report, paths[pathIndex:])
			return fmt.Errorf("stage normalized workload artifact %q: %w", artifactPath, err)
		}
		report.Artifacts = append(report.Artifacts, Artifact{
			Path:    artifactPath,
			Records: len(records),
			Bytes:   int64(data.Len()),
		})
	}
	return nil
}

func reconcileUnstagedArtifacts(report *Report, paths []string) {
	unstaged := make(map[string]struct{}, len(paths))
	for _, artifactPath := range paths {
		unstaged[artifactPath] = struct{}{}
	}
	for index := range report.Coverage {
		coverage := &report.Coverage[index]
		if _, affected := unstaged[coverage.ArtifactPath]; !affected ||
			coverage.RecordsRetained == 0 {
			continue
		}
		coverage.RecordsRetained = 0
		coverage.RetainedBytes = 0
		coverage.State = CoveragePartial
		coverage.Truncated = true
		coverage.Reason = reasonArtifactStaging
	}
	report.RetainedRecords = 0
	report.RetainedBytes = 0
	for _, coverage := range report.Coverage {
		report.RetainedRecords += coverage.RecordsRetained
		report.RetainedBytes += coverage.RetainedBytes
	}
	report.Truncated = true
}

func validateArtifactPath(value string) error {
	if value == "" || strings.Contains(value, `\`) || path.IsAbs(value) ||
		path.Clean(value) != value ||
		value == ".." || strings.HasPrefix(value, "../") ||
		!strings.HasPrefix(value, "kubernetes/") {
		return fmt.Errorf("invalid workload artifact path %q", value)
	}
	return nil
}
