package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
	"github.com/qodo-ai/qodo-support-bundle/internal/zitadel"
)

const (
	defaultLogLimit               int64 = 10 << 20
	maxLogLimit                         = kubernetes.MaximumLogBytes
	defaultTotalLogLimit          int64 = 1 << 30
	maxTotalLogLimit                    = kubernetes.MaximumTotalLogBytes
	defaultMetadataLimit          int64 = 128 << 20
	maxMetadataLimit                    = kubernetes.MaximumMetadataBytes
	defaultLogWorkers                   = 8
	maxLogWorkers                       = kubernetes.MaximumLogWorkers
	maxCustomerContextLength            = 4096
	maxCommandTimeout                   = 30 * time.Minute
	defaultProbeTimeout                 = 15 * time.Second
	defaultOutputDirectory              = "qodo-support-bundles"
	defaultOutputResolveHome            = "resolve home directory"
	defaultOutputCreateDirectory        = "create default output directory"
	defaultOutputInspectDirectory       = "inspect default output directory"
	defaultOutputSecureDirectory        = "secure default output directory"
	defaultOutputGenerateFilename       = "generate output filename"
	defaultOutputMustBeDirectory        = "default output directory must be a real directory"
	defaultOutputAbsoluteHome           = "absolute home path is required"
)

var (
	Version            = "dev"
	homeDirectory      = os.UserHomeDir
	currentTime        = time.Now
	randomOutputSuffix = func() (string, error) {
		value := make([]byte, 6)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		return hex.EncodeToString(value), nil
	}
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

// Run executes the support-bundle CLI and returns its process exit code.
func Run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "collect":
		return runCollect(ctx, arguments[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", arguments[0])
		printUsage(stderr)
		return 2
	}
}

func runCollect(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) (exitCode int) {
	flags := flag.NewFlagSet("collect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	namespace := flags.String("namespace", "", "Specific Kubernetes namespace to collect")
	namespaces := flags.String("namespaces", "", "Comma-separated Kubernetes namespaces")
	allNamespaces := flags.Bool("all-namespaces", false, "Collect every namespace")
	excludeSystemNamespaces := flags.Bool(
		"exclude-system-namespaces",
		false,
		"Exclude Kubernetes and managed GKE system namespaces",
	)
	selector := flags.String("selector", "", "Optional Kubernetes label selector")
	kubeContext := flags.String("context", "", "Optional kubeconfig context")
	kubeconfig := flags.String("kubeconfig", "", "Optional kubeconfig path")
	kubectl := flags.String("kubectl", "kubectl", "Path to kubectl-compatible binary")
	output := flags.String("output", "", "Exact output .tar.gz archive path")
	since := flags.Duration("since", 30*time.Minute, "Container log lookback")
	timeout := flags.Duration("command-timeout", 2*time.Minute, "Timeout per kubectl command")
	maxLogBytes := flags.Int64(
		"max-log-bytes",
		defaultLogLimit,
		"Maximum bytes collected from each container log",
	)
	maxTotalLogBytes := flags.Int64(
		"max-total-log-bytes",
		defaultTotalLogLimit,
		"Maximum bytes retained across all container logs",
	)
	maxMetadataBytes := flags.Int64(
		"max-metadata-bytes",
		defaultMetadataLimit,
		"Maximum bytes retained across Kubernetes metadata records",
	)
	logWorkers := flags.Int("log-workers", defaultLogWorkers, "Concurrent log readers")
	activity := flags.String("activity", "", "Customer description of current activity")
	problem := flags.String("problem", "", "Customer description of the failure")
	checkZitadel := flags.Bool(
		"check-zitadel",
		false,
		"Probe Platform-to-Zitadel connectivity in an existing container",
	)
	platformNamespace := flags.String(
		"platform-namespace",
		"",
		"Namespace of the selected Platform pod",
	)
	platformPod := flags.String("platform-pod", "", "Selected Platform pod")
	platformContainer := flags.String(
		"platform-container",
		"",
		"Selected Platform application container",
	)
	probeTimeout := flags.Duration(
		"probe-timeout",
		defaultProbeTimeout,
		"Maximum Zitadel probe execution time",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "collect does not accept positional arguments")
		return 2
	}

	visited := make(map[string]bool)
	flags.Visit(func(current *flag.Flag) { visited[current.Name] = true })
	if visited["namespace"] && visited["namespaces"] {
		_, _ = fmt.Fprintln(
			stderr,
			"--namespace and --namespaces cannot be combined",
		)
		return 2
	}
	explicitNamespaces := visited["namespace"] || visited["namespaces"]
	if *excludeSystemNamespaces && !visited["all-namespaces"] {
		_, _ = fmt.Fprintln(stderr, "--exclude-system-namespaces requires --all-namespaces")
		return 2
	}
	if !explicitNamespaces && !visited["all-namespaces"] {
		*allNamespaces = true
		if !visited["exclude-system-namespaces"] {
			*excludeSystemNamespaces = true
		}
	}
	var selectedNamespaces []string
	var err error
	if *allNamespaces {
		if explicitNamespaces {
			_, _ = fmt.Fprintln(
				stderr,
				"--all-namespaces cannot be combined with --namespace or --namespaces",
			)
			return 2
		}
	} else {
		selectedNamespaces, err = parseNamespaces(*namespace, *namespaces)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if err := validateCollectFlags(
		selectedNamespaces,
		*allNamespaces,
		*since,
		*timeout,
		*maxMetadataBytes,
		*maxLogBytes,
		*maxTotalLogBytes,
		*logWorkers,
		*activity,
		*problem,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := validateProbeFlags(
		*checkZitadel,
		visited,
		selectedNamespaces,
		*allNamespaces,
		platformNamespace,
		*platformPod,
		*platformContainer,
		*probeTimeout,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	usedDefaultOutput := false
	if *output == "" {
		usedDefaultOutput = true
		*output, err = defaultOutputPath()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
	}

	redactor := redact.New()
	if *allNamespaces {
		message := "Warning: collecting all namespaces includes non-Qodo workloads."
		if *excludeSystemNamespaces {
			message = "Scope: all application namespaces; Kubernetes system namespaces are excluded."
		}
		_, _ = fmt.Fprintln(stderr, message)
	}
	var builder *bundle.Builder
	if usedDefaultOutput {
		builder, err = bundle.New(*output, bundle.OmitAbsolutePaths())
	} else {
		builder, err = bundle.New(*output)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			closeBundle(builder, stderr, &exitCode)
		}
	}()

	resolvedKubectl, err := resolveKubectl(*kubectl)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "Using kubectl: resolved executable")
	runner := kubernetes.ExecRunner{Binary: resolvedKubectl}
	kubernetesConfig := kubernetes.Config{
		Namespaces:              selectedNamespaces,
		AllNamespaces:           *allNamespaces,
		ExcludeSystemNamespaces: *excludeSystemNamespaces,
		Selector:                *selector,
		Context:                 *kubeContext,
		Kubeconfig:              *kubeconfig,
		Since:                   *since,
		Timeout:                 *timeout,
		MaxMetadataBytes:        *maxMetadataBytes,
		MaxLogBytes:             *maxLogBytes,
		MaxTotalLogBytes:        *maxTotalLogBytes,
		LogWorkers:              *logWorkers,
		Progress: func(progress kubernetes.Progress) {
			writeCollectionProgress(stderr, redactor, progress)
		},
	}
	var zitadelConfig *zitadel.Config
	if *checkZitadel {
		zitadelConfig = &zitadel.Config{
			Namespace:    *platformNamespace,
			Pod:          *platformPod,
			Container:    *platformContainer,
			Context:      *kubeContext,
			Kubeconfig:   *kubeconfig,
			QueryTimeout: *timeout,
			ProbeTimeout: *probeTimeout,
		}
	}
	result, err := collection.Execute(
		ctx,
		collection.Request{
			CollectorVersion: Version,
			GeneratedAt:      currentTime().UTC(),
			Activity:         *activity,
			Problem:          *problem,
			Kubernetes:       kubernetesConfig,
			Zitadel:          zitadelConfig,
			Progress: func(event collection.Event) {
				writeCollectionEvent(stderr, event)
			},
		},
		runner,
		builder,
		redactor,
		collection.DefaultCollectors(),
	)
	if result.CanceledBeforeBundle {
		_, _ = fmt.Fprintln(stderr, "Collection canceled; no bundle was published.")
		return 1
	}
	if err != nil {
		if errors.Is(err, bundle.ErrCleanup) {
			_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", result.ArchivePath)
			_, _ = fmt.Fprintln(stderr, "Bundle created, but temporary data cleanup failed.")
			return 1
		}
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	cleanupPending = false

	_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", result.ArchivePath)
	_, _ = fmt.Fprintf(
		stdout,
		"Kubernetes scope: %d/%d namespaces, %d pods, %d containers (%d init, %d ephemeral)\n",
		len(result.KubernetesReport.Namespaces),
		result.KubernetesReport.NamespacesRequested,
		result.KubernetesReport.Pods,
		result.KubernetesReport.Containers,
		result.KubernetesReport.InitContainers,
		result.KubernetesReport.EphemeralContainers,
	)
	if result.Status == collection.CoveragePartial.String() {
		_, _ = fmt.Fprintln(
			stderr,
			"Warning: collection was partial; inspect collection-issues.jsonl.",
		)
		return 3
	}
	return 0
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

func defaultOutputPath() (string, error) {
	home, err := homeDirectory()
	if err != nil {
		return "", defaultOutputError(defaultOutputResolveHome, err)
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("%s: %s", defaultOutputResolveHome, defaultOutputAbsoluteHome)
	}
	directory := filepath.Join(home, defaultOutputDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", defaultOutputError(defaultOutputCreateDirectory, err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", defaultOutputError(defaultOutputInspectDirectory, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New(defaultOutputMustBeDirectory)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", defaultOutputError(defaultOutputSecureDirectory, err)
	}
	timestamp := currentTime().UTC().Format("20060102T150405Z")
	suffix, err := randomOutputSuffix()
	if err != nil {
		return "", defaultOutputError(defaultOutputGenerateFilename, err)
	}
	return filepath.Join(
		directory,
		"qodo-support-bundle-"+timestamp+"-"+suffix+".tar.gz",
	), nil
}

func defaultOutputError(operation string, err error) error {
	if cause := pathFreeCause(err); cause != "" {
		return fmt.Errorf("%s: %s", operation, cause)
	}
	return errors.New(operation)
}

func pathFreeCause(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		parts := make([]string, 0, 2)
		if pathErr.Op != "" && !strings.ContainsAny(pathErr.Op, `/\`) {
			parts = append(parts, pathErr.Op)
		}
		if pathErr.Err != nil {
			inner := pathErr.Err.Error()
			if inner != "" && !strings.ContainsAny(inner, `/\`) {
				parts = append(parts, inner)
			}
		}
		return strings.Join(parts, ": ")
	}
	message := err.Error()
	if message == "" || strings.ContainsAny(message, `/\`) {
		return ""
	}
	return message
}

func resolveKubectl(binary string) (string, error) {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("locate kubectl binary: %w", err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve kubectl binary path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve kubectl binary symlinks: %w", err)
	}
	fileInfo, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect kubectl binary: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", errors.New("kubectl binary must be a regular file")
	}
	return canonical, nil
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

func closeBundle(closer io.Closer, stderr io.Writer, exitCode *int) {
	if err := closer.Close(); err != nil {
		_, _ = fmt.Fprintln(stderr, "Failed to clean up temporary bundle data.")
		*exitCode = 1
	}
}

func terminalText(redactor *redact.Redactor, value string) string {
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, redactor.Text(value))
}

func writeCollectionEvent(writer io.Writer, event collection.Event) {
	switch event.Kind {
	case collection.EventZitadelStarted:
		_, _ = fmt.Fprintln(writer, "Checking Platform-to-Zitadel connectivity...")
	case collection.EventZitadelUnavailable:
		_, _ = fmt.Fprintf(
			writer,
			"Zitadel connectivity probe unavailable: %s\n",
			event.Reason,
		)
	case collection.EventZitadelDiagnosticFailure:
		_, _ = fmt.Fprintln(
			writer,
			"Zitadel connectivity: diagnostic failure recorded.",
		)
	case collection.EventZitadelPassed:
		_, _ = fmt.Fprintln(writer, "Zitadel connectivity: passed.")
	}
}

func writeCollectionProgress(
	writer io.Writer,
	redactor *redact.Redactor,
	progress kubernetes.Progress,
) {
	switch progress.Stage {
	case "discover_namespaces":
		_, _ = fmt.Fprintln(writer, "Discovering Kubernetes application namespaces...")
	case "namespaces_discovered":
		_, _ = fmt.Fprintf(writer, "Discovered %d namespaces.\n", progress.Total)
	case "scan_namespace":
		if progress.Current == 1 ||
			progress.Current == progress.Total ||
			progress.Current%5 == 0 {
			_, _ = fmt.Fprintf(
				writer,
				"Scanning namespace %d/%d: %s\n",
				progress.Current,
				progress.Total,
				terminalText(redactor, progress.Namespace),
			)
		}
	case "collect_logs":
		_, _ = fmt.Fprintf(
			writer,
			"Collecting %d container log streams with %d workers...\n",
			progress.Total,
			progress.Workers,
		)
	case "logs_progress":
		_, _ = fmt.Fprintf(
			writer,
			"Collected log streams: %d/%d\n",
			progress.Current,
			progress.Total,
		)
	}
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  qodo-support-bundle collect [options]
  qodo-support-bundle version
  qodo-support-bundle help

Collect bounded, redacted Kubernetes metadata, events, and container logs.
The optional --check-zitadel probe runs inside one selected Platform container.`)
}
