package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/bundle"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/har"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/kubernetes"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/redact"
	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/viewer"
)

const (
	defaultHARLimit          int64 = 256 << 20
	maxHARLimit              int64 = 4 << 30
	defaultLogLimit          int64 = 10 << 20
	maxLogLimit                    = kubernetes.MaximumLogBytes
	defaultTotalLogLimit     int64 = 1 << 30
	maxTotalLogLimit               = kubernetes.MaximumTotalLogBytes
	defaultLogWorkers              = 8
	maxLogWorkers                  = kubernetes.MaximumLogWorkers
	defaultMaxHAREntries           = 100_000
	maxHAREntryLimit               = 1_000_000
	collectionStatusComplete       = "complete"
	collectionStatusPartial        = "partial"
)

// Version is replaced during release builds.
var Version = "dev"

// Run executes the support-bundle CLI and returns its process exit code.
func Run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "collect":
		return runCollect(ctx, arguments[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, arguments[1:], stdout, stderr)
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

func runServe(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String(
		"listen",
		"127.0.0.1:0",
		"Loopback address for the local viewer",
	)
	noOpen := flags.Bool("no-open", false, "Do not open the system browser")
	maxArchiveBytes := flags.Int64(
		"max-archive-bytes",
		viewer.DefaultMaxArchiveBytes,
		"Maximum accepted compressed bundle size",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "serve requires exactly one bundle path")
		return 2
	}
	if *maxArchiveBytes <= 0 {
		_, _ = fmt.Fprintln(stderr, "max-archive-bytes must be positive")
		return 2
	}

	err := viewer.Serve(ctx, viewer.Config{
		BundlePath:    flags.Arg(0),
		ListenAddress: *listenAddress,
		OpenBrowser:   !*noOpen,
		Output:        stdout,
		ErrorOutput:   stderr,
		Limits: viewer.ExtractionLimits{
			MaxArchiveBytes: *maxArchiveBytes,
		},
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, redact.New().Text(err.Error()))
		return 1
	}
	return 0
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
	namespaces := flags.String(
		"namespaces",
		"",
		"Comma-separated Kubernetes namespaces; overrides --namespace",
	)
	allNamespaces := flags.Bool(
		"all-namespaces",
		false,
		"Collect every namespace in the current cluster",
	)
	excludeSystemNamespaces := flags.Bool(
		"exclude-system-namespaces",
		false,
		"Exclude Kubernetes and managed GKE control-plane namespaces",
	)
	selector := flags.String("selector", "", "Optional Kubernetes label selector")
	kubeContext := flags.String("context", "", "Optional kubeconfig context")
	kubeconfig := flags.String("kubeconfig", "", "Optional kubeconfig path")
	kubectl := flags.String("kubectl", "kubectl", "Path to kubectl-compatible binary")
	harPath := flags.String("har", "", "Path to a browser-exported HAR file")
	output := flags.String("output", defaultOutputPath(), "Output .tar.gz path")
	since := flags.Duration("since", 30*time.Minute, "Container log lookback")
	timeout := flags.Duration("command-timeout", 2*time.Minute, "Timeout per kubectl command")
	maxLogBytes := flags.Int64(
		"max-log-bytes",
		defaultLogLimit,
		"Maximum bytes collected from each container log (up to 100 MiB)",
	)
	maxTotalLogBytes := flags.Int64(
		"max-total-log-bytes",
		defaultTotalLogLimit,
		"Maximum bytes retained across all container logs (up to 8 GiB)",
	)
	logWorkers := flags.Int(
		"log-workers",
		defaultLogWorkers,
		"Concurrent container log reads (up to 64)",
	)
	maxHARBytes := flags.Int64(
		"max-har-bytes",
		defaultHARLimit,
		"Maximum accepted HAR file size (up to 4 GiB)",
	)
	maxHAREntries := flags.Int(
		"max-har-entries",
		defaultMaxHAREntries,
		"Maximum HAR requests included",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() > 1 {
		_, _ = fmt.Fprintln(stderr, "collect accepts one positional HAR path")
		return 2
	}
	visited := make(map[string]bool)
	flags.Visit(func(current *flag.Flag) {
		visited[current.Name] = true
	})
	if flags.NArg() == 1 {
		if visited["har"] {
			_, _ = fmt.Fprintln(
				stderr,
				"provide the HAR path either positionally or with --har, not both",
			)
			return 2
		}
		*harPath = flags.Arg(0)
	}
	explicitNamespaces := visited["namespace"] || visited["namespaces"]
	if *excludeSystemNamespaces && !visited["all-namespaces"] {
		_, _ = fmt.Fprintln(
			stderr,
			"--exclude-system-namespaces requires --all-namespaces",
		)
		return 2
	}
	if !explicitNamespaces && !visited["all-namespaces"] {
		*allNamespaces = true
		*excludeSystemNamespaces = true
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
		if *excludeSystemNamespaces {
			_, _ = fmt.Fprintln(
				stderr,
				"--exclude-system-namespaces requires --all-namespaces",
			)
			return 2
		}
		selectedNamespaces, err = parseNamespaces(*namespace, *namespaces)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if err := validateCollectFlags(
		selectedNamespaces,
		*allNamespaces,
		*harPath,
		*since,
		*timeout,
		*maxLogBytes,
		*maxTotalLogBytes,
		*logWorkers,
		*maxHARBytes,
		*maxHAREntries,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	redactor := redact.New()
	if *allNamespaces {
		message := "Warning: collecting all namespaces includes non-Qodo workloads in shared clusters."
		if *excludeSystemNamespaces {
			message = "Scope: all application namespaces; Kubernetes and managed GKE system namespaces are excluded."
		}
		_, _ = fmt.Fprintln(stderr, message)
	}
	builder, err := bundle.New(*output)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
		return 1
	}
	cleanupPending := true
	defer func() {
		if !cleanupPending {
			return
		}
		closeBundle(builder, stderr, &exitCode)
	}()

	_, _ = fmt.Fprintf(
		stderr,
		"Importing HAR: %s\n",
		filepath.Base(redactor.Text(*harPath)),
	)
	var harStats har.Stats
	if err := builder.AddStream("browser/network.jsonl", func(writer io.Writer) error {
		var importErr error
		harStats, importErr = har.Import(
			*harPath,
			writer,
			*maxHARBytes,
			*maxHAREntries,
			redactor,
		)
		return importErr
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
		return 1
	}
	_, _ = fmt.Fprintf(
		stderr,
		"Imported %d browser requests.\n",
		harStats.EntriesWritten,
	)

	resolvedKubectl, err := resolveKubectl(*kubectl)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "Using kubectl: %q\n", resolvedKubectl)
	kubernetesReport, kubernetesErr := kubernetes.Collect(
		ctx,
		kubernetes.Config{
			Namespaces:              selectedNamespaces,
			AllNamespaces:           *allNamespaces,
			ExcludeSystemNamespaces: *excludeSystemNamespaces,
			Selector:                *selector,
			Context:                 *kubeContext,
			Kubeconfig:              *kubeconfig,
			Since:                   *since,
			Timeout:                 *timeout,
			MaxLogBytes:             *maxLogBytes,
			MaxTotalLogBytes:        *maxTotalLogBytes,
			LogWorkers:              *logWorkers,
			Progress: func(progress kubernetes.Progress) {
				writeCollectionProgress(stderr, redactor, progress)
			},
		},
		kubernetes.ExecRunner{Binary: resolvedKubectl},
		builder,
		redactor,
	)

	collectionStatus := collectionStatusComplete
	if kubernetesErr != nil || len(kubernetesReport.Issues) > 0 || harStats.Truncated {
		collectionStatus = collectionStatusPartial
	}
	if kubernetesErr != nil {
		kubernetesReport.Issues = append(kubernetesReport.Issues, kubernetes.Issue{
			Operation: "collect Kubernetes diagnostics",
			Message:   redactor.Text(kubernetesErr.Error()),
		})
	}
	issuesData, err := marshalIssues(kubernetesReport.Issues)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
		return 1
	}
	if len(issuesData) > 0 {
		if err := builder.Add("collection-issues.jsonl", issuesData); err != nil {
			_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
			return 1
		}
	}

	manifestNamespaces := selectedNamespaces
	namespaceValue := strings.Join(selectedNamespaces, ",")
	if *allNamespaces {
		manifestNamespaces = kubernetesReport.Namespaces
		namespaceValue = "*"
	}
	generatedAt := time.Now().UTC()
	archivePath, err := builder.Finalize(bundle.Manifest{
		CollectorVersion: Version,
		GeneratedAt:      generatedAt,
		Collection: map[string]any{
			"status":                    collectionStatus,
			"namespace":                 redactor.Text(namespaceValue),
			"namespaces":                redactStrings(manifestNamespaces, redactor),
			"all_namespaces":            *allNamespaces,
			"exclude_system_namespaces": *excludeSystemNamespaces,
			"selector":                  redactor.Text(*selector),
			"since":                     since.String(),
			"browser": map[string]any{
				"source_file": filepath.Base(redactor.Text(*harPath)),
				"stats":       harStats,
				"bodies":      "omitted",
				"cookies":     "redacted",
			},
			"kubernetes": kubernetesReport,
		},
	})
	if err != nil {
		if errors.Is(err, bundle.ErrCleanup) {
			_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", archivePath)
			_, _ = fmt.Fprintln(
				stderr,
				"Support bundle was created, but temporary data cleanup failed.",
			)
			return 1
		}
		_, _ = fmt.Fprintln(stderr, redactor.Text(err.Error()))
		return 1
	}
	cleanupPending = false

	_, _ = fmt.Fprintf(stdout, "Support bundle created: %s\n", archivePath)
	_, _ = fmt.Fprintf(
		stdout,
		"Kubernetes scope: %d/%d namespaces, %d pods, %d containers (%d init)\n",
		len(kubernetesReport.Namespaces),
		kubernetesReport.NamespacesRequested,
		kubernetesReport.Pods,
		kubernetesReport.Containers,
		kubernetesReport.InitContainers,
	)
	if collectionStatus == collectionStatusPartial {
		_, _ = fmt.Fprintln(
			stderr,
			"Warning: collection was partial; inspect collection-issues.jsonl in the bundle.",
		)
		return 3
	}
	return 0
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

func closeBundle(closer io.Closer, stderr io.Writer, exitCode *int) {
	if err := closer.Close(); err != nil {
		_, _ = fmt.Fprintln(stderr, "Failed to clean up temporary bundle data.")
		*exitCode = 1
	}
}

func validateCollectFlags(
	namespaces []string,
	allNamespaces bool,
	harPath string,
	since time.Duration,
	timeout time.Duration,
	maxLogBytes int64,
	maxTotalLogBytes int64,
	logWorkers int,
	maxHARBytes int64,
	maxHAREntries int,
) error {
	switch {
	case !allNamespaces && len(namespaces) == 0:
		return errors.New("at least one namespace is required")
	case harPath == "":
		return errors.New("--har is required")
	case since <= 0:
		return errors.New("--since must be positive")
	case timeout <= 0:
		return errors.New("--command-timeout must be positive")
	case maxLogBytes <= 0:
		return errors.New("--max-log-bytes must be positive")
	case maxLogBytes > maxLogLimit:
		return fmt.Errorf("--max-log-bytes must not exceed %d bytes", maxLogLimit)
	case maxTotalLogBytes <= 0:
		return errors.New("--max-total-log-bytes must be positive")
	case maxTotalLogBytes > maxTotalLogLimit:
		return fmt.Errorf(
			"--max-total-log-bytes must not exceed %d bytes",
			maxTotalLogLimit,
		)
	case maxLogBytes > maxTotalLogBytes:
		return errors.New("--max-log-bytes must not exceed --max-total-log-bytes")
	case logWorkers <= 0:
		return errors.New("--log-workers must be positive")
	case logWorkers > maxLogWorkers:
		return fmt.Errorf("--log-workers must not exceed %d", maxLogWorkers)
	case maxHARBytes <= 0:
		return errors.New("--max-har-bytes must be positive")
	case maxHARBytes > maxHARLimit:
		return fmt.Errorf("--max-har-bytes must not exceed %d bytes", maxHARLimit)
	case maxHAREntries <= 0:
		return errors.New("--max-har-entries must be positive")
	case maxHAREntries > maxHAREntryLimit:
		return fmt.Errorf("--max-har-entries must not exceed %d", maxHAREntryLimit)
	default:
		return nil
	}
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

func redactStrings(values []string, redactor *redact.Redactor) []string {
	redacted := make([]string, 0, len(values))
	for _, value := range values {
		redacted = append(redacted, redactor.Text(value))
	}
	return redacted
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
				redactor.Text(progress.Namespace),
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

func marshalIssues(issues []kubernetes.Issue) ([]byte, error) {
	if len(issues) == 0 {
		return nil, nil
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, issue := range issues {
		if err := encoder.Encode(issue); err != nil {
			return nil, fmt.Errorf("encode collection issue: %w", err)
		}
	}
	return output.Bytes(), nil
}

func defaultOutputPath() string {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	return "qodo-support-bundle-" + timestamp + ".tar.gz"
}

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  qodo-support-bundle collect [options] capture.har
  qodo-support-bundle serve [--no-open] bundle.tar.gz
  qodo-support-bundle version

The collect command imports sanitized browser request metadata and gathers
Kubernetes metadata, events, and bounded container logs from automatically
discovered application namespaces. Explicit namespace flags override discovery.
The serve command opens a private, read-only viewer on the local machine.`)
}
