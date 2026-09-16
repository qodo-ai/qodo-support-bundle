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
	defaultHARLimit                 int64 = 256 << 20
	maxHARLimit                     int64 = 4 << 30
	defaultLogLimit                 int64 = 10 << 20
	maxLogLimit                           = kubernetes.MaximumLogBytes
	defaultLogScanLimit             int64 = 32 << 20
	maxLogScanLimit                       = kubernetes.MaximumLogScanBytes
	maxConcurrentLogScanLimit             = kubernetes.MaximumConcurrentLogScanBytes
	defaultTotalLogLimit            int64 = 1 << 30
	maxTotalLogLimit                      = kubernetes.MaximumTotalLogBytes
	defaultLogWorkers                     = 8
	maxLogWorkers                         = kubernetes.MaximumLogWorkers
	defaultMaxHAREntries                  = 100_000
	maxHAREntryLimit                      = 1_000_000
	defaultCorrelationContextLines        = 3
	maxCorrelationContextLines            = 100
	defaultCorrelationWindowPadding       = 2 * time.Minute
	maxCustomerContextLength              = 4096
	maxCommandTimeout                     = 30 * time.Minute
	collectionStatusComplete              = "complete"
	collectionStatusPartial               = "partial"
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
	if *maxArchiveBytes > viewer.MaxSupportedArchiveBytes {
		_, _ = fmt.Fprintln(stderr, "max-archive-bytes is too large")
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
		_, _ = fmt.Fprintln(stderr, terminalText(redact.New(), err.Error()))
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
	maxLogScanBytes := flags.Int64(
		"max-log-scan-bytes",
		defaultLogScanLimit,
		"Maximum raw bytes scanned from each container log (up to 256 MiB)",
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
	correlationContextLines := flags.Int(
		"correlation-context-lines",
		defaultCorrelationContextLines,
		"Log lines retained before and after a correlation-ID match",
	)
	correlationWindowPadding := flags.Duration(
		"correlation-window-padding",
		defaultCorrelationWindowPadding,
		"Time added before and after the HAR capture window",
	)
	activity := flags.String(
		"activity",
		"",
		"Customer description of what they were doing",
	)
	problem := flags.String(
		"problem",
		"",
		"Customer description of what failed",
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
		*maxLogScanBytes,
		*maxTotalLogBytes,
		*logWorkers,
		*maxHARBytes,
		*maxHAREntries,
	); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if *correlationContextLines < 0 ||
		*correlationContextLines > maxCorrelationContextLines {
		_, _ = fmt.Fprintf(
			stderr,
			"correlation-context-lines must be between 0 and %d\n",
			maxCorrelationContextLines,
		)
		return 2
	}
	if *correlationWindowPadding < 0 || *correlationWindowPadding > 24*time.Hour {
		_, _ = fmt.Fprintln(
			stderr,
			"correlation-window-padding must be between 0 and 24h",
		)
		return 2
	}
	if len(*activity) > maxCustomerContextLength || len(*problem) > maxCustomerContextLength {
		_, _ = fmt.Fprintf(
			stderr,
			"activity and problem must not exceed %d characters\n",
			maxCustomerContextLength,
		)
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
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
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
		terminalText(redactor, filepath.Base(*harPath)),
	)
	var harStats har.Stats
	if err := builder.AddStream("browser/network.jsonl", func(writer io.Writer) error {
		var importErr error
		harStats, importErr = har.ImportContext(
			ctx,
			*harPath,
			writer,
			*maxHARBytes,
			*maxHAREntries,
			redactor,
		)
		return importErr
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	_, _ = fmt.Fprintf(
		stderr,
		"Imported %d browser requests with %d correlation values.\n",
		harStats.EntriesWritten,
		harStats.CorrelationIDCount,
	)
	sinceTime, untilTime := correlationWindow(harStats, *correlationWindowPadding)

	resolvedKubectl, err := resolveKubectl(*kubectl)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
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
			SinceTime:               sinceTime,
			UntilTime:               untilTime,
			CorrelationIDs:          harStats.CorrelationIDs,
			CorrelationContextLines: *correlationContextLines,
			Timeout:                 *timeout,
			MaxLogBytes:             *maxLogBytes,
			MaxLogScanBytes:         *maxLogScanBytes,
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
	if ctx.Err() != nil {
		_, _ = fmt.Fprintln(stderr, "Collection canceled; no bundle was published.")
		return 1
	}

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
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	if len(issuesData) > 0 {
		if err := builder.Add("collection-issues.jsonl", issuesData); err != nil {
			_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
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
	customerContext := map[string]string{}
	if sanitizedActivity := strings.TrimSpace(redactor.Text(*activity)); sanitizedActivity != "" {
		customerContext["activity"] = sanitizedActivity
	}
	if sanitizedProblem := strings.TrimSpace(redactor.Text(*problem)); sanitizedProblem != "" {
		customerContext["problem"] = sanitizedProblem
	}
	summary := buildSummary(
		generatedAt,
		collectionStatus,
		harStats,
		kubernetesReport,
		customerContext,
	)
	if err := builder.Add("summary.md", []byte(summary)); err != nil {
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
		return 1
	}
	ruleset := redactor.Ruleset()
	archivePath, err := builder.FinalizeContext(ctx, bundle.Manifest{
		CollectorVersion:      Version,
		GeneratedAt:           generatedAt,
		ClockSkewMilliseconds: harStats.ClockSkewMilliseconds,
		Redaction: map[string]string{
			"version": ruleset.Version,
			"sha256":  ruleset.SHA256,
		},
		CustomerContext: customerContext,
		Collection: map[string]any{
			"status":                    collectionStatus,
			"namespace":                 redactor.Text(namespaceValue),
			"namespaces":                redactStrings(manifestNamespaces, redactor),
			"all_namespaces":            *allNamespaces,
			"exclude_system_namespaces": *excludeSystemNamespaces,
			"selector":                  redactor.Text(*selector),
			"since":                     since.String(),
			"correlation": map[string]any{
				"id_count":              harStats.CorrelationIDCount,
				"context_lines":         *correlationContextLines,
				"window_start":          formatOptionalTime(sinceTime),
				"window_end":            formatOptionalTime(untilTime),
				"window_padding":        correlationWindowPadding.String(),
				"scan_bytes_per_stream": *maxLogScanBytes,
			},
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
		_, _ = fmt.Fprintln(stderr, terminalText(redactor, err.Error()))
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

func correlationWindow(stats har.Stats, padding time.Duration) (time.Time, time.Time) {
	startedAt, startErr := time.Parse(time.RFC3339Nano, stats.AdjustedStartedAt)
	endedAt, endErr := time.Parse(time.RFC3339Nano, stats.AdjustedEndedAt)
	if startErr != nil || endErr != nil {
		return time.Time{}, time.Time{}
	}
	return startedAt.Add(-padding), endedAt.Add(padding)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339Nano)
}

func buildSummary(
	generatedAt time.Time,
	status string,
	harStats har.Stats,
	kubernetesReport kubernetes.Report,
	customerContext map[string]string,
) string {
	var summary strings.Builder
	fmt.Fprintln(&summary, "# Qodo support bundle summary")
	fmt.Fprintf(&summary, "\n- Captured: %s\n", generatedAt.Format(time.RFC3339Nano))
	fmt.Fprintf(&summary, "- Collection status: %s\n", status)
	if activity := summaryValue(customerContext["activity"]); activity != "" {
		fmt.Fprintf(&summary, "- Customer activity: %s\n", activity)
	}
	if problem := summaryValue(customerContext["problem"]); problem != "" {
		fmt.Fprintf(&summary, "- Reported problem: %s\n", problem)
	}
	fmt.Fprintln(&summary, "\n## Browser and correlation")
	fmt.Fprintf(&summary, "\n- HTTP requests: %d\n", harStats.EntriesWritten)
	fmt.Fprintf(&summary, "- HTTP failures (4xx/5xx): %d\n", harStats.HTTPFailures)
	fmt.Fprintf(&summary, "- Unique correlation values: %d\n", harStats.CorrelationIDCount)
	fmt.Fprintf(
		&summary,
		"- Browser-to-cluster clock offset: %d ms (%d Date-header samples)\n",
		harStats.ClockSkewMilliseconds,
		harStats.ClockSkewSamples,
	)
	if harStats.CaptureStartedAt != "" {
		fmt.Fprintf(
			&summary,
			"- HAR capture window: %s to %s\n",
			harStats.CaptureStartedAt,
			harStats.CaptureEndedAt,
		)
	}
	fmt.Fprintln(&summary, "\n## Kubernetes")
	fmt.Fprintf(
		&summary,
		"\n- Scope: %d/%d namespaces, %d pods, %d containers\n",
		len(kubernetesReport.Namespaces),
		kubernetesReport.NamespacesRequested,
		kubernetesReport.Pods,
		kubernetesReport.Containers,
	)
	fmt.Fprintf(&summary, "- Container restarts: %d\n", kubernetesReport.ContainerRestarts)
	fmt.Fprintf(&summary, "- OOMKills: %d\n", kubernetesReport.OOMKills)
	fmt.Fprintf(
		&summary,
		"- Correlated logs: %d lines across %d files (%d streams scanned)\n",
		kubernetesReport.MatchedLogLines,
		kubernetesReport.MatchedLogFiles,
		kubernetesReport.LogStreamsScanned,
	)
	fmt.Fprintf(&summary, "- Truncated log files: %d\n", kubernetesReport.TruncatedLogFiles)
	fmt.Fprintf(&summary, "- Truncated raw log scans: %d\n", kubernetesReport.TruncatedLogScans)
	fmt.Fprintf(&summary, "- Collection issues: %d\n", len(kubernetesReport.Issues))
	fmt.Fprintln(
		&summary,
		"\nOpen this bundle with `qodo-support-bundle serve` for the merged timeline.",
	)
	return summary.String()
}

func summaryValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func terminalText(redactor *redact.Redactor, value string) string {
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, redactor.Text(value))
}

func validateCollectFlags(
	namespaces []string,
	allNamespaces bool,
	harPath string,
	since time.Duration,
	timeout time.Duration,
	maxLogBytes int64,
	maxLogScanBytes int64,
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
	case timeout > maxCommandTimeout:
		return fmt.Errorf("--command-timeout must not exceed %s", maxCommandTimeout)
	case maxLogBytes <= 0:
		return errors.New("--max-log-bytes must be positive")
	case maxLogBytes > maxLogLimit:
		return fmt.Errorf("--max-log-bytes must not exceed %d bytes", maxLogLimit)
	case maxLogScanBytes <= 0:
		return errors.New("--max-log-scan-bytes must be positive")
	case maxLogScanBytes > maxLogScanLimit:
		return fmt.Errorf(
			"--max-log-scan-bytes must not exceed %d bytes",
			maxLogScanLimit,
		)
	case maxLogScanBytes < maxLogBytes:
		return errors.New("--max-log-scan-bytes must not be less than --max-log-bytes")
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
	case maxLogScanBytes*int64(logWorkers) > maxConcurrentLogScanLimit:
		return fmt.Errorf(
			"--max-log-scan-bytes times --log-workers must not exceed %d bytes",
			maxConcurrentLogScanLimit,
		)
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
