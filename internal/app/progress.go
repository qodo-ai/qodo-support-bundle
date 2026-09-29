package app

import (
	"fmt"
	"io"

	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

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
