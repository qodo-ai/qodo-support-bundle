package app

import (
	"fmt"

	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func writeCollectionEvent(renderer *progressRenderer, event collection.Event) {
	switch event.Kind {
	case collection.EventKubernetesStarted:
		renderer.Stage(string(event.Kind), "Checking cluster access...")
	case collection.EventKubernetesComplete:
		renderer.Stage(string(event.Kind), "Kubernetes diagnostics: complete.")
	case collection.EventKubernetesPartial:
		renderer.Stage(string(event.Kind), "Kubernetes diagnostics: partial collection recorded.")
	case collection.EventWorkloadStarted:
		renderer.Stage(
			string(event.Kind),
			fmt.Sprintf(
				"Collecting workload context for %d %s...",
				event.Total,
				plural(event.Total, "namespace", "namespaces"),
			),
		)
	case collection.EventWorkloadProgress:
		renderer.Stage(
			string(event.Kind),
			fmt.Sprintf(
				"Workload context: %d/%d namespaces processed.",
				event.Current,
				event.Total,
			),
		)
	case collection.EventWorkloadComplete:
		renderer.Stage(string(event.Kind), "Workload context: complete.")
	case collection.EventWorkloadPartial:
		renderer.Stage(string(event.Kind), "Workload context: partial collection recorded.")
	case collection.EventWorkloadUnavailable:
		renderer.Stage(string(event.Kind), "Workload context: unavailable; diagnostic recorded.")
	case collection.EventArchiveSummary:
		renderer.Stage(string(event.Kind), "Preparing archive summary...")
	case collection.EventPrometheusStarted:
		renderer.Stage(string(event.Kind), "Collecting Prometheus telemetry...")
	case collection.EventPrometheusComplete:
		renderer.Stage(string(event.Kind), "Prometheus telemetry: complete.")
	case collection.EventPrometheusPartial:
		renderer.Stage(string(event.Kind), "Prometheus telemetry: partial collection recorded.")
	case collection.EventPrometheusUnavailable:
		renderer.Stage(string(event.Kind), "Prometheus telemetry: unavailable; diagnostic recorded.")
	case collection.EventPhoenixStarted:
		renderer.Stage(string(event.Kind), "Collecting Phoenix telemetry...")
	case collection.EventPhoenixComplete:
		renderer.Stage(string(event.Kind), "Phoenix telemetry: complete.")
	case collection.EventPhoenixPartial:
		renderer.Stage(string(event.Kind), "Phoenix telemetry: partial collection recorded.")
	case collection.EventPhoenixUnavailable:
		renderer.Stage(string(event.Kind), "Phoenix telemetry: unavailable; diagnostic recorded.")
	case collection.EventZitadelStarted:
		renderer.Stage(string(event.Kind), "Checking Platform-to-Zitadel connectivity...")
	case collection.EventZitadelUnavailable:
		renderer.Stage(string(event.Kind), "Zitadel connectivity probe: unavailable; diagnostic recorded.")
	case collection.EventZitadelDiagnosticFailure:
		renderer.Stage(string(event.Kind), "Zitadel connectivity: diagnostic failure recorded.")
	case collection.EventZitadelPassed:
		renderer.Stage(string(event.Kind), "Zitadel connectivity: passed.")
	}
}

func writeCollectionProgress(
	renderer *progressRenderer,
	redactor *redact.Redactor,
	progress kubernetes.Progress,
) {
	switch progress.Stage {
	case "discover_namespaces":
		renderer.Stage(progress.Stage, "Discovering Kubernetes application namespaces...")
	case "namespaces_discovered":
		renderer.Stage(
			progress.Stage,
			fmt.Sprintf("Discovered %d namespaces.", progress.Total),
		)
	case "scan_namespace":
		if progress.Current == 1 ||
			progress.Current == progress.Total ||
			progress.Current%5 == 0 {
			renderer.Stage(
				progress.Stage,
				fmt.Sprintf(
					"Scanning namespace %d/%d: %s",
					progress.Current,
					progress.Total,
					terminalText(redactor, progress.Namespace),
				),
			)
		}
	case "collect_logs":
		renderer.Stage(
			progress.Stage,
			fmt.Sprintf(
				"Collecting %d container log streams with %d workers...",
				progress.Total,
				progress.Workers,
			),
		)
	case "logs_progress":
		renderer.Stage(
			progress.Stage,
			fmt.Sprintf(
				"Collected log streams: %d/%d",
				progress.Current,
				progress.Total,
			),
		)
	}
}

func writeBundleProgress(renderer *progressRenderer, progress bundle.Progress) {
	switch progress.Stage {
	case bundle.ProgressManifest:
		renderer.Stage(string(progress.Stage), "Creating archive manifest...")
	case bundle.ProgressChecksums:
		renderer.Stage(string(progress.Stage), "Writing archive checksums...")
	case bundle.ProgressPacking:
		renderer.Stage(string(progress.Stage), "Packing archive...")
	case bundle.ProgressFinalizing:
		renderer.Stage(string(progress.Stage), "Finalizing archive...")
	case bundle.ProgressComplete:
		renderer.Stage(string(progress.Stage), "Archive finalized.")
	}
}

func plural(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}
