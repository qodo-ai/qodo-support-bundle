package app

import (
	"github.com/qodo-ai/qodo-support-bundle/internal/bundle"
	"github.com/qodo-ai/qodo-support-bundle/internal/collection"
	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

func writeCollectionEvent(renderer *progressRenderer, event collection.Event) {
	switch event.Kind {
	case collection.EventKubernetesStarted:
		renderer.Update(progressUpdate{
			ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
			Status: progressActive,
		})
	case collection.EventKubernetesComplete:
		renderer.Update(progressUpdate{
			ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
			Status: progressCompleted, Current: event.Current, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventKubernetesPartial:
		renderer.Update(progressUpdate{
			ID: "kubernetes", Label: "Kubernetes diagnostics", Level: 1,
			Status: progressWarning, Detail: "partial",
			Current: event.Current, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventWorkloadStarted:
		renderer.Update(progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressActive, Current: 0, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventWorkloadProgress:
		renderer.Update(progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressActive, Current: event.Current, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventWorkloadComplete:
		renderer.Update(progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressCompleted, Current: event.Current, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventWorkloadPartial:
		renderer.Update(progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressWarning, Detail: "partial",
			Current: event.Current, Total: event.Total,
			Unit: plural(event.Total, "namespace", "namespaces"),
		})
	case collection.EventWorkloadUnavailable:
		renderer.Update(progressUpdate{
			ID: "workload", Label: "Workload context", Level: 1,
			Status: progressFailed, Detail: "unavailable",
		})
	case collection.EventArchiveSummary:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressActive, Detail: "preparing summary",
		})
	case collection.EventPrometheusStarted:
		renderer.Update(progressUpdate{
			ID: "prometheus", Label: "Prometheus telemetry", Level: 1,
			Status: progressActive,
		})
	case collection.EventPrometheusComplete:
		renderer.Update(progressUpdate{
			ID: "prometheus", Label: "Prometheus telemetry", Level: 1,
			Status: progressCompleted,
		})
	case collection.EventPrometheusPartial:
		renderer.Update(progressUpdate{
			ID: "prometheus", Label: "Prometheus telemetry", Level: 1,
			Status: progressWarning, Detail: "partial",
		})
	case collection.EventPrometheusUnavailable:
		renderer.Update(progressUpdate{
			ID: "prometheus", Label: "Prometheus telemetry", Level: 1,
			Status: progressFailed, Detail: "unavailable",
		})
	case collection.EventPhoenixStarted:
		renderer.Update(progressUpdate{
			ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
			Status: progressActive,
		})
	case collection.EventPhoenixComplete:
		renderer.Update(progressUpdate{
			ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
			Status: progressCompleted,
		})
	case collection.EventPhoenixPartial:
		renderer.Update(progressUpdate{
			ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
			Status: progressWarning, Detail: "partial",
		})
	case collection.EventPhoenixUnavailable:
		renderer.Update(progressUpdate{
			ID: "phoenix", Label: "Phoenix telemetry", Level: 1,
			Status: progressFailed, Detail: "unavailable",
		})
	case collection.EventZitadelStarted:
		renderer.Update(progressUpdate{
			ID: "zitadel", Label: "Zitadel connectivity", Level: 1,
			Status: progressActive,
		})
	case collection.EventZitadelUnavailable:
		renderer.Update(progressUpdate{
			ID: "zitadel", Label: "Zitadel connectivity", Level: 1,
			Status: progressFailed, Detail: "unavailable",
		})
	case collection.EventZitadelDiagnosticFailure:
		renderer.Update(progressUpdate{
			ID: "zitadel", Label: "Zitadel connectivity", Level: 1,
			Status: progressFailed, Detail: "diagnostic failure",
		})
	case collection.EventZitadelPassed:
		renderer.Update(progressUpdate{
			ID: "zitadel", Label: "Zitadel connectivity", Level: 1,
			Status: progressCompleted,
		})
	}
}

func writeCollectionProgress(
	renderer *progressRenderer,
	redactor *redact.Redactor,
	progress kubernetes.Progress,
) {
	switch progress.Stage {
	case "discover_namespaces":
		renderer.Update(progressUpdate{
			ID: "kubernetes.discovery", Label: "Namespace discovery", Level: 2,
			Status: progressActive,
		})
	case "namespaces_discovered":
		renderer.Update(progressUpdate{
			ID: "kubernetes.discovery", Label: "Namespace discovery", Level: 2,
			Status: progressCompleted, Current: progress.Total, Total: progress.Total,
			Unit: plural(progress.Total, "namespace", "namespaces"),
		})
	case "scan_namespace":
		if progress.Current == 1 ||
			progress.Current == progress.Total ||
			progress.Current%5 == 0 {
			renderer.Update(progressUpdate{
				ID: "kubernetes.scan", Label: "Namespace scan", Level: 2,
				Status: progressActive, Current: progress.Current, Total: progress.Total,
				Unit:   plural(progress.Total, "namespace", "namespaces"),
				Detail: terminalText(redactor, progress.Namespace),
			})
		}
	case "scan_complete":
		status := progressCompleted
		detail := ""
		if progress.Current < progress.Total {
			status = progressWarning
			detail = "partial"
		}
		renderer.Update(progressUpdate{
			ID: "kubernetes.scan", Label: "Namespace scan", Level: 2,
			Status: status, Current: progress.Current, Total: progress.Total,
			Unit:   plural(progress.Total, "namespace", "namespaces"),
			Detail: detail,
		})
	case "collect_logs":
		if progress.Total == 0 {
			renderer.Update(progressUpdate{
				ID: "kubernetes.logs", Label: "Container logs", Level: 2,
				Status: progressCompleted, Detail: "no streams",
			})
			break
		}
		renderer.Update(progressUpdate{
			ID: "kubernetes.logs", Label: "Container logs", Level: 2,
			Status: progressActive, Current: 0, Total: progress.Total,
			Unit: plural(progress.Total, "stream", "streams"),
		})
	case "logs_progress":
		renderer.Update(progressUpdate{
			ID: "kubernetes.logs", Label: "Container logs", Level: 2,
			Status: progressActive, Current: progress.Current, Total: progress.Total,
			Unit: plural(progress.Total, "stream", "streams"),
		})
	case "logs_complete":
		status := progressCompleted
		detail := ""
		if progress.Current < progress.Total {
			status = progressWarning
			detail = "partial"
		}
		renderer.Update(progressUpdate{
			ID: "kubernetes.logs", Label: "Container logs", Level: 2,
			Status: status, Current: progress.Current, Total: progress.Total,
			Unit:   plural(progress.Total, "stream", "streams"),
			Detail: detail,
		})
	}
}

func writeBundleProgress(renderer *progressRenderer, progress bundle.Progress) {
	switch progress.Stage {
	case bundle.ProgressManifest:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressActive, Detail: "creating manifest",
		})
	case bundle.ProgressChecksums:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressActive, Detail: "writing checksums",
		})
	case bundle.ProgressPacking:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressActive, Detail: "packing",
		})
	case bundle.ProgressFinalizing:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressActive, Detail: "finalizing",
		})
	case bundle.ProgressComplete:
		renderer.Update(progressUpdate{
			ID: "archive", Label: "Archive", Level: 1,
			Status: progressCompleted,
		})
	}
}

func plural(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}
