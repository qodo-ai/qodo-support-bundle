# Qodo Support Bundle

`qodo-support-bundle` is a portable Go CLI for customer-assisted diagnostics. It
imports a browser-exported HAR, collects bounded Kubernetes diagnostics through
the customer's existing `kubectl` access, redacts sensitive values, and creates
a checksummed `.tar.gz` archive.

The collector is read-only. It never collects Kubernetes Secrets, ConfigMaps,
workload environment variables, or HAR request/response bodies.

## Prerequisites

- The `qodo-support-bundle` binary for the customer's operating system.
- `kubectl` configured for the target cluster.
- Permission to list namespaces plus read access to pods, pod logs, and events
  in the application namespaces.
- A HAR exported by the customer from browser developer tools.

Minimal Kubernetes permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: qodo-support-bundle-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "events"]
    verbs: ["get", "list"]
```

Bind this role only in the application namespaces and remove the bindings after
collection when access is temporary. Automatic discovery also requires
cluster-scoped `list` access to `namespaces`.

## Customer workflow

1. Open browser developer tools and select **Network**.
2. Enable **Preserve log**, clear existing requests, and reproduce the issue.
3. Export the requests as a HAR file.
4. Run:

```bash
qodo-support-bundle collect ~/Downloads/qodo-login.har
```

That command uses the current `kubectl` context, discovers application
namespaces, excludes Kubernetes and managed GKE control-plane namespaces,
imports the required HAR, reads container logs concurrently, shows progress,
and writes a timestamped bundle in the current directory. Before accessing the
cluster, it resolves symlinks to an absolute `kubectl` path and prints that path
so the operator can verify which client will run.

Use `--context` only when the current `kubectl` context is not the target
cluster. Explicit namespace scope remains available for shared clusters:

```bash
qodo-support-bundle collect \
  --namespace <release-namespace> \
  ~/Downloads/qodo-login.har
```

Set `<release-namespace>` to the namespace where the Qodo Helm release is
installed, commonly `qodo-onprem`. Qodo Platform, Portal, and Zitadel are
workloads in that release namespace, not separate namespaces.

`--namespace`, `--namespaces`, and `--all-namespaces` override automatic
application discovery. `--har` remains supported as an alternative to the
positional HAR path.

To include Kubernetes and managed infrastructure too, request literal
cluster-wide scope:

```bash
qodo-support-bundle collect \
  --all-namespaces \
  ~/Downloads/qodo-login.har
```

This discovers every namespace and collects every pod container in the cluster.
Do not use it on a shared cluster unless the customer has approved including
non-Qodo workload metadata and logs. It requires cluster-wide permission to
list namespaces plus the documented pod, log, and event permissions in each
namespace. Automatic discovery excludes `kube-system`, `kube-public`,
`kube-node-lease`, the GKE `gke-managed-*` namespaces, Google Managed
Prometheus system namespaces, and Config Connector system namespaces.
Application dependencies such as `rabbitmq-system` remain included. Other
non-Qodo application namespaces may still be collected on a shared cluster.
Container logs use eight concurrent readers by default; tune this with
`--log-workers` (maximum 64) for unusually small or large API servers. Each
stream is capped at 10 MiB by default (`--max-log-bytes`, maximum 100 MiB), and
current plus previous logs share a 1 GiB retained-data budget
(`--max-total-log-bytes`, maximum 8 GiB). Once that aggregate budget is
exhausted, remaining streams are skipped and reported as non-fatal collection
issues. HAR input defaults to 256 MiB and can be raised with `--max-har-bytes`
up to 4 GiB.

Exit code `0` means collection completed. Exit code `3` means a usable partial
bundle was created; inspect `collection-issues.jsonl` for unavailable resources
or truncated inputs.

## Local viewer

Open a bundle in the offline viewer:

```bash
qodo-support-bundle serve ./qodo-support-bundle.tar.gz
```

The command checks every embedded checksum, safely extracts bounded files into
an owner-only temporary directory, starts a read-only server on a random
`127.0.0.1` port, and opens the system browser. The default timeline correlates
browser requests, backend logs, Kubernetes events, and pod lifecycle records in
horizontal swimlanes. Dense logs are clustered into clickable time slices, and
fair sampling across container groups prevents one noisy source from hiding the
other lanes. Lanes expand into namespace, pod/container, host, or resource
groups. Time-window selection, zoom, horizontal navigation, text search, error
and authentication-flow filters, record details, and the original paginated
file explorer are also available.

Use `--no-open` when the tool cannot launch a browser. Open the printed
owner-only launcher file, which hands the one-time credential to the viewer
without placing it in terminal output, browser history, or process arguments:

```bash
qodo-support-bundle serve --no-open ./qodo-support-bundle.tar.gz
```

Compressed bundle input is capped at 4 GiB by default. Lower that bound for
smaller expected bundles with `--max-archive-bytes`.

Press `Ctrl+C` to stop the server and delete the extracted temporary data. The
viewer rejects non-loopback clients, unexpected host headers, modified
checksums, unsafe archive paths, non-regular archive entries, oversized files,
and mutation requests. It has no upload API or external web dependencies.

## Bundle contents

```text
manifest.json
checksums.sha256
browser/network.jsonl
kubernetes/pods.jsonl
kubernetes/events.jsonl
kubernetes/logs/<pod>/<container>.log
# Multi-namespace bundles use:
kubernetes/pods/<namespace>.jsonl
kubernetes/events/<namespace>.jsonl
kubernetes/logs/<namespace>/<pod>/<container>.log
kubernetes/logs/<namespace>/<pod>/<container>-previous.log
collection-issues.jsonl
```

HAR records and Kubernetes metadata are newline-delimited JSON with a
`schema_version`, `source.type`, and `@timestamp` when available. These files
can be ingested by Elastic Agent/Filebeat, Logstash, OpenSearch, Splunk, or a
custom JSONL pipeline. Container logs retain their original line structure
after redaction.

Verify integrity after extracting:

```bash
mkdir -p ./qodo-support-bundle
tar -xzf qodo-support-bundle.tar.gz -C ./qodo-support-bundle
cd ./qodo-support-bundle
shasum -a 256 -c checksums.sha256
```

The embedded checksums detect accidental corruption within a bundle, but they
do not authenticate who created it or where it originated. Transfer bundles
only through an approved authenticated channel.

Verify the build provenance of an official release binary after downloading it
from GitHub:

```bash
gh attestation verify ./qodo-support-bundle-linux-amd64 \
  --repo Codium-ai/qodo-platform
```

## Security boundaries

- Authorization, cookie, token, credential, password, private-key, email, and
  common provider-token patterns are replaced with `[REDACTED]`.
- Sensitive HAR headers remain visible by name so missing authentication can be
  diagnosed, but their values are removed.
- HAR cookies and request/response bodies are omitted.
- Every input and per-container log is bounded; truncated files are reported in
  the manifest.
- Temporary files, bundle members, and the resulting archive use owner-only
  permissions.
- Collection uses argument-based process execution, not a shell.

Redaction cannot recognize every customer-specific identifier embedded in
free-form application text. Customers must treat both the original HAR and the
generated bundle as sensitive, inspect the bundle before sharing it, transfer
it through an approved secure channel, and delete local copies according to
their retention policy.

## Build and test

```bash
make test
make build VERSION=dev
```

Cross-compile release binaries and generate distribution checksums:

```bash
make release VERSION=1.0.0
```
