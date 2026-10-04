# Qodo Scout · Read-only on-prem diagnostics

Qodo Scout is a portable, read-only CLI for collecting bounded and redacted
Kubernetes diagnostics. The executable, release assets, and archive filenames
remain `qodo-support-bundle` for compatibility. It collects pod metadata,
events, current and previous container logs, normalized namespace-scoped
workload context, optional namespace-scoped Prometheus telemetry, optional
bounded Arize Phoenix traces, and an optional Platform-to-Zitadel connectivity
report.

**Collection safeguards**

Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and
sensitive text is redacted.

## Install

Cross-platform installers resolve `version.json`, select and verify the matching
release artifact, and install the stable `qodo-scout` command without sudo or
administrator access. Merging the publication code does not publish live
objects; stable endpoints return 404 until the manual dev and approved
production workflows run. See [the installer contract and commands](docs/installers.md)
and [the publication runbook](docs/publication.md). Maintainers preparing a
pilot must complete the
[public distribution readiness checklist](docs/public-readiness.md).

The installer runs only a local `version` smoke check. It never starts
collection. The customer starts the guided flow explicitly:

```bash
qodo-scout collect --interactive
```

Security boundaries and platform assurance are documented in the
[security model](docs/security-model.md). See [CONTRIBUTING.md](CONTRIBUTING.md)
to propose a change and [SECURITY.md](SECURITY.md) to report a vulnerability
privately.

## Prerequisites and scope

- A release binary for the operator's platform.
- `kubectl` configured for the target cluster.
- Read access to pods, pod logs, events, and the supported workload resources
  in each collected namespace.
- Cluster-scoped `list` access to namespaces only when automatic discovery or
  `--all-namespaces` is used.
- `create` on `pods/portforward` in each selected Prometheus or Phoenix service
  namespace only when that telemetry source is requested.
- `pods/exec` permission only when `--check-zitadel` is requested.

The collector never requests Secrets or ConfigMaps. Workload artifacts omit raw
manifests, environment values, command arguments, annotations, endpoint
addresses, and volume contents. A namespace-scoped baseline role is:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: qodo-support-bundle-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "events", "services", "persistentvolumeclaims"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list"]
```

For the optional probe, add `create` on `pods/exec` only in the selected
Platform namespace and remove temporary bindings after collection.

For optional Prometheus or Phoenix collection, bind the baseline Service and
EndpointSlice read permissions in each telemetry service namespace and add this
rule there. Remove temporary bindings after collection:

```yaml
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/portforward"]
  verbs: ["create"]
```

## Collect

```bash
qodo-support-bundle collect
```

By default, the command uses the current kubeconfig and context, discovers
application namespaces, excludes known Kubernetes and managed GKE system
namespaces, and writes:

```text
~/qodo-support-bundles/qodo-support-bundle-<UTC timestamp>-<random suffix>.tar.gz
```

The dedicated output directory and archive use owner-only permissions where
supported. `--output` is an exact archive file-path override; it is never
treated as a directory and existing files are not overwritten.

The command may run from any working directory. Standard `kubectl` resolution
still applies: without `--kubeconfig`, `KUBECONFIG` or the normal user default
is used; without `--context`, the current context is used. Explicit values are
passed as argument-array elements:

```bash
qodo-support-bundle collect \
  --kubeconfig /secure/customer.kubeconfig \
  --context customer-production \
  --namespace qodo-onprem \
  --output /secure/cases/case-123.tar.gz
```

Routine progress is written to stderr so stdout remains stable for scripts. In
an interactive terminal, Qodo Scout uses an inline Bubble Tea display that
keeps the current hierarchy visible without entering the alternate screen, so
terminal history remains available. A single-line scanner is shown beside the
active stage caption during real processing, including stage counters when
known. Redirected stderr and CI output contain only stable lines, without
animation or terminal control sequences.

Progress is grouped into high-level stages with nested discovery, scanning,
logs, workload, optional telemetry, and archive work. Interactive terminals use
completed, active, warning/partial, and failed markers, with ASCII-safe markers
when Unicode is unavailable. Reliable counts and elapsed times are shown when
known; lines are shortened to the terminal width. A final stderr summary lists
compact counts, successful top-level sources, actionable warnings, duration,
and the local archive path and size. Successful nested stages are not repeated.
Only known safe explanations appear in this summary; detailed diagnostics stay
in `collection-issues.jsonl`. For example, redirected output uses stable lines
such as:

```text
[active] Qodo Scout collection
  [active] Read-only Kubernetes data
    [done] Namespaces | 2/2 namespaces
  [done] Read-only Kubernetes data | 2/2 namespaces
Qodo Scout
Bundle created | 1 warning
2 namespaces | 18 pods | 37 log sources | 38.7s

[done] Read-only Kubernetes data
[done] Workload and service context
[warning] Prometheus not collected
  No Prometheus service found in monitoring.
[done] Archive prepared with redaction | 2.4 MiB

Bundle saved: /secure/cases/case-123.tar.gz
[!] Review before sharing
```

Supported interactive terminals render the full `Bundle saved` path as a
clickable local-file link. Redirected and unsupported terminals always show the
same absolute path as plain text.

```bash
# Launch the optional setup wizard. Bare `collect` never prompts.
qodo-support-bundle collect --interactive

# Suppress routine progress; warnings, errors, and stdout results remain.
qodo-support-bundle collect --no-progress

# Deprecated compatibility no-op.
qodo-support-bundle collect --mascot
```

`--mascot` is deprecated and has no effect, but remains accepted so existing
scripts do not fail. `--no-progress` disables routine progress and animation.

The setup wizard requires both stdin and stderr to be interactive terminals.
In CI or with redirected stderr it exits with usage code `2` instead of
waiting for input. Escape or Ctrl+C cancels setup with exit code `1` before
collection, so no archive is created. Existing flags remain the automation
interface; when combined with `--interactive`, supported flags become initial
answers that can be reviewed and edited.

Interactive setup begins with a sub-second Harmonica scanner entrance while
real kubeconfig preflight runs concurrently. A bounded scan beam crosses the
track and settles beneath the title before setup. The compact single-line
scanner remains the active processing indicator. Setup
resolves kubectl before reporting it ready, lists kubeconfig contexts,
identifies the current context when available, and checks read-only API access
only after a cluster is selected. Any key skips the remaining decorative
entrance while validation continues; Ctrl+C cancels setup. `NO_COLOR`,
`ACCESSIBLE`, `--no-progress`, and non-interactive output skip the entrance.

The wizard first offers the effective Kubernetes context: the explicit
`--context` value when supplied, otherwise the kubeconfig's current context.
Choose `Choose another…` to open the complete context list; press `/` in
that list to filter it. Namespace discovery and cluster authentication happen
only after a context is selected. The wizard then asks for namespace scope, log
lookback, optional Prometheus, Phoenix, or Zitadel data sources and their
dependent settings, the output path, and final confirmation. It never requests
credentials or lists Kubernetes Secrets.

Recognized GKE contexts use compact `<cluster> (<project>)` labels. The exact
kubeconfig context remains the internal value; confirmation includes it when
friendly labels would otherwise be ambiguous. Unknown context formats are
displayed unchanged. Only the
kubeconfig's actual current context is marked `CURRENT`, so an explicit
`--context` default that differs from it is not mislabeled. Recognized
production GKE cluster names receive a factual read-only/sensitive-diagnostics
confirmation. A typical flow is:

```text
QODO SCOUT
Read-only on-prem diagnostics

[    ━●━       ]  Checking environment…

✓ kubectl ready
● finding kubeconfig contexts
[   ━●━    ]  Scout is checking setup
✓ 2 kubeconfig contexts found
✓ current context identified

● Cluster  ○ Scope  ○ Logs  ○ Sources  ○ Confirm

Qodo Scout · Setup
Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted.

Cluster
> development-cluster (codium-development)  CURRENT
  Choose another…

# Only after choosing "Choose another…":
Available clusters
development-cluster (codium-development)  CURRENT
customer-cluster (customer-project)

Checking read-only access…

✓ Cluster  ● Scope  ○ Logs  ○ Sources  ○ Confirm

Scope
> All application namespaces
  Choose namespaces…

✓ Cluster  ✓ Scope  ● Logs  ○ Sources  ○ Confirm

Log window
> 30 minutes
  1 hour
  6 hours
  Custom

✓ Cluster  ✓ Scope  ✓ Logs  ● Sources  ○ Confirm

Extra sources · optional
Kubernetes data is already included.
[ ] Prometheus
[ ] Phoenix
[ ] Zitadel check

✓ Cluster  ✓ Scope  ✓ Logs  ✓ Sources  ● Confirm

Output
> Automatic (~/.qodo-support-bundles)
  Custom path…

Ready to collect
Cluster   Development
Scope     All application namespaces
Logs      30 minutes
Extras    None
Output    Automatic

! Review before sharing
[ Collect ] [ Cancel ]
```

Set `ACCESSIBLE=1` to use Huh's plain accessible form mode. `--no-progress`
affects collection progress after setup; it does not disable the wizard.
`--mascot` is a deprecated no-op. `NO_COLOR` disables ANSI styling; redirected
and non-TTY output is plain.

Use `--namespaces qodo-onprem,rabbitmq-system` for several explicit namespaces,
or `--all-namespaces` for literal cluster-wide collection. The latter can
include unrelated workloads in shared clusters. `--selector` narrows pod
collection within each selected namespace. `--namespace` and `--namespaces`
are mutually exclusive.

Logs are requested with `kubectl logs --since <duration> --timestamps=true`.
Current and restarted-container previous logs are collected concurrently.
Defaults and hard bounds are:

- `--since 30m`
- `--command-timeout 2m` per Kubernetes command, maximum 30 minutes
- `--max-metadata-bytes 128 MiB` across staged pod, container-event, and event
  records, maximum 1 GiB
- `--max-log-bytes 10 MiB` per stream, maximum 100 MiB
- `--max-total-log-bytes 1 GiB`, maximum 8 GiB
- `--log-workers 8`, maximum 64

Workload collection separately bounds each raw API response to 8 MiB, each
normalized resource kind to 4 MiB, all normalized workload artifacts to
16 MiB, namespace scope to 100 namespaces, and total workload collection time
to 5 minutes.

Once the total log budget is exhausted, remaining log sources are skipped and
recorded as collection issues. The metadata budget is shared across every
selected namespace. Records are truncated only at complete JSONL line
boundaries; once exhausted, remaining metadata namespaces are not queried.
Truncation and skipped namespaces are reported as non-secret partial-collection
issues. Values matching the bundled redaction rules and multiline private keys
are removed before files are staged.

Exit code `0` means collection completed. Exit code `3` means a usable partial
bundle was created; inspect `collection-issues.jsonl`. Fatal setup, cancellation,
or archive failures return `1`; invalid CLI usage returns `2`.

Qodo Scout saves the archive locally. It does not upload or send the bundle.
Review it, then share it separately through the support channel approved for
the customer.

## Optional Prometheus telemetry

Prometheus collection is opt-in and uses a temporary loopback-only
`kubectl port-forward`:

```bash
qodo-support-bundle collect \
  --namespace qodo-onprem \
  --collect-prometheus \
  --prometheus-namespace prometheus
```

`--prometheus-namespace` identifies only the namespace hosting the Prometheus
service. With exactly one explicit workload namespace it may be omitted and is
inferred; it is required for multi-namespace, automatic, or all-namespace
collection. The telemetry queries remain restricted to the selected workload
namespace scope. The target service is discovered from fixed application labels
and port `9090`; arbitrary URLs, ports, labels, and PromQL are not accepted.

The versioned built-in catalog covers CPU, memory, restarts and OOMs, replica
availability, request rate, error rate, latency, CPU-throttling saturation, and
PVC capacity pressure. Collection uses the same `--since` window as logs and
enforces fixed deadlines and bounds on query count, response bytes, retained
bytes, series, and samples. Missing metrics are recorded as complete query
coverage with no data. Discovery, forwarding, or query failures produce a
usable partial bundle with sanitized coverage; cancellation and artifact
staging failures publish no bundle.

## Optional Phoenix trace telemetry

Phoenix collection is opt-in. General mode collects a bounded time window ending
at the collection timestamp:

```bash
qodo-support-bundle collect \
  --namespace qodo-onprem \
  --collect-phoenix \
  --phoenix-namespace qodo-onprem \
  --since 30m
```

Exact mode adds one trace ID. The value must be exactly 32 hexadecimal
characters and is normalized to lowercase:

```bash
qodo-support-bundle collect \
  --namespace qodo-onprem \
  --collect-phoenix \
  --phoenix-namespace qodo-onprem \
  --trace-id 0123456789ABCDEF0123456789ABCDEF
```

`--trace-id` and `--phoenix-namespace` are rejected unless
`--collect-phoenix` is enabled. With exactly one explicit collection namespace,
the Phoenix namespace may be omitted and is inferred. It is required for
multi-namespace, automatic, or all-namespace collection. Phoenix collection
uses `--since`, with a maximum window of 24 hours.

The collector discovers a Phoenix service with fixed application labels and
port `6006`. It never accepts an arbitrary URL, host, port, or query. It starts
`kubectl port-forward --address=127.0.0.1`, talks only to the resulting
loopback HTTP endpoint, and supervises and reaps the child process. Prometheus
and Phoenix run sequentially. They share one forwarder configuration when
their service namespace is the same; separate namespace-bound forwarders are
used when the namespaces differ.

Phoenix requests use fixed deadlines, pagination bounds, project/trace/span
limits, response limits, and per-trace and total retained-byte budgets. Output
contains normalized trace and span fields plus a non-reversible project
surrogate; raw project identifiers, responses, attributes, names, events,
status messages, and credentials are not retained. A successful no-data
response is complete coverage and may omit `phoenix/traces.jsonl`. Discovery,
forwarding, HTTP, schema, pagination, or retention-limit failures produce a
usable partial bundle with stable reason codes in `phoenix/coverage.json` and
`collection-issues.jsonl`. Cancellation and artifact staging failures publish
no bundle.

## Optional Zitadel connectivity probe

The probe runs only when explicitly requested:

```bash
qodo-support-bundle collect \
  --namespace qodo-onprem \
  --check-zitadel \
  --platform-pod platform-0 \
  --platform-container platform
```

With exactly one explicit collection namespace, `--platform-namespace` is
inferred. It is required for multi-namespace, automatic, or all-namespace
collection:

```bash
qodo-support-bundle collect \
  --all-namespaces \
  --check-zitadel \
  --platform-namespace qodo-onprem \
  --platform-pod platform-0 \
  --platform-container platform \
  --probe-timeout 15s
```

All target values are required with `--check-zitadel`, and target/probe flags
are rejected without it. Names are validated as DNS-compatible Kubernetes
names. Before exec, the CLI performs a bounded exact-pod query and verifies
that the selected pod and container are running. The pod preflight has its own
2 MiB bound so ordinary Pod metadata does not consume the probe's stricter
output allowance.

The probe source is embedded in the Go binary. The CLI passes it to the
container as one `kubectl exec` argument and invokes `python -B -c` without a
shell, TTY, upload, installed helper, or workload change. The container must
already provide Python, Platform's `simple_settings`, and HTTPX.

Inside the container, the probe:

- accepts Platform `zitadel` and `oidc` client types and validates the configured
  public HTTPS issuer;
- uses Platform's configured internal Zitadel API URL and safe forwarding
  headers when present, while validating responses against the public issuer;
- honors HTTPX's normal proxy and CA environment behavior;
- sends no authorization or cookie and uses a fresh client for each request;
- requests only `/.well-known/openid-configuration` and `/oauth/v2/keys`;
- never follows redirects and requests identity encoding;
- rejects compressed, oversized (over 256 KiB), malformed, or schema-invalid
  responses;
- requires the exact configured issuer, fixed JWKS URI, and nonempty valid
  RSA, EC, or OKP public-key shapes;
- has an in-pod real-time deadline in addition to the local kubectl deadline;
- suppresses settings/import stdout and stderr and emits only bounded
  schema-v1 JSON with fixed status and reason constants.

Probe stdout is capped at 32 KiB. Response bodies, exception strings, kubectl
stderr, tokens, cookies, and settings dumps are never retained. Valid
configuration or connectivity failures are diagnostic findings and do not make
an otherwise complete bundle partial. Failure to execute, read, or strictly
validate the report makes the bundle partial. A valid report is stored at
`connectivity/zitadel.json`; the summary and manifest record concise probe
metadata. The probe does not test login, browser redirects, token issuance, or
end-user authentication.

## Archive contents and integrity

```text
manifest.json
summary.md
checksums.sha256
kubernetes/pods.jsonl
kubernetes/events.jsonl
kubernetes/container_events.jsonl
kubernetes/logs/<pod>/<container>.log
kubernetes/workloads.jsonl                 # present when records are retained
kubernetes/services.jsonl                  # present when records are retained
kubernetes/autoscalers.jsonl               # present when records are retained
kubernetes/storage.jsonl                   # present when records are retained
kubernetes/workload-coverage.json
prometheus/metrics.jsonl                  # optional; present when records exist
prometheus/coverage.json                  # present when Prometheus is requested
phoenix/traces.jsonl                      # optional; present when traces exist
phoenix/coverage.json                     # present when Phoenix is requested
connectivity/zitadel.json                 # optional
collection-issues.jsonl                   # partial collection only
```

Pod, event, and log paths include the namespace below `kubernetes/` in
multi-namespace bundles. Normalized workload JSONL paths remain flat and combine
records from all selected namespaces; every record identifies its namespace.
Categories with no retained records have no JSONL file. The schema-version 4
manifest identifies the normalized workload-context format and records
collector version, timestamp, redaction rules, scope, limits, Kubernetes
statistics, connectivity metadata, and each artifact's size and SHA-256.
It also records bounded Prometheus and Phoenix configuration and aggregate
coverage metadata when those sources are requested.
`checksums.sha256` includes every artifact and the manifest.

After safe extraction, verify embedded integrity:

```bash
shasum -a 256 -c checksums.sha256
```

### Manual workload smoke test

Build the current source and collect one namespace that contains representative
applications. The collector is read-only; this does not create or modify
cluster resources:

```bash
NAMESPACE=qodo-onprem
make build VERSION=manual

TEST_DIR="$(mktemp -d)"
ARCHIVE="$TEST_DIR/bundle.tar.gz"
./dist/qodo-support-bundle collect \
  --namespace "$NAMESPACE" \
  --output "$ARCHIVE"

mkdir "$TEST_DIR/extracted"
tar -xzf "$ARCHIVE" -C "$TEST_DIR/extracted"
```

Verify archive integrity, schema 4, all nine namespace/resource coverage rows,
and the four normalized JSONL artifacts:

```bash
(
  set -e
  cd "$TEST_DIR/extracted"
  shasum -a 256 -c checksums.sha256
  jq -e '.schema_version == "4"' manifest.json
  jq -e --arg namespace "$NAMESPACE" '
    .namespaces == [$namespace] and
    (.coverage | length == 9) and
    all(.coverage[]; .namespace == $namespace)
  ' kubernetes/workload-coverage.json

  for artifact in \
    kubernetes/workloads.jsonl \
    kubernetes/services.jsonl \
    kubernetes/autoscalers.jsonl \
    kubernetes/storage.jsonl
  do
    if [ -f "$artifact" ]; then
      jq -e -s 'all(.[]; type == "object")' "$artifact" || exit 1
    fi
  done
)
```

Inspect `kubernetes/workload-coverage.json` for `partial`, `failed`, or
`skipped` entries. Exit code `3` and `collection-issues.jsonl` indicate a usable
partial bundle, commonly caused by missing RBAC for one of the resource kinds.
An absent normalized JSONL category means that no records for it were retained;
the coverage file remains authoritative for whether its API requests succeeded.
Review normalized artifacts before sharing; they must not contain raw
manifests, Secrets, ConfigMaps, endpoint addresses, environment values,
commands, arguments, annotations, or volume contents.

### Manual Prometheus smoke test

Choose one workload namespace and the namespace hosting its Prometheus service:

```bash
NAMESPACE=qodo-onprem
PROMETHEUS_NAMESPACE=prometheus
make build VERSION=manual

TEST_DIR="$(mktemp -d)"
ARCHIVE="$TEST_DIR/bundle.tar.gz"
./dist/qodo-support-bundle collect \
  --namespace "$NAMESPACE" \
  --collect-prometheus \
  --prometheus-namespace "$PROMETHEUS_NAMESPACE" \
  --since 30m \
  --output "$ARCHIVE"

mkdir "$TEST_DIR/extracted"
tar -xzf "$ARCHIVE" -C "$TEST_DIR/extracted"
(
  set -e
  cd "$TEST_DIR/extracted"
  shasum -a 256 -c checksums.sha256
  jq -e '.schema_version == "4"' manifest.json
  jq -e \
    --arg namespace "$NAMESPACE" \
    '.requested_start < .requested_end and
     (.coverage | length > 0) and
     all(.coverage[]; .state == "collected" or
                      .state == "no_data" or
                      .state == "partial" or
                      .state == "failed" or
                      .state == "skipped")' \
    prometheus/coverage.json
  if [ -f prometheus/metrics.jsonl ]; then
    jq -e -s --arg namespace "$NAMESPACE" \
      'all(.[]; type == "object" and .labels.namespace == $namespace)' \
      prometheus/metrics.jsonl
  fi
)
```

Inspect `prometheus/coverage.json` even when `metrics.jsonl` is absent. Verify
that retained labels contain only the selected workload namespace and that no
`kubectl port-forward` child remains after the command exits.

### Manual Phoenix smoke test

Choose the namespace containing the Phoenix service. This procedure accepts
either a complete run (exit `0`) or a usable partial run (exit `3`); it does not
claim live acceptance until an operator runs it against the target cluster.
Leave `TRACE_ID` empty for general-window mode, or set an exact 32-character
hexadecimal ID:

```bash
(
  set -e
  NAMESPACE=qodo-onprem
  PHOENIX_NAMESPACE=qodo-onprem
  TRACE_ID=

  make build VERSION=manual
  TEST_DIR="$(mktemp -d)"
  ARCHIVE="$TEST_DIR/bundle.tar.gz"
  EXTRACTED="$TEST_DIR/extracted"
  mkdir "$EXTRACTED"

  set -- \
    ./dist/qodo-support-bundle collect \
    --namespace "$NAMESPACE" \
    --collect-phoenix \
    --phoenix-namespace "$PHOENIX_NAMESPACE" \
    --since 30m \
    --output "$ARCHIVE"
  if [ -n "$TRACE_ID" ]; then
    set -- "$@" --trace-id "$TRACE_ID"
  fi

  if "$@"; then
    STATUS=0
  else
    STATUS=$?
  fi
  [ "$STATUS" -eq 0 ] || [ "$STATUS" -eq 3 ]

  tar -xzf "$ARCHIVE" -C "$EXTRACTED"
  cd "$EXTRACTED"
  shasum -a 256 -c checksums.sha256
  jq -e '.schema_version == "4"' manifest.json
  jq -e '
    .contract_version == "arize-phoenix-rest-v1-15.5.1" and
    (.mode == "window" or .mode == "trace_id") and
    (.state == "complete" or .state == "partial" or .state == "failed") and
    (.coverage.state == "collected" or
     .coverage.state == "no_data" or
     .coverage.state == "partial" or
     .coverage.state == "failed")
  ' phoenix/coverage.json

  if [ -f phoenix/traces.jsonl ]; then
    jq -e -s '
      length > 0 and
      all(.[];
        .schema_version == "1" and
        (.trace_id | test("^[0-9a-f]{32}$")) and
        (.spans | type == "array"))
    ' phoenix/traces.jsonl
  fi
  if [ -f collection-issues.jsonl ]; then
    jq -e -s 'all(.[]; type == "object")' collection-issues.jsonl
  fi

  if pgrep -f '[k]ubectl.*port-forward.*:6006' >/dev/null; then
    echo "Phoenix kubectl port-forward process remains" >&2
    exit 1
  fi
)
```

Inspect `phoenix/coverage.json` even when `phoenix/traces.jsonl` is absent.
Exit `3` is expected for bounded partial behavior; review the stable reason and
`collection-issues.jsonl` before sharing the bundle.

Checksums detect corruption but do not authenticate provenance. Treat bundles
as sensitive, review them before sharing, and use an approved authenticated
channel.

Official release binaries include six targets (Linux amd64/arm64, macOS
amd64/arm64, and Windows amd64/arm64), distribution checksums, and GitHub build
provenance. Verify a downloaded binary with:

```bash
gh attestation verify ./qodo-support-bundle-linux-amd64 \
  --repo qodo-ai/qodo-support-bundle
```

After a GitHub release is validated, the manually dispatched dev-publication
workflow downloads and verifies all ten asset attestations before publishing
the exact bytes to the existing Qodo CLI dev-canary bucket:

```text
gs://qodo-cli-public-dev/support-bundle/releases/<version>/
```

After canary validation, the manually approved promotion workflow independently
downloads and verifies the attested GitHub release, rejects any dev-canary
object that is not byte-identical to it, and promotes those bytes without
rebuilding. Stable installers are validated before `version.json` is updated:

```text
gs://qodo-cli-public/support-bundle/releases/<version>/
https://get.qodo.ai/support-bundle/releases/<version>/
```

The Qodo CLI continues to own the bucket root. Support Bundle workflows operate
only under `support-bundle/`. Versioned uploads use create-only exact-object
requests; stable installers and metadata use generation CAS. Identical reruns
succeed without overwriting, conflicts fail, and semantic version checks prevent
pointer rollback. The publisher does not need `storage.objects.list` or delete
permission. See [the exact object, ordering, cache, and rollback contract](docs/publication.md).

## Customer delivery

For a customer workstation that can reach GitHub, provide the matching binary,
`checksums.sha256`, and the release URL. The customer verifies the binary after
download, makes it executable on Linux or macOS, and runs it from any directory:

```bash
grep ' qodo-support-bundle-darwin-arm64$' checksums.sha256 | shasum -a 256 -c -
chmod 700 qodo-support-bundle-darwin-arm64
./qodo-support-bundle-darwin-arm64 collect --context customer-production
```

For a customer environment that cannot reach Qodo or GitHub, Support downloads
the same release binary and checksum on an approved connected workstation,
verifies them, and places them together in the existing case-specific customer
handoff ZIP. Deliver that ZIP through the channel already approved for the
customer, such as a private support-case attachment or authenticated,
time-limited download. The customer transfers it to the operator workstation
and verifies the checksum again before running it. No cluster image, Helm
upgrade, sidecar, or permanent installation is required.

## Build, test, and release

The integration tests execute the embedded probe against local HTTP, TLS, and
proxy fixtures. They require Python 3.12 and the hash-locked HTTPX environment:

```bash
make test-python-deps
make test
make build VERSION=dev
make release VERSION=1.0.0
```

`make test-python-deps` creates the ignored `.test-venv` and installs only
`test-requirements.txt` with pip `--require-hashes --only-binary=:all:`.
`make test` fails with a prerequisite message when that environment is absent;
the network tests never silently skip. The release workflow creates the same
environment in both validation and release jobs before testing.

Pull requests and releases run an end-to-end CLI smoke test on GitHub-hosted
Linux, macOS, and Windows runners. The test builds the native binary, executes
it against a controlled fake `kubectl`, and validates the resulting archive,
checksums, and redaction without using cluster credentials.

The release workflow also tests the module, cross-compiles all six platforms,
generates `dist/checksums.sha256`, attests all assets, stores the workflow
artifact, and uploads assets to an existing matching GitHub release. Release
publishing waits for every native smoke job. Manual dispatch must run from the
same release tag ref and provide that tag.
