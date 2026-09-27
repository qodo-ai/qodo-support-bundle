# Qodo Support Bundle

`qodo-support-bundle` is a portable, read-only CLI for collecting bounded and
redacted Kubernetes diagnostics. It collects pod metadata, events, current and
previous container logs, and an optional Platform-to-Zitadel connectivity
report.

## Prerequisites and scope

- A release binary for the operator's platform.
- `kubectl` configured for the target cluster.
- Read access to pods, pod logs, and events in each collected namespace.
- Cluster-scoped `list` access to namespaces only when automatic discovery or
  `--all-namespaces` is used.
- `pods/exec` permission only when `--check-zitadel` is requested.

The collector never requests Secrets, ConfigMaps, or new workload resources,
and it does not retain workload environment variables from the Pod metadata it
reads. A namespace-scoped baseline role is:

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

For the optional probe, add `create` on `pods/exec` only in the selected
Platform namespace and remove temporary bindings after collection.

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

Once the total log budget is exhausted, remaining streams are skipped and
recorded as collection issues. The metadata budget is shared across every
selected namespace. Records are truncated only at complete JSONL line
boundaries; once exhausted, remaining metadata namespaces are not queried.
Truncation and skipped namespaces are reported as non-secret partial-collection
issues. Values matching the bundled redaction rules and multiline private keys
are removed before files are staged.

Exit code `0` means collection completed. Exit code `3` means a usable partial
bundle was created; inspect `collection-issues.jsonl`. Fatal setup, cancellation,
or archive failures return `1`; invalid CLI usage returns `2`.

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
connectivity/zitadel.json                 # optional
collection-issues.jsonl                   # partial collection only
```

Multi-namespace paths include the namespace below `kubernetes/`. The
schema-version 3 manifest identifies the Kubernetes-only archive format and
records collector version, timestamp, redaction rules, scope, limits,
Kubernetes statistics, connectivity metadata, and each artifact's size and
SHA-256. `checksums.sha256` includes every artifact and the manifest.

After safe extraction, verify embedded integrity:

```bash
shasum -a 256 -c checksums.sha256
```

Checksums detect corruption but do not authenticate provenance. Treat bundles
as sensitive, review them before sharing, and use an approved authenticated
channel.

Official release binaries include five targets (Linux amd64/arm64, macOS
amd64/arm64, and Windows amd64), distribution checksums, and GitHub build
provenance. Verify a downloaded binary with:

```bash
gh attestation verify ./qodo-support-bundle-linux-amd64 \
  --repo Codium-ai/qodo-platform
```

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

The release workflow tests the module, cross-compiles all five platforms,
generates `dist/checksums.sha256`, attests all assets, stores the workflow
artifact, and uploads assets to an existing matching GitHub release. Manual
dispatch must run from the same release tag ref and provide that tag.
