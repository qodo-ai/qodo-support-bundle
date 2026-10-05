# Qodo Scout security model

## Trust and data boundaries

Qodo Scout is a local, read-only diagnostic collector. Installation downloads
one platform binary and verifies it against the release checksum manifest. The
installer runs only `qodo-scout version`; collection starts only after the
operator explicitly runs `qodo-scout collect`.

The operator workstation is the main trust boundary:

- the customer supplies and controls kubeconfig credentials, cloud-provider
  authentication plugins, Kubernetes RBAC, proxy configuration, and endpoint
  policy;
- Qodo Scout invokes the local `kubectl` with the selected kubeconfig and
  context and does not provision credentials or permissions;
- collected data and the final archive remain on the local filesystem until
  the customer shares them through an approved channel; and
- optional Prometheus, Phoenix, and Zitadel operations occur only when selected
  and use the bounded behaviors documented in the
  [collection guide](collection.md).

The distribution boundary consists of GitHub release provenance and immutable,
version-specific GCS objects. Publication verifies exact bytes and headers in
dev and requires production approval. There are no mutable aliases, latest
metadata, or publication locks in the supported contract. See
[the publication runbook](publication.md).

## Kubernetes RBAC

The baseline namespace role needs `get` and `list` access to:

- pods, events, services, and persistent volume claims;
- deployments, stateful sets, and daemon sets;
- jobs and cron jobs;
- endpoint slices; and
- horizontal pod autoscalers.

Pod logs require only `get` on the `pods/log` subresource. Qodo Scout never
requests Secrets or ConfigMaps. Automatic namespace discovery and
`--all-namespaces` additionally require cluster-scoped `list` access to
namespaces. Optional collection requires narrowly scoped `create` access only
for the selected feature:

- `pods/portforward` in each selected Prometheus or Phoenix service namespace;
- `pods/exec` in the selected Platform namespace for the Zitadel check.

Remove temporary bindings after collection. The customer controls all RBAC
grants; Qodo Scout does not create roles or bindings.

## Explicit non-goals

The installer and collector do not:

- disable or bypass Gatekeeper, SmartScreen, WDAC, AppLocker, antivirus, EDR,
  PowerShell execution policy, TLS validation, or proxy controls;
- remove macOS quarantine or Windows Mark-of-the-Web metadata;
- request administrator or `sudo` privileges by default;
- create Kubernetes workloads, mutate customer resources, request Secret
  objects, install cloud authentication plugins, or upload an archive; or
- make a checksum equivalent to code signing. Platform signing and
  notarization require separate security and release approval.

## Supported-platform assurance

- **Linux amd64:** `qodo-support-bundle-linux-amd64`; Go cross-build, ELF
  x86-64 inspection, and GitHub-hosted Linux smoke.
- **Linux arm64:** `qodo-support-bundle-linux-arm64`; Go cross-build, ELF
  AArch64 inspection, and GitHub-hosted Ubuntu ARM smoke.
- **macOS amd64:** `qodo-support-bundle-darwin-amd64`; Go cross-build, Mach-O
  x86_64 inspection, and GitHub-hosted macOS smoke.
- **macOS arm64:** `qodo-support-bundle-darwin-arm64`; Go cross-build, Mach-O
  arm64 inspection, and GitHub-hosted macOS ARM smoke.
- **Windows amd64:** `qodo-support-bundle-windows-amd64.exe`; Go cross-build,
  PE32+ x86-64 inspection, and GitHub-hosted Windows smoke.
- **Windows arm64:** `qodo-support-bundle-windows-arm64.exe`; Go cross-build,
  PE32+ AArch64 inspection, and native binary and installer smoke on
  `windows-11-arm`.

Native installer smoke tests validate artifact selection, checksum handling,
installation, startup, and exact `version` output without customer credentials.
The broader test suite covers bounded collection, archive integrity, and
redaction. These tests do not certify every enterprise endpoint policy or
Kubernetes provider integration.

## Security reporting

Report suspected vulnerabilities privately as described in
[`SECURITY.md`](../SECURITY.md). Do not include credentials, customer data,
kubeconfig content, support archives, or exploit details in a public issue.
