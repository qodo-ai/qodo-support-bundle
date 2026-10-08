# Qodo Scout

<img src="docs/assets/qodo-scout-logo.jpg" alt="Qodo Scout logo: a magnifying glass inspecting protected diagnostics" width="160">

[![Qodo Scout version v0.3.1](https://img.shields.io/badge/version-v0.3.1-blue?style=flat-square)](https://github.com/qodo-ai/qodo-support-bundle/releases/tag/v0.3.1)
![Supported platforms: macOS, Linux, and Windows](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-informational?style=flat-square)
![Safety: read-only diagnostic collection](https://img.shields.io/badge/safety-read--only%20diagnostic%20collection-success?style=flat-square)

Qodo Scout collects redacted Kubernetes diagnostics into a local support
archive using your existing `kubectl` access. Nothing is uploaded
automatically—you review the archive and decide whether to share it.

Scout runs on your workstation without deploying anything to the cluster.
Native binaries are available for macOS, Linux, and Windows; no Go installation
is required.

## Install

The installers select the native binary for your OS and architecture, download
the immutable **0.3.1** release, and verify its SHA-256 before installing the
`qodo-scout` command. Installation runs only a local version check; it does not
contact your cluster or start collection.

Supported targets: **macOS, Linux, and Windows**, each on **amd64 and arm64**.
For manual installation, download your platform's binary from the
[v0.3.1 release](https://github.com/qodo-ai/qodo-support-bundle/releases/tag/v0.3.1).
See [Verify your download](#verify-your-download) for independent provenance
verification before running an installer or binary.

### macOS and Linux

```bash
rm -f ./install-qodo-scout.sh
curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  -o ./install-qodo-scout.sh \
  https://get.qodo.ai/support-bundle/releases/0.3.1/install.sh &&
  sh ./install-qodo-scout.sh --version 0.3.1 --add-to-path
```

Use the installed command immediately in the same shell:

```bash
"${XDG_BIN_HOME:-$HOME/.local/bin}/qodo-scout" collect --interactive
```

### Windows

Run this in **Command Prompt (cmd.exe)**:

```bat
curl.exe -fSLo "%TEMP%\install-qodo-scout.ps1" "https://get.qodo.ai/support-bundle/releases/0.3.1/install.ps1" && powershell.exe -NoProfile -File "%TEMP%\install-qodo-scout.ps1" -Version 0.3.1 -AddToPath
```

Use the installed command immediately in the same Command Prompt session:

```bat
"%LOCALAPPDATA%\Qodo\bin\qodo-scout.exe" collect --interactive
```

For download-inspect-run instructions, air-gapped installation, proxies, custom
install locations, and uninstall steps, see the
[installer guide](docs/installers.md).

## Quick start

Before collecting, make sure:

- `kubectl` is on `PATH` and works with the intended kubeconfig and context.
- Any cloud-provider authentication helper required by that kubeconfig is
  installed and configured.
- You can reach the Kubernetes API and have the
  [required permissions](#safety-and-permissions).
- Your local filesystem has a writable location for the archive.

After installation, open a new terminal and start the guided flow:

```bash
qodo-scout collect --interactive
```

The wizard lets you select the context, namespaces, log window, optional data
sources, and output path before asking for confirmation.

For scripted collection, set the scope explicitly. Replace the example context
and namespace with your own:

```bash
qodo-scout collect \
  --context customer-production \
  --namespace qodo-onprem \
  --since 30m \
  --output ./qodo-support-bundle.tar.gz
```

Use `--kubeconfig` to select a different kubeconfig file, or `--namespaces` for a
comma-separated list. Run `qodo-scout collect --help` for all flags and collection
limits. See the [collection guide](docs/collection.md) for automation and
optional-source examples.

## What it collects

| Source | Collected information |
| --- | --- |
| Kubernetes | Sanitized pod and workload records, events, and bounded pod logs within the selected scope |
| Workload resources | Sanitized service, endpoint slice, persistent volume claim, and horizontal pod autoscaler records |
| Prometheus and Phoenix (opt-in) | Bounded telemetry queries through temporary, loopback-only `kubectl port-forward` sessions |
| Zitadel check (opt-in) | Connectivity diagnostics from an explicitly selected Platform pod and container through `kubectl exec` |

Scout never requests Kubernetes Secrets or ConfigMaps. Raw manifests,
environment values, command arguments, annotations, endpoint addresses, and
volume contents are omitted.

## Safety and permissions

- **Local and read-only:** Scout does not create or mutate Kubernetes resources,
  provision credentials, or grant permissions. You control the kubeconfig,
  authentication, and RBAC.
- **Scoped access:** Baseline collection requires `get` and `list` access to the
  supported namespace-scoped resources, plus `get` on `pods/log`. Namespace
  discovery and `--all-namespaces` additionally require cluster-scoped `list`
  access to namespaces.
- **Optional permissions:** Only selected Prometheus or Phoenix collection
  requires `create` on `pods/portforward`; only the selected Zitadel check
  requires `create` on `pods/exec`.
- **Bounded collection:** Log windows, byte limits, timeouts, and concurrency
  limits constrain collection.
- **Review before sharing:** Redaction reduces exposure but is not a guarantee
  that an archive is free of sensitive data. Treat every archive as sensitive
  and share it only through an approved support channel.

See the [security model](docs/security-model.md) for the full RBAC resource list,
trust boundaries, and platform-security limitations.

## Output

By default, archives are saved under `~/qodo-support-bundles/`:

```text
qodo-support-bundle-<UTC timestamp>-<random suffix>.tar.gz
```

Each archive contains redacted diagnostic records and these review files:

| File | Purpose |
| --- | --- |
| `summary.md` | Collection summary and coverage |
| `manifest.json` | Bundle metadata and artifact inventory |
| `checksums.sha256` | Integrity checks for the archive's contents |
| `collection-issues.jsonl` | Collection issues when the result is partial |

Output directories and archives use owner-only permissions where supported.
An explicit `--output` path is never overwritten.

Exit `0` means collection completed. Exit `3` means a usable **partial archive**
was created; inspect `collection-issues.jsonl` before sharing it. See
[output and exit behavior](docs/collection.md#output-and-exit-behavior) for the
full exit-code contract and archive-integrity instructions.

## Verify your download

The installers verify each binary against the release's `checksums.sha256`.
The release also provides `installer-checksums.sha256` for the installer scripts.
Checksums detect corruption, but a checksum downloaded alongside a binary does
not by itself authenticate the publisher.

Release assets also have **signed GitHub build attestations**. This is a
separate verification step; the installers do not verify attestations for you.
Before execution, use the [GitHub CLI](https://cli.github.com/) to verify a
downloaded asset against the repository, release workflow, tag, and commit.

For example, from the directory containing the downloaded Linux amd64 binary,
run the following in a POSIX shell:

```sh
release_tag=v0.3.1
release_sha="$(
  gh api "repos/qodo-ai/qodo-support-bundle/commits/$release_tag" --jq .sha
)"
gh attestation verify ./qodo-support-bundle-linux-amd64 \
  --repo qodo-ai/qodo-support-bundle \
  --signer-workflow \
    qodo-ai/qodo-support-bundle/.github/workflows/release-support-bundle.yaml \
  --source-digest "$release_sha" \
  --source-ref "refs/tags/$release_tag"
```

Use the filename for your platform or installer script, and keep the release
tag matched to the download. Do not run an asset if verification fails.
Attestations establish provenance, not that software is free of vulnerabilities;
they do not replace macOS code signing/notarization or Windows Authenticode.
See [verification and provenance](docs/installers.md#verification-and-provenance)
and [air-gapped installation](docs/installers.md#air-gapped-installation) for
details.

## Documentation

- [Collection guide](docs/collection.md) — automation flags, optional sources,
  archive behavior, and integrity checks.
- [Installer guide](docs/installers.md) — supported platforms, offline setup,
  verification, proxies, troubleshooting, and uninstall.
- [Security model](docs/security-model.md) — trust boundaries, Kubernetes RBAC,
  data handling, and platform assurance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, build and test
commands, and pull request guidance. Do not attach customer archives, credentials,
or unredacted diagnostic output to public issues or pull requests.

Maintainers: see the [publication runbook](docs/publication.md) and
[public distribution readiness checklist](docs/public-readiness.md).

## Security

Report suspected vulnerabilities privately to
[security@qodo.ai](mailto:security@qodo.ai), not in a public issue. See
[SECURITY.md](SECURITY.md) for reporting guidance and supported-version policy.
