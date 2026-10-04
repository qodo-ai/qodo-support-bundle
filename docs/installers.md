# Qodo Scout installers

`install.sh` and `install.ps1` provide the customer-side installation flow for
Qodo Scout. They detect the supported platform, resolve a release, download one
binary and its checksum manifest, verify the exact artifact, install it under
the stable `qodo-scout` name, and run only the non-collecting `version` command.
Collection starts only when the customer runs:

```text
qodo-scout collect --interactive
```

## Publication status

Publication is implemented as manually dispatched dev and approved production
workflows. Merging the implementation does not run either workflow. The URLs
below return 404 until an operator publishes and promotes the first release.
See [the publication contract and runbook](publication.md).

After publication, macOS and Linux customers can inspect and run:

```sh
curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  -o install.sh \
  https://get.qodo.ai/support-bundle/install.sh
less install.sh
sh ./install.sh --add-to-path
```

Windows customers can inspect and run from PowerShell:

```powershell
curl.exe --fail --location --proto '=https' --tlsv1.2 `
  --proto-redir '=https' `
  --output install.ps1 `
  https://get.qodo.ai/support-bundle/install.ps1
Get-Content .\install.ps1
& .\install.ps1 -AddToPath
```

For convenience, the same endpoints can be executed without saving a copy:

```sh
curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://get.qodo.ai/support-bundle/install.sh |
  sh -s -- --add-to-path
```

```powershell
& {
  $installer = Join-Path ([IO.Path]::GetTempPath()) (
    'qodo-scout-install-{0}.ps1' -f [guid]::NewGuid()
  )
  try {
    curl.exe --fail --location --proto '=https' --proto-redir '=https' `
      --tlsv1.2 --output $installer `
      https://get.qodo.ai/support-bundle/install.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Installer download failed' }
    & $installer -AddToPath
    if (-not $?) { throw 'Installer execution failed' }
  } finally {
    Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
  }
}
```

The convenience form is less inspectable: it executes without a review step.
The Windows form still invokes a temporary script file so normal PowerShell
execution policy applies, then removes that file. Prefer the
download-inspect-run form for production and regulated workstations.

If the installer adds a previously absent directory to the user PATH, open a
new terminal before using the short command. The installer also prints a
full-path command that works immediately. Neither installer requests
administrator privileges or changes machine-wide PATH configuration.

To install a known release for reproducibility or rollback:

```sh
sh ./install.sh --version 0.2.0 --add-to-path
```

```powershell
& .\install.ps1 -Version 0.2.0 -AddToPath
```

The published artifact names remain
`qodo-support-bundle-<os>-<arch>[.exe]` internally. Customers use the installed
`qodo-scout` command.

## Supported platforms

- macOS amd64 and arm64
- Linux amd64 and arm64
- Windows amd64 and arm64

Windows ARM64 installs the native ARM64 binary rather than selecting the amd64
artifact through emulation. CI exercises the release binary and local installer
on the `windows-11-arm` GitHub-hosted runner.

The installers determine the operating system and runtime CPU automatically.
They reject unsupported systems instead of falling back to a different
artifact. The default install locations are:

```text
macOS/Linux: ${XDG_BIN_HOME:-$HOME/.local/bin}/qodo-scout
Windows:     %LOCALAPPDATA%\Qodo\bin\qodo-scout.exe
```

Use `--install-dir` or `-InstallDir` with an absolute, user-owned directory to
override that location. `--add-to-path` and `-AddToPath` update only the current
user's shell profile or user PATH.

## Air-gapped installation

An approved local directory may contain the platform binary and the release's
`checksums.sha256`. The release version remains explicit:

```sh
sh ./install.sh \
  --version 0.2.0 \
  --source-dir /approved/qodo-scout-release \
  --add-to-path
```

```powershell
& .\install.ps1 `
  -Version 0.2.0 `
  -SourceDir C:\Approved\QodoScoutRelease `
  -AddToPath
```

Local mode performs no network requests and applies the same exact-row SHA-256
verification as connected mode.

At minimum, the approved handoff must contain the installer for the customer's
operating system, the selected platform binary, and the release's binary
manifest:

```text
install.sh or install.ps1
checksums.sha256
qodo-support-bundle-<os>-<arch>[.exe]
```

Also retain the release version and source release URL in the approved handoff
record. Support should verify the connected copy before transfer; the customer
verifies it again offline.

## `version.json` contract

The unversioned metadata response has exactly one string property:

```json
{ "version": "0.2.0" }
```

Installers reject additional properties, missing values, non-string values, and
versions outside the release version grammar. A resolved release uses:

```text
https://get.qodo.ai/support-bundle/releases/<version>/
```

The publication workflow updates `version.json` atomically only after every
production artifact, manifest, and stable installer has been published and
verified. Metadata uses
`Cache-Control: no-cache, max-age=0, must-revalidate`; immutable release
objects retain one-year immutable caching. No live-current metadata file is
committed to the repository because it could drift from production.

## Security and proxy behavior

Network mode uses `curl` or `curl.exe`, which preserves normal proxy environment
and system trust behavior. The installers do not print proxy configuration or
credentials. They do not remove macOS quarantine, delete Windows
Mark-of-the-Web data, call `xattr -d` or `Unblock-File`, change PowerShell
execution policy, or weaken endpoint security controls.

Downloading with `curl` or `curl.exe` may avoid browser-added quarantine or
Mark-of-the-Web metadata, depending on the operating system and enterprise
configuration. That is not code signing and does not guarantee acceptance by
Gatekeeper, SmartScreen, WDAC, AppLocker, antivirus, EDR, or other enterprise
policy. Follow the customer's normal approval process; do not disable controls.

Set the standard `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` variables when the
workstation requires a proxy. PowerShell uses the environment inherited by
`curl.exe`. Private-CA environments must install the CA through the operating
system's approved trust mechanism; the installers do not bypass TLS checks.

## Verification and provenance

Both installers download `checksums.sha256`, require exactly one valid row for
the selected artifact, and compare its SHA-256 before replacing an existing
installation. A failed checksum or `version` smoke check leaves or restores the
previous executable.

For independent provenance verification, download the versioned release assets
from the matching GitHub release and verify their attestations:

```sh
release_tag=v0.2.0
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

The GitHub release also carries `installer-checksums.sha256` for `install.sh`
and `install.ps1`. It is separate from the binary-only manifest consumed by the
installers, avoiding circular self-verification. SHA-256 detects corruption;
the GitHub attestation binds an asset to the repository release workflow.

## Kubernetes prerequisites

Installation itself does not contact a cluster. Before collection, the
operator needs:

- `kubectl` on `PATH`;
- a kubeconfig and the intended current or explicitly selected context;
- any provider authentication plugin required by that kubeconfig;
- network access from the workstation to the Kubernetes API and any explicitly
  selected in-cluster telemetry endpoint reached through `kubectl`;
- the documented read RBAC, plus optional `pods/portforward` or `pods/exec`
  permissions only for features the operator selects; and
- a writable local filesystem for the owner-only output directory and archive.

The customer owns credentials, provider-plugin installation, kubeconfig
selection, and RBAC grants. Qodo Scout does not provision or retain them.

## Uninstall

Remove the installed executable:

```sh
rm -- "${XDG_BIN_HOME:-$HOME/.local/bin}/qodo-scout"
```

If `--add-to-path` was used, edit the reported profile (`~/.zprofile`,
`~/.bash_profile`, or `~/.profile`) and remove the `# qodo-scout installer`
line and its following PATH export. Preserve unrelated profile content.

On Windows:

```powershell
$installDir = Join-Path $env:LOCALAPPDATA 'Qodo\bin'
Remove-Item -LiteralPath (Join-Path $installDir 'qodo-scout.exe')
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$updated = (($userPath -split ';') | Where-Object {
  $_ -and -not $_.TrimEnd('\').Equals(
    $installDir.TrimEnd('\'),
    [StringComparison]::OrdinalIgnoreCase
  )
}) -join ';'
[Environment]::SetEnvironmentVariable('Path', $updated, 'User')
```

Open a new terminal after a PATH change. If a custom install directory was
used, substitute that exact directory.

## Troubleshooting

- **Stable URL returns 404:** expected before the first approved production
  promotion. Maintainers should verify publication status; customers should not
  substitute an unapproved URL.
- **`curl` or checksum tool missing:** install `curl` and either `sha256sum` or
  `shasum` through the workstation's approved software channel. Windows uses
  built-in `curl.exe` and `Get-FileHash`.
- **Command not found after installation:** open a new shell, apply the exact
  PATH command printed by the installer, or invoke the printed full path.
- **Unsupported platform:** confirm the native OS and CPU. Supported values are
  macOS/Linux amd64 or arm64 and Windows X64 or Arm64.
- **TLS, proxy, Gatekeeper, SmartScreen, or policy failure:** preserve the
  error and involve the customer's network or endpoint-security administrator.
  Do not bypass certificate validation or security policy.
- **Kubernetes authentication or authorization failure:** verify `kubectl`
  works with the intended context and that the customer-provided identity has
  the documented read permissions.
