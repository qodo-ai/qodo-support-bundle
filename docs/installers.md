# Qodo Scout installers

`install.sh` and `install.ps1` provide the customer-side installation flow for
Qodo Scout. They require an explicit version, detect the supported platform,
download one binary and its checksum manifest from that immutable release,
verify the exact artifact, install it as `qodo-scout`, and run only the
non-collecting `version` command.
Collection starts only when the customer runs:

```text
qodo-scout collect --interactive
```

## Publication status

Version 0.3.1 is published at the immutable URLs below. Future versions require
the manually dispatched dev and approved production workflows; merging
publication code alone does not publish release objects. See
[the publication contract and runbook](publication.md).

macOS and Linux customers can inspect and run:

```sh
rm -f ./install-qodo-scout.sh
curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  -o ./install-qodo-scout.sh \
  https://get.qodo.ai/support-bundle/releases/0.3.1/install.sh &&
  less ./install-qodo-scout.sh
sh ./install-qodo-scout.sh --version 0.3.1 --add-to-path
```

Windows customers can inspect and run from PowerShell:

```powershell
Remove-Item .\install-qodo-scout.ps1 -Force -ErrorAction SilentlyContinue
curl.exe --fail --location --proto '=https' --tlsv1.2 `
  --proto-redir '=https' `
  --output install-qodo-scout.ps1 `
  https://get.qodo.ai/support-bundle/releases/0.3.1/install.ps1
if ($LASTEXITCODE -ne 0) { throw 'Installer download failed' }
Get-Content .\install-qodo-scout.ps1
& .\install-qodo-scout.ps1 -Version 0.3.1 -AddToPath
```

For convenience, the same endpoints can be executed without saving a copy:

```sh
(
  set -eu
  installer="$(mktemp "${TMPDIR:-/tmp}/qodo-scout-install.XXXXXX")"
  trap 'rm -f "$installer"' EXIT
  trap 'exit 1' HUP INT TERM
  curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    -o "$installer" \
    https://get.qodo.ai/support-bundle/releases/0.3.1/install.sh
  sh "$installer" --version 0.3.1 --add-to-path
)
```

```powershell
& {
  $installer = Join-Path ([IO.Path]::GetTempPath()) (
    'qodo-scout-install-{0}.ps1' -f [guid]::NewGuid()
  )
  try {
    curl.exe --fail --location --proto '=https' --proto-redir '=https' `
      --tlsv1.2 --output $installer `
      https://get.qodo.ai/support-bundle/releases/0.3.1/install.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Installer download failed' }
    & $installer -Version 0.3.1 -AddToPath
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

All installations are pinned for reproducibility:

```sh
sh ./install-qodo-scout.sh --version 0.3.1 --add-to-path
```

```powershell
& .\install-qodo-scout.ps1 -Version 0.3.1 -AddToPath
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
  --version 0.3.1 \
  --source-dir /approved/qodo-scout-release \
  --add-to-path
```

```powershell
& .\install.ps1 `
  -Version 0.3.1 `
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
installer-checksums.sha256
qodo-support-bundle-<os>-<arch>[.exe]
```

Before running the Unix installer, require exactly one valid manifest row and
verify it:

```sh
(
  pattern='^[[:xdigit:]]{64}  install\.sh$'
  count="$(grep -Ec "$pattern" installer-checksums.sha256)" || {
    echo 'Cannot read a valid install.sh checksum row' >&2
    exit 1
  }
  if [ "$count" -ne 1 ]; then
    echo 'Expected exactly one install.sh checksum row' >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    grep -E "$pattern" installer-checksums.sha256 |
      sha256sum --strict --check -
  else
    grep -E "$pattern" installer-checksums.sha256 |
      shasum -a 256 -c -
  fi
)
```

On Windows PowerShell:

```powershell
$rows = @(Get-Content .\installer-checksums.sha256 | Where-Object {
  $_ -match '^([0-9a-fA-F]{64})  install\.ps1$'
})
if ($rows.Count -ne 1) { throw 'Expected one install.ps1 checksum row' }
$expected = ($rows[0] -split '\s+')[0]
$actual = (Get-FileHash .\install.ps1 -Algorithm SHA256).Hash
if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Installer checksum mismatch'
}
```

Also retain the release version and source release URL in the approved handoff
record. Support should verify the connected copy before transfer; the customer
verifies it again offline.

## Immutable version contract

Both installers require `--version` or `-Version` and reject missing or invalid
versions. Every download uses the selected release directory:

```text
https://get.qodo.ai/support-bundle/releases/<version>/
```

All release objects use one-year immutable caching. Root installer aliases and
current-version metadata are unsupported and may be absent. Documentation and
portal instructions must be updated to an exact version for every release.
This makes customer commands reproducible and lets publication remain
create-only, at the cost of no automatic latest-version selection.

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

- **Root installer or metadata URL returns 404:** those mutable paths are not
  supported. Use the documented version-specific installer URL and explicit
  version.
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
