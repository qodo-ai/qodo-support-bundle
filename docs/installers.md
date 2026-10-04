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

This repository change does not publish either installer or `version.json`.
The URLs below are the intended contract for the follow-up publication PR and
are not expected to work until that PR is deployed.

After publication, macOS and Linux customers can inspect and run:

```sh
curl -fL --proto '=https' --tlsv1.2 \
  -o install.sh \
  https://get.qodo.ai/support-bundle/install.sh
less install.sh
sh ./install.sh --add-to-path
```

Windows customers can inspect and run from PowerShell:

```powershell
curl.exe --fail --location --proto '=https' --tlsv1.2 `
  --output install.ps1 `
  https://get.qodo.ai/support-bundle/install.ps1
Get-Content .\install.ps1
& .\install.ps1 -AddToPath
```

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

The publication workflow in the follow-up PR must update `version.json`
atomically only after every production artifact and `checksums.sha256` has been
published and verified. The metadata should use a short or no-cache policy,
such as `Cache-Control: no-cache, max-age=0, must-revalidate`; immutable release
objects retain long-lived immutable caching. This PR intentionally does not
commit a live-current metadata file that could drift from production.

## Security and proxy behavior

Network mode uses `curl` or `curl.exe`, which preserves normal proxy environment
and system trust behavior. The installers do not print proxy configuration or
credentials. They do not remove macOS quarantine, delete Windows
Mark-of-the-Web data, call `xattr -d` or `Unblock-File`, change PowerShell
execution policy, or weaken endpoint security controls.
