# Qodo Scout publication

Qodo Scout uses an authenticated GitHub release as the source of truth, a
development GCS canary, and a manually approved production promotion. The
workflows never rebuild during publication or promotion.

## Object contract

Each immutable release directory contains:

```text
support-bundle/releases/<version>/
  qodo-support-bundle-linux-amd64
  qodo-support-bundle-linux-arm64
  qodo-support-bundle-darwin-amd64
  qodo-support-bundle-darwin-arm64
  qodo-support-bundle-windows-amd64.exe
  qodo-support-bundle-windows-arm64.exe
  checksums.sha256
  install.sh
  install.ps1
  installer-checksums.sha256
```

`checksums.sha256` covers only the six binaries consumed by the installers.
`installer-checksums.sha256` separately covers the two installer scripts, so
there is no circular self-verification. All ten versioned objects use
`Cache-Control: public, max-age=31536000, immutable`. Binaries use
`application/octet-stream`; manifests and scripts use
`text/plain; charset=utf-8`.

The mutable customer endpoints are:

```text
support-bundle/install.sh
support-bundle/install.ps1
support-bundle/version.json
```

They use `Cache-Control: no-cache, max-age=0, must-revalidate`. Installer
scripts use `text/plain; charset=utf-8`; metadata uses `application/json`.
`version.json` has the strict shape `{ "version": "<version>" }`.

The production object paths map directly to:

```text
https://get.qodo.ai/support-bundle/install.sh
https://get.qodo.ai/support-bundle/install.ps1
https://get.qodo.ai/support-bundle/version.json
https://get.qodo.ai/support-bundle/releases/<version>/<asset>
```

Before these workflows are merged and deliberately run, a 404 from a stable
endpoint is expected. A 404 is not evidence that the load balancer or CDN is
misconfigured.

## Release and publication sequence

1. The release workflow builds six binaries, copies the exact repository
   installer bytes, creates separate binary and installer manifests, attests
   all ten files, and uploads only missing GitHub release assets.
2. An existing same-name GitHub asset is downloaded and compared. Identical
   bytes make a rerun succeed; different bytes stop the release. Assets are
   never overwritten with `--clobber`.
3. A manual dev-publication dispatch verifies every release attestation and
   checksum before using the development publisher identity.
4. The dev publisher creates immutable versioned objects, conditionally
   updates stable installer scripts, validates exact bytes and headers, and
   updates `version.json` last.
5. Dev canaries install from exact objects and run only `qodo-scout version`.
   The Windows ARM64 canary executes natively on `windows-11-arm`.
6. The production workflow requires the `production` environment approval. It
   independently verifies the GitHub release, dev objects, stable scripts, and
   metadata before promoting byte-identical objects.
7. Production updates immutable objects first, stable scripts next, validates
   them, and commits `version.json` last. Public CDN canaries then exercise
   pinned and metadata-selected installation and run only `version`.

Neither canary starts cluster collection.

## Concurrency, reruns, and rollback

Versioned objects are create-only with generation-match `0`. Identical bytes
and headers are accepted after an exact-object read; any conflict fails. No
operation requires `storage.objects.list`, overwrite, or delete permission.

Stable scripts and metadata use exact-object generation-match writes. A rerun
with identical bytes and headers performs no write. `version.json` is compared
semantically before mutable writes, and its observed generation is retained
until the final conditional update. An older version is rejected, and a
concurrent change causes the final CAS to fail rather than rolling the pointer
back.

Each workflow attempt also acquires
`support-bundle/control/publication-lock.json` with a unique run owner before
it repairs or changes stable installers and holds that lock through metadata
activation. The lock is an exact object with generation CAS and `no-store`
caching; it requires neither bucket listing nor deletion. A different owner
cannot take over a held lock, so overlapping or stale publishers cannot undo a
newer publisher's stable scripts. Successful and failed runs release the lock
through the shell cleanup trap.

The lock deliberately has no time-based lease: an interrupted process cannot
resume writes after another publisher takes over. If a runner is terminated
before cleanup, later publication stops safely. Recovery requires an operator
to confirm that no publication process is active, reconcile both stable
installers to the immutable release selected by `version.json`, and reset the
lock with an exact generation-match write. That is a production change and
retains the same manual approval boundary as promotion.

Rollback never mutates an immutable release. If rollback is required, create
and verify a new release containing the intended bytes, or promote a newer
fixed version. The monotonic pointer contract intentionally rejects moving
`version.json` to an older version.

## Manual boundaries

Merging code does not publish anything. The following remain explicit operator
actions:

- dispatch dev publication from `main`;
- review dev canary evidence;
- approve the protected production environment;
- dispatch production promotion and review public canaries.

The workflows and scripts operate only under `support-bundle/`. Repository
visibility, platform signing, customer cloud-auth plugins, and automatic
cluster collection are outside this publication contract.
