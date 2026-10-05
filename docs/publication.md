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

The supported production paths are version-specific:

```text
https://get.qodo.ai/support-bundle/releases/<version>/<asset>
```

Root installer aliases, a current-version metadata object, and publication
control objects are not part of the supported contract. Customers must use an
explicit version. Documentation and portal instructions are updated for each
release. This trades automatic latest-version selection for reproducible,
create-only publication that requires no object update or delete permission.

## Release and publication sequence

1. The release workflow builds six binaries, copies the exact repository
   installer bytes, creates separate binary and installer manifests, attests
   all ten files, and uploads only missing GitHub release assets.
2. An existing same-name GitHub asset is downloaded and compared. Identical
   bytes make a rerun succeed; different bytes stop the release. Assets are
   never overwritten with `--clobber`.
3. A manual dev-publication dispatch verifies every release attestation and
   checksum before using the development publisher identity.
4. The dev publisher creates or verifies only the ten immutable versioned
   objects.
5. Dev canaries install from exact objects and run only `qodo-scout version`.
   The Windows ARM64 canary executes natively on `windows-11-arm`.
6. The production workflow requires the `production` environment approval. It
   independently verifies the GitHub release and exact dev objects before
   promoting byte-identical objects.
7. Production creates or verifies only immutable versioned objects. Public CDN
   canaries use versioned installers with an explicit version and run only
   `version`.

Neither canary starts cluster collection.

## Operator dispatch checklist

1. Confirm the intended commit is on `main`, the version follows the installer
   grammar, and the matching GitHub release is published.
2. Let `.github/workflows/release-support-bundle.yaml` process the published
   release. A manual release run is recovery-only: run it from the matching tag
   ref and provide that same tag, never from an unrelated branch.
3. After the release assets, attestations, and native smoke jobs pass, manually
   dispatch `.github/workflows/publish-support-bundle.yaml` from `main` with the
   release version (for example `1.2.3`; the workflow also resolves its matching
   `v1.2.3` tag).
4. Review all exact dev object validation and pinned canary evidence. Stop on
   any mismatch.
5. Manually dispatch `.github/workflows/promote-support-bundle.yaml` from
   `main` with the same version. A named reviewer must approve the protected
   `production` environment before promotion can run.
6. Review exact GitHub/dev/CDN byte identity, headers, and every public canary.
   Preserve the workflow URLs, checksums, object generations, and approver in
   the release record.

Workflow dispatch, environment approval, and cloud credentials are live
operational actions. This runbook documents them but does not authorize them.

## Concurrency, reruns, and rollback

Versioned objects are create-only with generation-match `0`. Identical bytes
and headers are accepted after an exact-object read; any byte or header
conflict fails. Publication uses exact object requests and requires no
`storage.objects.list`, update, overwrite, or delete permission.

Workflow concurrency prevents overlapping attempts in the same environment.
No GCS publication lock is needed because each version has a disjoint,
immutable namespace. A stale control object from an earlier publication model
is inert and must not be read, updated, or deleted by these workflows.

Rollback never mutates an immutable release. If a release must be replaced,
create and verify a new version, update customer-facing instructions to that
version, and preserve the prior objects as audit evidence.

## Manual boundaries

Merging code does not publish anything. The following remain explicit operator
actions:

- complete and approve the
  [public distribution readiness checklist](public-readiness.md) before a
  customer pilot;
- dispatch dev publication from `main`;
- review dev canary evidence;
- approve the protected production environment;
- dispatch production promotion and review public canaries.

The workflows and scripts operate only under `support-bundle/`. Repository
visibility, platform signing, customer cloud-auth plugins, and automatic
cluster collection are outside this publication contract.
