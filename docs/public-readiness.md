# Public distribution readiness

This checklist is the approval gate for a future public repository or customer
pilot. Completing code changes in this repository does not authorize a
visibility change, release publication, bucket write, or customer rollout.

## Repository and legal review

- [ ] Scan the complete Git history, open and closed pull requests, issue
  attachments, review comments, Actions logs and artifacts, releases, tags,
  packages, discussions, and wiki for credentials, customer data, internal
  hostnames, infrastructure identifiers, and other sensitive material.
- [ ] Confirm that any discovered sensitive value is revoked or rotated before
  history remediation; obtain Security approval for the remediation plan.
- [ ] Inventory direct and transitive dependencies, generated code, embedded
  assets, notices, and third-party license obligations.
- [ ] Obtain Legal/Open Source approval for a repository software license. This
  repository currently has no approved license, so public visibility must not
  be enabled until that choice is recorded.
- [ ] Review workflow files, documentation, examples, git metadata, and release
  artifacts for internal infrastructure details.
- [ ] Verify that contribution and vulnerability-reporting paths are staffed
  and that an actual team or user is selected before adding `CODEOWNERS`.

## GitHub governance

- [ ] Define and test branch protections and tag protections without an
  administrator bypass path for ordinary releases.
- [ ] Require review for workflow changes and use least-privilege default and
  per-job `GITHUB_TOKEN` permissions.
- [ ] Enable and validate secret scanning, push protection, dependency review,
  and supported code-scanning controls.
- [ ] Audit repository, environment, organization, and GitHub App credentials;
  retain only the minimum publication identities and scopes.
- [ ] Protect the production environment with named reviewers and ensure the
  workflow cannot self-approve.
- [ ] Verify release assets and immutable versioned GCS objects reject
  conflicting reruns rather than overwriting published bytes.

## Distribution validation

- [ ] Run the complete release and publication test suite from a clean checkout.
- [ ] Publish to dev, then verify exact object names, bytes, checksums, content
  types, cache controls, provenance, and native smoke evidence for every
  supported target.
- [ ] Validate version-pinned installer resolution in dev. Installer smoke must
  run only `version`, never collection.
- [ ] Confirm anonymous access only to intended
  `support-bundle/` customer objects; verify that bucket listing and unrelated
  prefixes remain denied.
- [ ] Confirm root installer aliases and current-version metadata are not part
  of the supported contract; customer instructions must use versioned URLs.
- [ ] Obtain production approval and execute the
  [publication runbook](publication.md) without bypassing its canaries.
- [ ] Validate GitHub, GCS, and CDN byte identity and headers after production
  promotion, including every supported OS and architecture at the level its
  runner can genuinely execute.

## Pilot and rollback evidence

- [ ] Record approver, commit, release version, workflow run, checksums, object
  generations, canary results, and native-platform evidence for the pilot.
- [ ] Test customer instructions from a clean, non-administrator account behind
  representative proxy and endpoint policies.
- [ ] Confirm support ownership, vulnerability triage, incident response,
  retention, and customer archive handling before onboarding pilot users.
- [ ] Rehearse rollback using a new semantic version with known-good bytes and
  updated customer instructions; do not overwrite immutable release objects.
- [ ] Document how to pause activation, revoke compromised credentials, and
  communicate a withdrawn release without deleting audit evidence.

## Deferred approval boundary

The following remain operational decisions outside repository code:

- repository visibility and GitHub security/settings changes;
- software license and public contribution policy approval;
- final owner/team selection and `CODEOWNERS`;
- platform signing, notarization, and certificate custody;
- cloud identity, bucket/CDN policy, anonymous access, and production
  environment reviewers; and
- live release, dev publication, production promotion, rollback, or pilot
  dispatch.
