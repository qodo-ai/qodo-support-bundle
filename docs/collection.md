# Qodo Scout collection guide

This guide covers collection after Qodo Scout is installed. Installation and
collection are separate actions: the installer runs only a local `version`
check, and the operator must explicitly start every collection.

## Guided collection

```sh
qodo-scout collect --interactive
```

The wizard selects the Kubernetes context, namespace scope, log window,
optional data sources, and output path before asking for confirmation. It never
requests credentials or lists Kubernetes Secrets. It requires interactive stdin
and stderr; use flags for CI or redirected sessions.

## Scripted collection

Without `--interactive`, `collect` uses the current kubeconfig context,
discovers application namespaces, and excludes known Kubernetes and managed
GKE system namespaces:

```sh
qodo-scout collect
```

Common explicit controls include:

```sh
qodo-scout collect \
  --kubeconfig /secure/customer.kubeconfig \
  --context customer-production \
  --namespace qodo-onprem \
  --since 30m \
  --output /secure/cases/case-123.tar.gz
```

- `--namespace` selects one namespace; `--namespaces` accepts a comma-separated
  list; `--all-namespaces` requests literal cluster-wide collection.
- `--selector` narrows pods within selected namespaces.
- `--output` is an exact archive path and never overwrites an existing file.
- `--no-progress` suppresses routine progress while preserving warnings,
  errors, and stdout results.

Run `qodo-scout collect --help` for the complete flag reference and enforced
bounds.

## Optional sources

Prometheus and Phoenix collection are opt-in. Each uses a temporary
loopback-only `kubectl port-forward`, fixed service discovery, fixed bounded
queries, and the selected workload namespace scope. The Zitadel check is also
opt-in and requires an explicit Platform pod and container; it executes the
embedded probe through `kubectl exec` without uploading a helper or changing
the workload.

These sources require only their documented additional permissions:

- `pods/portforward` for the selected Prometheus or Phoenix service namespace;
- `pods/exec` for the selected Platform namespace when checking Zitadel.

Missing optional data produces a bounded coverage record or a usable partial
bundle rather than broadening access. See the
[security model](security-model.md) for the permission and data boundaries.

## Output and exit behavior

The default archive path is:

```text
~/qodo-support-bundles/qodo-support-bundle-<UTC timestamp>-<random suffix>.tar.gz
```

The output directory and archive use owner-only permissions where supported.
The archive includes a manifest, summary, SHA-256 checksums, redacted
Kubernetes records and logs, optional-source coverage, and collection issues
when the result is partial.

- Exit `0`: collection completed.
- Exit `3`: a usable partial archive was created; inspect
  `collection-issues.jsonl`.
- Exit `1`: setup, cancellation, or archive failure.
- Exit `2`: invalid CLI usage.

Qodo Scout saves the archive locally and never uploads or sends it. Review the
contents before sharing through an approved support channel.

## Archive integrity

After extracting the archive safely, verify its embedded checksums:

```sh
shasum -a 256 -c checksums.sha256
```

Checksums detect corruption but do not authenticate provenance. Treat the
archive as sensitive diagnostic data and retain it according to the customer's
approved support process.
