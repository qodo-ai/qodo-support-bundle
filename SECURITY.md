# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to
[security@qodo.ai](mailto:security@qodo.ai). Include the affected version,
reproduction steps, impact, and any suggested mitigation when it is safe to do
so.

Do not open a public GitHub issue or discussion containing:

- exploitable vulnerability details;
- credentials, tokens, kubeconfig content, or cloud configuration;
- customer names, infrastructure details, logs, or support archives; or
- unredacted output produced by Qodo Scout.

Before a public pilot, maintainers must verify that this address is monitored
and assign vulnerability-triage ownership as required by the
[readiness checklist](docs/public-readiness.md). Until that operational gate is
complete, this policy makes no response-time commitment. Do not attempt testing
against systems or data that you do not own or have explicit authorization to
assess.

## Supported versions

Before a public pilot policy is approved, use the most recent published release
and include its exact version in a report. A formal support window and
end-of-life policy must be approved before general availability.

## Scope boundary

Qodo Scout collects diagnostics locally using customer-provided Kubernetes
credentials and writes the archive to the customer's filesystem. Customers
remain responsible for credential handling, RBAC, archive review, storage, and
transfer. See the [security model](docs/security-model.md) for trust boundaries
and explicit non-goals.
