# Contributing

Thank you for helping improve Qodo Scout.

## Before opening a change

- Use a focused branch and keep unrelated changes separate.
- Open an issue for significant behavior or contract changes before investing in
  an implementation.
- Never commit credentials, kubeconfig files, customer data, support archives,
  generated release artifacts, or private infrastructure details.
- Report vulnerabilities through the private process in
  [`SECURITY.md`](SECURITY.md), not through an issue or pull request.

## Development setup

Install Go 1.25 or newer, Python 3, GNU Make, and ShellCheck. PowerShell changes
also require Pester 5 and PSScriptAnalyzer. Workflow changes should be checked
with `actionlint`.

Create the pinned Python test environment once:

```sh
make test-python-deps
```

Build the local binary with:

```sh
make build
```

## Tests

Run the complete local suite before requesting review:

```sh
make test
```

This includes formatting checks, ShellCheck and installer tests, the Go race
suite, and `go vet`. When changing Windows installation behavior, also run the
Pester suite and PSScriptAnalyzer as described in
[`tests/Install.Tests.ps1`](tests/Install.Tests.ps1). When changing
release or publication behavior, run the fake-GCS and static workflow contract
tests in `internal/distribution/` and validate workflows with `actionlint`.

Changes to platform inventory must preserve all six release targets. Verify
cross-compilation with:

```sh
make release VERSION=0.0.0-test
```

Do not commit the generated `dist/` directory.

## Pull requests

Describe the user-visible behavior, security or compatibility impact, and exact
verification performed. Add a regression test before a behavioral fix when
practical. Keep public comments in English and explain why non-obvious code is
needed rather than restating what it does.

Changes to installers, checksums, release assets, immutable publication
inventory, or cache controls are distribution-contract changes. Update the
corresponding tests and documentation together, and never weaken checksum or
create-only protections to make a test pass.

Repository maintainers will apply the configured review, CI, and release
controls. A merged pull request does not itself authorize a live release,
bucket publication, repository visibility change, or customer rollout.
