# Contributing

Read [governance](GOVERNANCE.md), the [threat model](docs/security/threat-model.md)
and the [current scope](docs/release/v0.2-public-scope.md) before changing code. Keep target
repositories untrusted, use synthetic fixtures, and never add network, install, build or target-code
execution behavior to audit-only defaults.

Commits should include a DCO sign-off (`git commit -s`). Pull requests that change a security or
license boundary need the corresponding reviewer decision record before merge.

## Build and check locally

Use the exact approved Go 1.27.1 toolchain and Python 3.9 or newer. PowerShell
scripts require PowerShell 7.2 or newer. Run from the repository root with normal
user privileges. The commands below do not install or download dependencies.
Go must be on PATH; alternatively invoke its approved absolute executable path.

```powershell
$env:GOTOOLCHAIN = 'local'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
go version
go test -count=1 ./...
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Vet failed.' }
```

Opt-in Docker and installed-scanner tests can be skipped by this default suite.
Record skips separately: passing unit tests does not establish Docker/platform
acceptance or a successful audit. Use only synthetic targets for development
tests; real audit execution retains its exact run-specific confirmation.

For complete offline format and workflow checks, follow the
[schema harness](scripts/schema/README.md) and
[workflow contract checks](scripts/workflow-security/README.md), using fresh
absolute staging directories outside this repository. For both executable
packages, smoke tests and package verification, follow the
[release build instructions](docs/release-verification.md). Keep build evidence
separate from the three public distribution files. Do not commit private
configuration, audit inputs, raw output or review evidence.

Adapter changes must keep the manifest, bounded parser, synthetic fixtures,
plan/support reasons and schema contracts consistent. An unavailable tool or
unsupported ecosystem must remain a reported coverage gap.
