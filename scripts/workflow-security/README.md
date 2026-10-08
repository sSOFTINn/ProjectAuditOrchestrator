# Offline workflow and candidate transfer checks

`test_contracts.py` uses only Python 3.9+ standard libraries. It does not install
dependencies, contact a service, or execute transferred archives. From the repo:

```powershell
$workflowScratch = Join-Path $env:RUNNER_TEMP 'NEW-workflow-check'
python -I -B scripts/workflow-security/test_contracts.py --repo $PWD.Path --scratch $workflowScratch
```

The scratch destination must be a new absolute directory outside the repository
with an existing parent. Synthetic output stays there for inspection. The test
suite checks the current CI/release workflows, rejects altered permission/ref/
public-upload/reproduction contracts, and creates small inert candidate fixtures to verify
source/run identity, hashes, missing/extra entries, reparse/link refusal, size
limits, duplicate JSON and refused overwrite. Windows tests use an isolated
synthetic junction if symlink creation is unavailable.

`contracts.py` parses a restrictive YAML subset that covers these two workflows
and checks their authored structure and security invariants. Duplicate keys,
anchors/aliases, tags and unsupported syntax fail closed. This is local syntax
and contract lint, **not** the full GitHub schema or actionlint. It does not prove
that runner expressions, action execution or service settings work. Hosted
validation remains **NOT VERIFIED** until the approved immutable candidate is
run in R16. Native Windows 11 and Ubuntu 24.04 with exact Docker Desktop versions
remain distinct acceptance gates; hosted Windows Server CI is not Windows 11 evidence.

## Build and public upload boundary

CI and the release build use `contents: read` and an exact `github.sha` checkout
with `persist-credentials: false`. The pinned Go 1.27.1 preparation is explicit;
subsequent Go/schema/mock tests run without dependency network access. The release
checkout fetches full history and requires a stable candidate to equal the fetched
`origin/main` commit. Two builds use separate new output and Go cache directories;
an exact public-file comparison must pass before candidate upload. No job obtains
an attestation/identity write token, creates a release, signs a tag or changes visibility.

The build seals three exact public distribution assets into `payload/`, with per-file
bytes/SHA-256 and source/version/ref/run identity in `transfer.json`. Its SHA-256
is recorded locally. `transfer.py` reads clean `BUILD-METADATA.json` through the
required `--build-metadata` path outside the public directory. Neither that private
file nor `transfer.json` is copied into `payload/`. The only public files are the
Windows AMD64 ZIP, Linux AMD64 TAR.GZ and `SHA256SUMS.txt`; the checksum list covers
only the two archives. The upload path is exactly `payload/`, never its parent.
SBOM, provenance and reports remain in runner-local evidence and are not uploaded.

`upload-artifact` returns an immutable artifact ID and digest. Local sealing checks
payload contents, not the service's eventual transport ZIP; it does not prove a
hosted run happened, authenticate a publisher or establish approval. Private
runner-local evidence is ephemeral unless separately collected into approved
private storage. Required hosted status settings, owner main-merge approval,
trusted signed-tag verification and final owner publication approval still require
separate evidence and exact external-action authorization.

The per-file read cap is 64 MiB, total payload cap is 256 MiB, and only three flat
assets plus the transfer manifest are accepted. Reading observes file identity,
size and modification time before/during/after. Existing output paths, symlinks
and Windows reparse ancestors are refused. No archive extraction or payload
execution happens in local transfer verification.

The proposed required hosted check names are `hosted-windows-2025`,
`hosted-ubuntu-24.04` and `hosted-ubuntu-cgo-race`. YAML prepares those checks;
it cannot prove GitHub main protection or owner approval is configured.

## Action provenance and compatibility

`action-pins.json` records official tag/commit/definition URLs checked on
2026-10-02. GitHub reported each pinned commit as verified; this is not a local
signature verification or an exhaustive dependency review. All five pins use
Node 24. Their [checkout runtime requirement](https://raw.githubusercontent.com/actions/checkout/3d3c42e5aac5ba805825da76410c181273ba90b1/README.md)
is Actions Runner 2.327.1 or newer. Hosted `windows-2025` and `ubuntu-24.04`
execution and these updated action major versions still require R16 evidence.

The historical approved download/attest action pins remain recorded in
`action-pins.json` as reference evidence. Current contracts reject invocation of
either action; no public attestation workflow remains.
