# Project Audit Orchestrator (PAO)

PAO is an offline-first orchestrator for evidence-based audits of open-source
projects. It coordinates verified external tools for SAST, SCA, secrets,
licenses and SBOM evidence. It does not issue an automated clean security or
legal verdict.

## Scope

This source implements the bounded `v0.2.0` scope.
The [current scope](docs/release/v0.2-public-scope.md) records implementation,
support boundaries and verification requirements. Internal planning, review and
acceptance records are retained separately from the public source.

The configured CLI has a preview-first planner, strict operator-owned
configuration, an immutable raw-evidence store and ten external adapter
contracts: nine scanner adapters plus an owner-gated `sbomqs` quality adapter.
The explicit `mvp` profile selects all ten; unavailable tools remain coverage
gaps. Every launch requires the exact current `RUN <audit-id> <plan-digest>`
and evidence that the local Docker Desktop Linux VM satisfies the
`container-vm` contract. Native process mode cannot silently downgrade it.

The target hosts are Windows 11 x64 and Ubuntu 24.04 LTS x64, with separately
validated Docker Desktop versions listed for the particular release.
Ordinary/rootless Docker Engine, remote contexts and root scanners are
unsupported. Check the repository's signed release tag and verification guide
before treating a downloaded build as a supported release.

See the [release verification guide](docs/release-verification.md)
for package and signature checks. Build/test reports,
SBOM and provenance are internal; the public release contains source, both
binary archives, checksums and a signed tag. PAO is pre-1.0; compatibility changes
will be stated in release notes.

## Read results precisely

Applicability, format/ecosystem support, tool availability, execution and parsing
are distinct. `coverage_complete` retains execution/parsing meaning;
`inventory_coverage` compares detected dependency ecosystems with verified
inventory, and `analysis_coverage_complete` also accounts for support gaps.
None proves every runtime, build or transitive component. A recognized filename
is a planning hint rather than proof that a scanner consumed its contents.

The current OSV database covers Go only. Python-only OSV is `UNSUPPORTED`
with `DB_ECOSYSTEM_UNSUPPORTED`; mixed Go/Python retains partial support.
Custom `requirements.lock`/`build-requirements.lock` names remain
`UNSUPPORTED_INPUT_FORMAT`. Actions-only Syft inventory does not satisfy Python
inventory. An informational sbomqs score cannot close these gaps.

New reports distinguish the original `run_producer` from `report_producer`,
recording PAO version, source/revision, actual executable hash and Go identity.
Old runs without producer evidence remain `UNKNOWN_HISTORICAL`. Snapshot
inspection never starts Git from PATH; target VCS state is `UNAVAILABLE/UNKNOWN`.

The configured CLI produces private details and portable Ukrainian Markdown/JSON.
Canonical normalization, policy, correlation, baseline and
JSONL/SARIF 2.1.0/CycloneDX 1.5/SPDX 2.3 renderers also exist as internal library
helpers. The source-only [offline schema harness](scripts/schema/README.md)
validates their actual synthetic outputs against complete pinned schemas.
These helpers are not extra public CLI modes or a supported external
`internal/*` Go API. Full upstream prose compliance, complete inventories and
automatic policy approval are not claimed.

## Isolation and defaults

- Target repositories and their instruction files are untrusted data.
- Audit execution reads a bounded private target copy and frozen verified tool,
  state, database, rule and captured-input copies; originals are not writable mounts.
- The bundled static supervisor confines scanner output and temporary files to
  byte/inode-limited tmpfs in the reviewed VM, with no writable host output mount.
- Raw evidence stays private; portable outputs retain closed status/reason fields
  and hashes, with no raw scanner text, component names or private paths.
- Native scanner JSON is parsed in the PAO process under format-specific bounds.
  The common parser limits size/depth/count; SBOMQS has a separate size-bounded
  parser. Separate parser-process isolation is absent.
- Missing data, unsupported input, partial execution and legal ambiguity require review.

The [frozen-input boundary](docs/security/frozen-inputs.md) defines trusted
operators/administrators and remaining platform compatibility limits. It does
not claim resistance to arbitrary malicious code under the same privileged
account. PAO runs no target package manager, build/test script or Git subprocess.

## Start here

Read the [Ukrainian beginner guide](docs/public-start.uk.md) and
[verify the exact archive and signed tag](docs/release-verification.md).
Both Windows AMD64 ZIP and Linux AMD64 tar.gz contain the host PAO executable,
its own `pao-sandbox-linux-amd64` helper, ten manifests, blank JSON templates,
version/content manifests and license notices. They contain no scanners, runtime
images, databases, rule packs, Python wheels or cached schemas.

The `UNAPPROVED`/empty templates require real local setup and review. Use
`pao audit --config FILE --profile NAME` for preview; `--execute` additionally
requests the current exact confirmation. See the
[operator guide](docs/operations/configured-local-audit.md) for private config
discovery, actual exit codes and failure handling. Configured execution returns
a nonpass review/incomplete/blocked code; preview success is not audit PASS.
Private configurations, approvals, reports and evidence are never distributed.

PAO has no telemetry or automatic updater. Updates and rollback use separately
verified folders; uninstall must preserve private evidence and configuration.
Security support targets the latest published stable release. Use
[private GitHub Security Advisories](https://github.com/sSOFTINn/ProjectAuditOrchestrator/security/advisories/new);
the maintainer must verify availability before public release. See [SECURITY.md](SECURITY.md).

## Source and release boundaries

The canonical module identity is
`github.com/sSOFTINn/ProjectAuditOrchestrator`, with exact Go 1.27.1 builds.
No `go install` availability is promised before reviewed source publication.
CLI/config/report versions are public contracts; support applies to verified
published releases. Wider APIs, policy automation and
roadmap capabilities remain separately scoped.

- [Current product scope](docs/release/v0.2-public-scope.md)
- [Threat model](docs/security/threat-model.md)
- [Toolchain register](docs/legal/toolchain-register.md)
- [Audit-storage policy](docs/operations/audit-storage.md)

PAO-authored code/docs use [Apache-2.0](LICENSE). Both owned executables include
Go runtime/stdlib under the exact included Go license. Source-only cached
schemas and validator wheels retain separate terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [NOTICE](NOTICE).
Scanner/rule/database licenses remain separate human decisions.
