# Changelog

## 0.2.1

This entry describes the version's scope; availability and the signed tag
must be checked on the repository's Releases page. Platform acceptance and
review must identify the exact source and archive hashes. Previous candidates'
evidence is historical and does not approve a later release's bytes.

- Distinguish a verified empty Go dependency declaration from missing inventory.
  The exception requires bounded `module`/`go` declarations, a plan-bound content
  proof, unchanged target identity and matching successful Syft outputs/cataloger.
  Checksums, workspaces, Go vendor inputs or unsupported directives prevent it.
- Add optional plan `empty_go_module_sha256_v1` and report
  `verified_empty_declared_ecosystems` fields. Observed ecosystems remain separate;
  empty declarations do not prove the standard-library, build or runtime graph.
- Advance native projection to `pao-native-projection/6`. Validate historical
  `/5` reports against their matching historical schema. Old plans without the
  content proof retain their inventory gap; rerendering does not backfill it.
- Explain local candidate identity separately from signed published releases.
- Accept omitted optional CycloneDX `components` for an empty Syft inventory,
  while retaining the separate proof required for empty Go declarations.
- Remove the verified-empty declaration claim when native Syft and CycloneDX
  inventories disagree or the export is invalid; preserve the incomplete result.
- Document the offline contributor build and verification commands.
- Show applicability, supported/unsupported ecosystems and known support gaps
  in the configured preview before requesting the run confirmation.
- Make global and subcommand help succeed without reading configuration or
  targets. Explain commands, profiles, the first single-scanner workflow and
  the limits of `doctor`.
- Name missing or invalid configuration/approval fields without echoing private
  values. Preserve the existing strict parsing and approval requirements.
- Explain a first `secrets` audit with one separately verified Linux AMD64
  Gitleaks binary. Keep every approval placeholder invalid until actual review.
- Verify the selected release tag and the downloaded platform archive instead
  of always using the historical `v0.2.0` tag.

## 0.2.0

This entry describes the version's scope;
availability and the signed tag must be checked on the repository's Releases page.
PAO is pre-1.0. CLI, configuration and report formats are versioned; compatibility
changes will be documented. Internal Go packages are not a supported public API.

- Configured audits use an explicit preview and exact run confirmation, with
  separate applicability, support, execution and inventory coverage results.
- The local Docker Desktop Linux VM runs scanners without network access.
  Verified target/tool/database/rule inputs are frozen for each execution;
  scanner output and scratch use bounded VM filesystems and a pinned supervisor.
- Reports distinguish the original audit producer from the report producer and
  retain unknown identity for historical evidence.
- Release packages contain PAO, the owned Linux supervisor, adapter manifests,
  blank configuration templates, operator instructions and licenses. Third-party
  scanners, databases, images and rule packs are installed and approved separately.
- Public delivery is source, Windows x64 ZIP, Linux x64 tar.gz, SHA-256 checksums
  and a signed tag. Test reports, SBOM and build provenance remain internal.

Target hosts are Windows 11 x64 and Ubuntu 24.04 LTS x64 with explicitly tested
Docker Desktop versions. Exact-candidate platform acceptance remains a release
gate. Rootless/ordinary Docker Engine, remote endpoints, ARM and macOS are outside
this release. Native scanner JSON is parsed in process with explicit bounds;
there is no separate parser process. A complete run does not establish complete
dependency inventory or provide an automatic security or legal approval.

Tool/database preparation and updates are explicit operator actions. Missing,
stale or unsupported prerequisites retain partial/review outcomes. Network and
agent modes are future design work and are not implemented by this release.
