# Changelog

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
