# Governance

PAO preserves the public [product boundaries](docs/release/v0.2-public-scope.md)
and [security model](docs/security/threat-model.md). Contributions use DCO 1.1
sign-off (`git commit -s`); a CLA is not required for the current release scope.

Changes to runner capabilities, adapter protocol, policy packs, licensing/distribution or release
workflow require a documented decision and human architecture/security/license review. Maintainers
must preserve raw evidence, offline/read-only defaults and explicit incomplete states.

Audit storage follows [the PAO audit-storage policy](docs/operations/audit-storage.md).  Protected
raw evidence belongs only in the private PAO evidence root; this repository's `audits/` tree is
reserved for redacted local reports and is Git-ignored.  A report may cite SHA-256 evidence
references but must never contain raw output, secrets, PII, target contents or absolute local paths.
