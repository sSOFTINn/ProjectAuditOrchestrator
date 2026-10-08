# Third-party integration policy

Tool-specific use and redistribution decisions require explicit human review;
this policy supplies no approval for an individual component.

## Rules

1. An adapter manifest is metadata, not permission to distribute its scanner, rules or database.
2. Each tool, adapter, ruleset and advisory database has separate source URL, version, SHA-256 or OCI digest, provenance status, license/data terms, update timestamp and redistribution decision.
3. Supported distribution modes are `metadata-only`, `user-installed` and `bundled`. `bundled` requires a License Integration Decision Record before publication.
4. GPL, LGPL, AGPL, custom, source-available, non-commercial, `LicenseRef-*` and unknown inputs are `user-installed-only` until an explicit review says otherwise.
5. Tool and database preparation is a separate, connected operation. Configured `pao audit` execution consumes only immutable, pre-verified local copies with scanner networking denied and may not update DBs or tools.
6. A license finding keeps the detected exact SPDX expression. A dual-license election needs selection basis plus linked policy/assumption; ambiguity remains `MANUAL_REVIEW`.
7. No document or output may claim legal advice, license clearance or safe redistribution merely from a technical scan.

## Required integration record

Every candidate tool must document: purpose/capability; upstream; exact version; platform; scanner output; source/tool/data license; redistribution mode; network behavior; target-write/target-execution behavior; pin and verification method; offline prerequisites; fixture corpus; known limitations; owner and review date.

## Initial scope

The register lists intended MVP tools only. This policy does not authorize installing, downloading, running or bundling any of them.
