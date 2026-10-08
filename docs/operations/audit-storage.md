# PAO audit-storage policy

This policy separates protected evidence from portable reports. Each operator
selects and provisions private roots before running an audit.

## Fixed roots

| Material | Root | Purpose | Publication rule |
|---|---|---|---|
| Protected raw evidence | `<evidence_base>\<year>\<audit-id>\` | Native scanner output, run locks, manifests, journals, tool and state identities. | Never commit, publish, synchronise to cloud or copy to a target repository. |
| Human-readable audit result | `<report_base>\<year>\<audit-id>\` | Redacted decision summary and the evidence index needed by the owner. | Local by default; external sharing needs a separate owner decision for this exact audit. |

`<audit-id>` is a stable, human-readable identifier chosen before the run, for example
`2026-10-08-example-audit`. It must not contain a real secret, person name, or an
unbounded target path.  A run must fail closed if a raw-evidence root is a symbolic link/reparse
point, lies inside the target, or cannot be protected with the required access controls.

## Required audit layout

```text
audits/<year>/<audit-id>/
├── 00_scope/        # approved scope and target identity, no target content
├── 01_inventory/    # redacted inventory/SBOM summary
├── 02_security/     # portable security findings and coverage state
├── 03_licenses/     # license observations and manual-review queue
├── 04_quality/      # quality and completeness summary
├── 05_decisions/    # owner decisions, waivers and residual risks
└── 06_report/       # final redacted report and evidence index
```

The matching protected evidence directory is content-addressed and may contain more material than
the report directory.  Its stable SHA-256 references, not absolute paths or raw contents, provide
the link between the two roots.

## Product rules and operator responsibilities

1. Store native output before parsing or normalization in the protected raw-evidence root.
2. Store only redacted, portable projections in the report root.  Never copy native scanner output,
   secrets, credentials, PII, target source files, or absolute local paths there.
3. Keep one independent raw artifact and coverage outcome per adapter; a missing tool, database,
   rule pack, state capsule, timeout or isolation failure remains explicit and non-pass.
4. Do not delete, overwrite, deduplicate away, or relocate raw evidence as a side effect of report
   generation.  Retention is indefinite by default; deletion needs a separately recorded owner
   decision for the exact audit directory.
5. Treat report folders as local audit artifacts.  They are ignored by this source repository so a
   Git commit cannot publish an audit result accidentally.
6. Review the ACL/BitLocker protection of the private evidence root and perform an encrypted-backup
   restore drill every 90 days.  A failed review or restore drill blocks new release claims and must
   be visible in the affected audit's `05_decisions/` folder.

## Operational boundary

This policy creates no audit, does not inspect a target and does not grant authority to publish,
delete, share or run a real scanner.  The owner must separately approve the exact target and audit
scope before any real run.
