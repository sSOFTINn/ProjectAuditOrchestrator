# Private toolchain catalog for portable configuration v2

Public templates are deliberately unusable. Installing, licensing and reviewing
scanner bytes, state, databases and images is a separate operator task. No catalog
operation downloads them. Do not replace approval placeholders with invented values.

This describes the v0.2 catalog contract. Each installation needs its own verified
tool, data and runtime approvals.
Use the exact manifests from the verified package. Their compatible tool/native
schema versions are admission boundaries; a hash match does not approve a new
scanner version, unknown JSON shape or every adjacent runtime file.

Use `audit.json` version `pao.dev/local-audit-config/v2`. Required absolute paths:
`target`, `evidence_base`, `report_base`, `toolchain_root`, `manifest_root`,
`toolchain_catalog`. Evidence/reports and trusted configuration must not overlap
the untrusted target. `manifest_root` points at the package's `adapters` directory.
`docker_base_provider` / `docker_scancode_provider` are absolute paths to reviewed
provider JSON; only providers selected by the profile are required. `rule_pack_root`
may be empty unless a selected adapter needs rules. Windows JSON paths escape
backslashes; catalog-relative paths always use `/`.

The catalog requires `api_version`, `owner`, `approved_at`, `expires_at`, and
`tools` (1–10 unique supported tools). Approval must already have occurred, remain
unexpired and span at most 90 days. `UNAPPROVED` is rejected. Timestamps are UTC
RFC3339. Catalog approval does not extend prerequisite freshness: database, state,
runtime, rule and license-data timestamps are checked separately.

This complete one-tool example is intentionally invalid. It shows field placement,
not an approved installation. A `secrets` profile needs Gitleaks and its provider;
`mvp` needs the selected tools and their prerequisites. `record` SHA-256 values
are measured 64-hex digests without `sha256:`; versions/licenses must match the
exact installed bytes and the adapter contract.

```json
{
  "api_version": "pao.dev/toolchain-catalog/v1",
  "owner": "UNAPPROVED",
  "approved_at": "1970-01-01T00:00:00Z",
  "expires_at": "1970-01-01T00:00:00Z",
  "tools": [
    {
      "record": {
        "id": "gitleaks",
        "version": "REPLACE_WITH_REVIEWED_VERSION",
        "sha256": "REPLACE_WITH_64_HEX_TOOL_DIGEST",
        "source_license": "MIT",
        "redistribution": "user-installed-only",
        "runtime_sha256": "REPLACE_WITH_64_HEX_LOCAL_IMAGE_ID",
        "runtime_at": "1970-01-01T00:00:00Z"
      },
      "binary": "gitleaks/REPLACE_VERSION/bin/gitleaks",
      "provider": "base"
    }
  ]
}
```

`binary`, `database`, `state` are relative to `toolchain_root`; `rule_pack` is
relative to `rule_pack_root`; `state_entrypoint` is relative to `state`. These
paths cannot be absolute, use drive letters or `..`, or escape roots through
links. `provider` is `base` or `scancode`. Its `runtime_image` must equal
`sha256:` plus `record.runtime_sha256`. Provider `docker_sha256` and `runtime_image`
use the prefix; catalog digests do not. The provider template records the Docker
CLI identity and separate runtime approval (`id`, `owner`, `evidence_digest`,
`expires_at`). Approval is evidence-backed; it is not implied by a hash match.

Additional prerequisite fields go inside `record` as digest/time pairs, with
the matching directory outside `record`:

| Tool | Required extra fields |
| --- | --- |
| Grype, OSV Scanner, Trivy | `database`, `database_sha256`, `database_at`; environment below where needed |
| Opengrep | `state`, `state_sha256`, `state_at`, `state_environment`, `rule_pack`, `rule_pack_sha256`, `rule_pack_at` |
| ScanCode | `state`, `state_entrypoint`, `state_sha256`, `state_at`, `state_environment`, `license_data_sha256`, `license_data_at` |
| REUSE | `state`, `state_entrypoint`, `state_sha256`, `state_at` |
| Syft, Gitleaks, zizmor, sbomqs | No extra catalog directories; exact binary/runtime identity still required |

Do not hash a directory name or concatenate arbitrary files. Database/prepared
state manifests and rule/license-data identities follow the PAO capsule protocol,
including file inventories and digest validation. Prepare them separately for
the selected scanner version and record source, retrieval time, hashes, terms
and a source-specific expiry in the private catalog. A previous machine's
database or tool approval does not transfer to another installation. See the
[toolchain and license register](legal/toolchain-register.md) for the separation
between local use and redistribution.

Environment values are container paths, not host paths, and must match registered
capsule metadata and the adapter allowlist. Supply the following maps inside
`record`; they are separate tool-specific examples, not one combined map.

Grype:

```json
{"database_environment":{"GRYPE_DB_CACHE_DIR":"/pao/database","GRYPE_DB_AUTO_UPDATE":"false","GRYPE_CHECK_FOR_APP_UPDATE":"false"}}
```

OSV Scanner:

```json
{"database_environment":{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY":"/pao/database"}}
```

Opengrep:

```json
{"state_environment":{"HOME":"/pao/state","TMPDIR":"/pao/state","XDG_CACHE_HOME":"/pao/state","SEMGREP_LOG_FILE":"/pao/out/semgrep.log"}}
```

ScanCode:

```json
{"state_environment":{"PYTHONDONTWRITEBYTECODE":"1","SCANCODE_CACHE":"/pao/out/scancode-cache","SCANCODE_TEMP":"/pao/out/scancode-tmp"}}
```

Trivy's database path and offline flags come from fixed manifest arguments.
REUSE has no allowed environment map. A catalog cannot supply shell commands,
arbitrary arguments, network permission or custom output destinations. Changes to
catalog/provider invalidate the previous preview and require a fresh plan and its
exact `RUN <audit-id> <plan-digest>` confirmation.

## Support and inventory boundaries

Profile applicability, supported input/ecosystem, verified availability and
execution/parsing are separate. The current OSV local DB covers Go only.
Present PyPI/npm/crates.io inputs are `DB_ECOSYSTEM_UNSUPPORTED`; Python-only
OSV is `UNSUPPORTED`, not `SKIPPED_NOT_APPLICABLE`. A mixed Go/PyPI target can
retain Go execution while support is partial. Changing the database directory
or its approval does not silently expand the adapter's admitted ecosystem claim.

Filename detection does not parse package managers. `requirements.lock` and
`build-requirements.lock` have `UNSUPPORTED_INPUT_FORMAT`. `inventory_coverage`
compares detected expected ecosystems with verified Syft observations; Actions-only
inventory does not cover PyPI. Legacy `coverage_complete` concerns execution and
parsing, while `analysis_coverage_complete` also includes support/inventory gaps.
No field or informational sbomqs score proves a full runtime/build/transitive
inventory, absence of vulnerabilities or a legal decision. sbomqs receives the
captured SBOM only and requires its own exact owner-approved tool identity.

## Verified bytes at use

The runner copies admitted tool, database, state, rule and captured-input bytes
into private per-execution frozen inputs, then verifies their actual bytes and
capsule inventories. The originals are not writable scanner mounts. Default
freeze caps are 4 GiB per file, 8 GiB per copied payload, 100,000 entries and
16 MiB per capsule manifest; excess, drift, redirect or cancellation refuses
launch. Docker CLI and the bundled `pao-sandbox-linux-amd64` helper also retain
their approved pinned/frozen identity through use. This does not renew freshness
or approval and does not automatically approve native DLL/plugin dependencies.
See the [writer/ownership model](security/frozen-inputs.md).

Keep the bundled helper beside PAO in both binary archives. Scanner output and
scratch use byte/inode-limited VM tmpfs with no writable host output mount.
The host accepts only bounded declared results; overflow/truncation remains
nonpass. This mechanism is distinct from registry hashes and CPU/RAM/time limits.

After actual Gitleaks approval, start with synthetic inputs and
`pao audit --config ABSOLUTE_FILE --profile secrets`. There is no automatic
download, update or approval. The provider accepts only a local Docker Desktop
Linux VM; ordinary/rootless Linux engines and remote contexts are unsupported.
Each supported host requires acceptance of the exact PAO candidate, Docker
Desktop installation and scanner/runtime versions. Successful parsing, dry
planning or cross-build does not establish that compatibility. Native output is
bounded but parsed inside PAO; parser-process isolation is absent. Neither
catalog approval nor technical tests approve release publication.
