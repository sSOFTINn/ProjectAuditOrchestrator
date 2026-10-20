# MVP toolchain, license and redistribution register

This is a design-time register. A release may use a tool only after exact version, checksum/image digest, source URL, DB/rule digest/timestamp and license evidence are recorded in a signed toolchain manifest.

## PAO build toolchain pin

The approved development toolchain is Go `1.27.1`. Its Windows and Linux AMD64 archive SHA-256 values are
recorded in `scripts/toolchain/go-1.27.1-checksums.txt`; verification is offline and fails
closed through `scripts/verify-go-toolchain.ps1` or `scripts/verify-go-toolchain.sh`. The
archive is a developer/CI input, never an audit-time dependency and never downloaded by PAO.

| Capability | Primary | Fallback / skip | Mode | Evidence contract |
|---|---|---|---|---|
| SBOM inventory | Syft (Apache-2.0) | `UNAVAILABLE`; no synthetic BOM | download-not-bundle | Syft JSON, version/digest, target snapshot |
| SBOM quality | sbomqs (Apache-2.0), compatible version 2.1.1 | `UNAVAILABLE` without owner approval; informational score only | user-installed-only | Captured Syft CycloneDX input, legacy JSON score, tool version/digest and linked evidence; [adapter contract](../../adapters/sbomqs/manifest.json) and [local operation](../operations/sbomqs-local-operation.md) |
| Deep SCA | Grype + OSV-Scanner (Apache-2.0) | `PARTIAL` with DB age if either absent/stale | user-installed | Native JSON/SARIF, DB digest/timestamp |
| Fast/IaC | Trivy (Apache-2.0) | `UNAVAILABLE` | user-installed | Native JSON/SARIF, DB/rule digest |
| License/copyright | ScanCode (Apache-2.0; reference dataset CC-BY-4.0 with documented secondary terms) | `MANUAL_REVIEW` for missing coverage | user-installed, no redistribution | Native JSON/JSONL, exact license-data subset digest and terms |
| REUSE compliance | REUSE (GPL-3.0-or-later) | `UNAVAILABLE`; no bundled distribution | user-installed-only | JSON/SPDX, version/config |
| Secrets | Gitleaks (MIT) | `UNAVAILABLE` | user-installed | Redacted native JSON/SARIF, version/config |
| SAST | Opengrep (LGPL-2.1) + PAO-owned Apache-2.0 baseline rules | `UNAVAILABLE` until owner production approval | user-installed-only | Native JSON/SARIF, exact runtime/state/rule digests |
| Workflow security | zizmor (MIT), conditional | `SKIPPED` when no workflow artifacts | user-installed | Native JSON/SARIF, detector evidence |

## Review rules

No GPL/LGPL/AGPL/custom/source-available/unknown tool is bundled just because it runs out-of-process. DB/rule data has its own license and redistribution review. “Offline” means an imported, verified immutable cache; updates occur only through a separate connected phase.
