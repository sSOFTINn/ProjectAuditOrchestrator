# PAO threat model

## Assets and trust boundaries

- **Untrusted**: target repository path, source, instructions, hooks, configuration, artifacts and scanner native output.
- **Trusted only after verification**: PAO binary, pinned toolchain records, schemas, policy packs and fixture corpus.
- **Protected assets**: host filesystem/credentials, target integrity, raw evidence lineage, secrets/PII and policy verdicts.

## Threats and controls

| Threat | Required control | Verification |
|---|---|---|
| Shell/argument injection | Fixed `argv[]`, executable/options allowlist, no shell | Hostile argv fixture |
| Target instruction injection | Treat all target files as data; no instruction execution | `AGENTS.md` fixture |
| Path/symlink/junction escape | Canonical root check, relative URIs, no follow outside root | Windows junction/Linux symlink fixture |
| Package lifecycle RCE | No install/build/test scripts in default mode | Process event assertions |
| Network exfiltration | Scanner networking denied in the local Docker Desktop Linux VM | Offline integration test |
| Host or target mutation | Read-only target and pre/post manifest | Manifest equality test |
| Secret/PII disclosure | Environment allowlist and redaction before portable output | Secret/PII fixture report test |
| Malicious tool/plugin | Version/digest/provenance pin and out-of-process protocol | Toolchain verification test |
| Parser/output bomb | Schema validation, size/depth/stream bounds and quotas | Malformed/bomb fixtures |
| Policy or cache poisoning | Content-addressed digests and immutable inputs | Determinism/cache tests |

## Residual risks

Configured execution requires `container-vm`; native host process mode is not a fallback. Native output is parsed inside PAO under format-specific limits, without parser-process isolation. Same-account and privileged host actors remain trusted. After unconfirmed container cleanup, retained inputs and the process-local launch block require operator recovery; that block does not survive a restart. See [frozen inputs](frozen-inputs.md) for ownership and lifecycle details. Legal classification remains human-governed.
