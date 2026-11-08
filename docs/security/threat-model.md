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
| Secret/PII disclosure | Declared scanner environment and allowlisted portable fields | Secret/PII fixture report test |
| Malicious tool/plugin | Version/digest/provenance pin and out-of-process protocol | Toolchain verification test |
| Parser/output bomb | Schema validation, size/depth/stream bounds and quotas | Malformed/bomb fixtures |
| Policy or cache poisoning | Content-addressed digests and immutable inputs | Determinism/cache tests |

## Residual risks

Configured execution requires `container-vm`; native host process mode is not a fallback. Native output is parsed inside PAO under format-specific limits, without parser-process isolation. Same-account and privileged host actors remain trusted. The v3 installation journal records intent before container creation and the complete container ID before start. Pending records survive a PAO restart and block dependent launches. Recovery matches installation/run labels, image and full container ID before controlled cleanup; it preserves evidence and refuses ambiguous ownership. See [frozen inputs](frozen-inputs.md) for ownership and lifecycle details. Legal classification remains human-governed.

The host Docker CLI inherits the operator's process environment except
`DOCKER_*` overrides. This is separate from the declared environment supplied
to scanner containers. Hashing the Docker executable does not attest every
native library or plugin it may load; the operator's account and host remain
trusted prerequisites.

## Online preparation boundary

Explicit `setup --apply` can download allowlisted public artifacts and prepare
an isolated runtime. Its network phase does not accept target contents, target
configuration files or repository package-manager commands. Archive extraction
rejects links, traversal, excessive entries and expanded size. Tool recipes
bind exact versions and hashes; changing advisory databases are captured with
provenance and snapshot identity. Approval of a preparation plan is distinct
from the owner's later approval of the completed installation and synthetic
verification. Setup does not install Docker Desktop or accept its terms.

The bundled probe executes fixed synthetic checks, without an arbitrary
command or target argument. Those checks establish measured properties of one
runtime; they do not prove all scanners work or constitute a security verdict.
Ordinary audits retain network denial and exact run-specific confirmation.
