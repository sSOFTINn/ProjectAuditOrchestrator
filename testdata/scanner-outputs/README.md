# Synthetic scanner-output fixtures

Fixtures in this directory are intentionally synthetic. They exercise parser and evidence
handling without containing a real project, package, secret, personal data, scanner binary or
database.

| Fixture | Expected adapter status | Purpose |
|---|---|---|
| `syft/success.json` | `SUCCEEDED` | One valid synthetic component. |
| `syft/empty.json` | `NO_FINDINGS` | Valid SBOM with no artifacts. |
| `syft/partial.json` | `PARTIAL` | Valid SBOM with an explicit source limitation. |
| `syft/error.json` | `FAILED` | Structured upstream failure. |
| `syft/malformed.json` | `FAILED` | Invalid JSON; no result must be inferred. |

The fixture corpus is parser input only. It never authorizes launching a scanner or target code.
