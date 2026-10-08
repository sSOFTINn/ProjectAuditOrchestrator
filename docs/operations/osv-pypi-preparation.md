# Manual OSV PyPI database preparation

Owner-approved workflow: separate connected database preparation, offline target
scan, explicit review of the exact SHA-256, maximum 90-day approval/data age.

`scripts/stage_osv_pypi_database.py` only downloads the public PyPI dump from
the [OSV bulk-data endpoint](https://google.github.io/osv.dev/data/).
It has no target argument, query payload or scanner invocation. It does not
read project code, upload evidence, change an active database or grant approval.
No scheduled task is created. Without `--manual`, it refuses before network or
filesystem writes. Only a new candidate directory on a local fixed drive is
accepted. Redirects, proxy discovery, overwrites and archive extraction are absent.

Example, invoked by the owner from the PAO root after creating the exact parent
directory in the protected OSV toolchain database area:

```powershell
python scripts/stage_osv_pypi_database.py --manual --output '<new-local-candidate-directory>'
```

Optionally pass `--expected-sha256` from a separately trusted publisher record.
Without it, HTTPS identifies the source and the resulting SHA-256 identifies
downloaded bytes; the checksum alone does not authenticate the publisher.
The ZIP is bounded, reread and validated without extraction. Candidate metadata
records upstream Last-Modified, download date, hash and `PENDING_APPROVAL`.
Errors leave an unusable partial download with no successful candidate manifest.

Before activation the owner must review the exact candidate and its data-source
license terms, reject missing/stale data, approve its SHA-256, and validate the
scanner-native import on synthetic PyPI input. The current PAO local runner has
a pinned Go-only database record; native import and a new reviewed registry
record are still required. This staging command does not bypass that gate.
No new production database was downloaded or approved during remediation.

## Current input and coverage contract

The public local-audit contract still admits a **Go-only OSV database**. A Python
input is applicable, but its database coverage is unsupported. Python-only plans
therefore record `UNSUPPORTED` / `DB_ECOSYSTEM_UNSUPPORTED`; they do not claim that
Python files are absent. Mixed Go/Python plans can run the admitted Go check while
recording partial feed coverage. Staging a PyPI ZIP does not change this contract.

PAO detects dependency expectations from names such as `pyproject.toml`,
`requirements.txt`, `poetry.lock`, `Pipfile.lock` and `uv.lock`. Recognition of a
name is not validation of its contents or proof that a scanner consumed it.
`requirements.lock` and `build-requirements.lock` are explicitly recorded as
`UNSUPPORTED_INPUT_FORMAT`: those names do not identify a standard wire format,
and PAO neither renames nor passes them off as `requirements.txt`. The latter
name carries a build-scope hint; all other scopes remain unspecified. Arbitrary
`.lock` names are not accepted as dependency lockfiles.

`coverage_complete` retains its execution/parsing meaning.
`analysis_coverage_complete` also checks known support gaps and the
`inventory_coverage` record. The record compares expected ecosystems with
ecosystems observed in verified Syft output and reports missing ecosystems,
missing versions and unsupported input formats. GitHub Actions inventory cannot
stand in for PyPI inventory. An empty inventory for a dependency manifest remains
unresolved until the absence of dependencies is established separately.
The captured CycloneDX component identities must also match the native Syft
inventory; an empty or divergent export cannot substantiate the Grype input.
`adequate_for_detected_inputs` is only this bounded adequacy check; it does not
prove enumeration of every runtime, build, optional or transitive package.
SBOM quality scores remain informational and cannot close these gaps.

Activating PyPI support is a separate scope change. It requires reviewed
source/license and immutable database identity, freshness, scanner-native import,
and a known-vulnerable synthetic PyPI positive control plus a non-vulnerable
negative control. Neither this documentation nor the staging helper grants that
activation, runs a scanner or downloads a database.

Verification uses only synthetic ZIPs and a mocked HTTP stream:
`python -m unittest discover -s scripts -p test_stage_osv_pypi_database.py -v`.
