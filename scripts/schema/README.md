# Offline JSON Schema validation

The current `unified-report-v1` schema requires native projection
`pao-native-projection/6`, including its optional verified-empty Go declaration
field. The schema ID remains `pao.dev/unified-report/v1`; select the schema from
the source revision matching the report's parser version. Historical `/5`
reports require their historical schema and are not rewritten or silently
accepted by the current `/6` schema. Historical plans without a content proof
do not gain one when a report is rendered again.

This source-only harness validates synthetic artifacts emitted by the actual PAO
libraries and explicit synthetic release-provenance profile examples. It uses
complete cached upstream schemas for SARIF 2.1.0, CycloneDX 1.5 and SPDX 2.3,
plus the repository's published PAO contracts and maintained profiles. The cached
upstream schema bytes are unchanged. Every cached schema, Python wheel and
license is identified by its source and SHA-256 in `schemas/vendor/pins.json`.

Run from the PAO repository root with its approved Go toolchain and Python 3.9
or newer. Ordinary user rights are sufficient. Select a new absolute corpus
directory and an explicitly approved absolute scratch directory. The generator
refuses to overwrite an existing corpus directory. The validator writes only
fresh temporary subdirectories beneath scratch, and installs no packages.

PowerShell example after selecting absolute repository and staging paths in
`$absoluteRepositoryRoot` and `$absoluteStagingBase`:

```powershell
Set-Location -LiteralPath $absoluteRepositoryRoot
$schemaRun = Join-Path $absoluteStagingBase ('PAO-schema-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $schemaRun | Out-Null
$schemaCorpus = Join-Path $schemaRun 'corpus'
$schemaScratch = Join-Path $schemaRun 'validation'
go run ./scripts/schema/corpus -repo (Get-Location).Path -out $schemaCorpus
if ($LASTEXITCODE -ne 0) { throw 'Synthetic corpus generation failed' }
python -I scripts/schema/validate.py --corpus $schemaCorpus --scratch $schemaScratch
if ($LASTEXITCODE -ne 0) { throw 'Schema validation failed' }
python -I scripts/schema/test_validator.py --corpus $schemaCorpus --scratch $schemaScratch
if ($LASTEXITCODE -ne 0) { throw 'Schema regression tests failed' }
```

In CI, use a new corpus directory and scratch directory below the runner's
temporary directory. No `pip install` or network access is needed. The `-I`
Python option excludes user site packages and environment path overrides.

For a specific document, select its declared schema explicitly:

```powershell
python -I scripts/schema/validate.py --schema unified-report-v1 --document $absoluteReportPath --scratch $schemaScratch
```

`--schema` accepts a schema filename stem from `schemas/` or the cached aliases
`sarif-2.1.0`, `cyclonedx-1.5` and `spdx-2.3`. Document values are not included in
error output; failures contain JSON pointers and failed schema keywords. The
wire reader also refuses duplicate keys, trailing JSON, non-finite numbers,
invalid UTF-8 and documents larger than 16 MiB.

The regression corpus includes findings and empty outputs, all ten shipped
adapter manifests, configured and default plans, native unified reports, both
configuration versions, a Docker provider, a toolchain catalog, and local/hosted
unsigned release-provenance profile examples. Negative
checks exercise field closure, required properties, unknown versions, formats,
nested cached references, producer identity, wire ambiguity, changed pins and
refusal of uncached references. Unknown HTTP, HTTPS and file references fail
closed; socket and URL access are disabled before validator imports.

The exact pure Python validator dependency graph is `jsonschema` 4.17.3,
`attrs` 23.2.0, `pyrsistent` 0.20.0, `rfc3339-validator` 0.1.4,
`rfc3986-validator` 0.1.1, `six` 1.17.0, `rfc3987-syntax` 1.1.0 and `lark`
1.2.2. These MIT-licensed wheels are hash checked before extraction and imports.
The older pinned validator avoids an unpinned native dependency and supports
the required draft 4, draft 7 and draft 2020-12 schemas. It is a development and
CI dependency, separate from the Go product runtime and public binary package.

Redistribution material is retained under `schemas/vendor/licenses`: Apache 2.0
for CycloneDX, CC-BY 3.0 for SPDX, the OASIS notices accompanying SARIF, and the
MIT texts for the Python wheels. Pins retain exact revision or release URLs and
attribution. Preserving these texts is evidence for a redistribution review;
it does not constitute legal approval.

`full_json_schema_validation: true` applies only to the documents listed in the
result and the complete selected schemas. Exact format versions are checked
separately because some upstream version properties permit broader strings.
JSON Schema does not prove complete component inventories, absence of
vulnerabilities, normative prose compliance, historical run lineage, binary
hash correctness, signatures, publication approval or runtime isolation.
SARIF, CycloneDX and SPDX cases exercise the internal report library's exports;
they do not establish release support for those CLI output modes. Synthetic
cases launch no scanner and approve no toolchain record.

## PAO release provenance profile

`schemas/release-provenance-v1.json` is a PAO-maintained strict producer profile
for every field currently emitted by
`scripts/release/generate-release-metadata.ps1`. Its schema ID is
`https://pao.dev/schemas/release-provenance/v1`. It derives its field semantics
from [SLSA v1.2 Build Provenance](https://slsa.dev/spec/v1.2/build-provenance),
whose predicate type remains `https://slsa.dev/provenance/v1`, and the in-toto
[Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[ResourceDescriptor](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md),
[field types](https://github.com/in-toto/attestation/blob/main/spec/v1/field_types.md)
and [DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)
specifications. These primary sources were checked on 2026-10-02. The JSON
Schema is original PAO source; no additional upstream schema bytes, licenses or
executable dependencies were vendored for this profile.

The profile requires all current nested objects and fields, safe release-version
and Go-version strings, the source-state vocabulary, lowercase SHA-256 values,
the current repository URI and its 40-character Git object identifier. Four
unordered subjects must identify the Windows AMD64 archive, Linux AMD64 archive,
CycloneDX document and build metadata, with one occurrence per artifact kind.
Subjects require a name and SHA-256 digest; the single source dependency requires
a URI and `gitCommit` digest. This satisfies each context's ResourceDescriptor
minimum while deliberately allowing only the producer's present field set.

Both known builder labels are covered. The hosted label requires its numeric
GitHub `invocationId`; the local label omits it. Timestamps require valid calendar
values in RFC3339 UTC `Z` form and may contain fractional seconds. Validation
rejects nested wrong types, nulls, missing fields, unexpected fields, malformed
digests/URIs/timestamps and mismatched builder/invocation shapes.

These are strict PAO producer rules. Upstream parsing rules require consumers to
ignore unrecognized fields and treat unset, null and empty values equivalently;
the general formats support more ResourceDescriptor fields, optional metadata,
other builders, opaque invocation identifiers, and 40- or 64-character Git
identifiers. A document rejected by this fixed producer profile can therefore
still be valid for the general specifications. This harness serves PAO producer
contract checking; it is not a general-purpose upstream attestation consumer or
an official upstream JSON Schema.

Validate the exact unsigned package output, with existing absolute document and
scratch paths selected explicitly:

```powershell
python -I -B scripts/schema/validate.py --schema release-provenance-v1 --document $absoluteProvenancePath --scratch $schemaScratch
if ($LASTEXITCODE -ne 0) { throw 'PAO release provenance profile validation failed' }
```

On success, `full_json_schema_validation: true` and
`full_pao_release_provenance_profile_validation: true` describe the complete
selected PAO profile and listed document. They establish neither universal
SLSA compliance nor a SLSA level, authenticated builder/signer identity,
dependency or input completeness, reproducibility, actual build-time accuracy,
signature validity or publication approval. `builder.id` is a document value,
not authenticated evidence of the service that produced it. The generator uses
its caller-provided `AsOf` for both timestamps; schema checking does not turn
those values into measured execution times. For modified source, the recorded
HEAD dependency alone does not identify all modified source bytes.

The profile does not compare timestamps, bind each subject filename to the
external version, recompute file digests, or compare the source revision/tree
and Go version with separate build metadata. Keep the release integrity and
build-identity verifier as independent checks. The synthetic corpus covers both
profile shapes without executing PowerShell or building binaries; validation of
actual generator/package output must use `--document` as above.
