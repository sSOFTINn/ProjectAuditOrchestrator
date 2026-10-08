# Release verification guide

Use this procedure to verify the exact source, signed tag and release archives.
The version `0.2.0-rc.1` in the local example below is illustrative, not a published
or approved candidate identity. See the [current release scope](release/v0.2-public-scope.md).
Planning, review and verification records are retained internally. A local
build or this guide alone does not establish release approval.

The exact public distribution contains three files:

- `pao-VERSION-windows-amd64.zip`
- `pao-VERSION-linux-amd64.tar.gz`
- `SHA256SUMS.txt`

The separate internal `evidence` directory contains `BUILD-METADATA.json`,
`pao-VERSION.cdx.json`, `pao-provenance.intoto.json` and its own `SHA256SUMS.txt`.
Never upload that directory, test reports or the runner-local transfer manifest
to a public repository, workflow artifact or release. The binary archives do
not contain those evidence files.

Each archive has exactly twenty-one allowlisted files: its host PAO binary,
the owned static Linux `pao-sandbox-linux-amd64` supervisor, ten adapter
manifests, three blank JSON templates, beginner guide, LICENSE, NOTICE, Go license,
`VERSION.json` (version/platform/architecture) and a content manifest. The Linux binary has mode `0755`. Source
archives are handled separately by GitHub for an approved tag; neither the packager
nor the workflow publishes a GitHub Release or changes visibility.

## Build and verify locally without downloads

From a trusted clean source checkout on Windows, in PowerShell 7.2+, with approved Go 1.27.1 already
installed. Replace `D:\staging\pao-candidate` with a new staging directory outside
the repository and `D:\tools\go\bin\go.exe` with your local toolchain. Ordinary
user rights suffice. These commands do not download tools or dependencies:

The paths and prerelease version are examples: substitute the approved checkout,
new staging output, exact Go path and candidate version. The timestamp comes from
the selected commit, matching the hosted build contract.

```powershell
Set-Location 'D:\src\ProjectAuditOrchestrator'
$env:GOTOOLCHAIN = 'local'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$paoCommitTimestamp = (& git show -s --format=%cI HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot read source commit timestamp.' }
$paoAsOf = [DateTimeOffset]::Parse($paoCommitTimestamp, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
.\scripts\release\build-public-package.ps1 -OutputPath 'D:\staging\pao-candidate' -Version '0.2.0-rc.1' -AsOf $paoAsOf -GoPath 'D:\tools\go\bin\go.exe'
.\scripts\release\verify-release.ps1 -DistributionPath 'D:\staging\pao-candidate\dist' -EvidencePath 'D:\staging\pao-candidate\evidence' -PackageVerifierPath 'D:\staging\pao-candidate\work\package-verifier.exe'
```

`-AllowDirty` is allowed only for local prerelease preparation. Stable packages require
a clean tree at the selected `main` commit. The internal source record contains `source_state` and a digest of the
current nonignored source files; a modified build does not claim to be that commit.
The builder refuses existing output and changes to source during the build. Repeat
with the same source, toolchain, version and timestamp in a different new directory
and use `compare-public-builds.ps1 -FirstDistributionPath FIRST/dist -SecondDistributionPath SECOND/dist`.
It requires identical file sets and SHA-256 for both archives and the checksum
manifest. Repeat builds on the same host are not independent reproduction.
Keep failed candidates separate as incomplete evidence.

The verifier must return `"status":"VERIFIED"`. It checks both exact archives, the
file allowlist and hashes inside them without extracting or running their contents,
CycloneDX 1.5 envelope, bounded unambiguous metadata JSON, consistent versions/build
identity, and exact provenance subjects. Unexpected files, missing platforms,
duplicate entries, unsafe paths, links and mismatched hashes fail. Build smoke tests
execute only the native binary built from the trusted source checkout. Never pass
an untrusted archive's program as `-PackageVerifierPath`; use the helper just built
from the reviewed source.

This bounded verifier is **not** full CycloneDX/SLSA schema validation, an independent software inventory,
a signature check or release approval. These limits are explicit in the JSON result:
`full_schema_validation`, `signature_verified` and `release_approved` remain `false`.
The generated SBOM lists PAO and its Go toolchain; it does not inventory external scanners.
Separate selected-schema and PAO provenance-profile checks are recorded internally;
they do not change this
verifier's claims or establish a signature, builder trust or SLSA level.
Local metadata names the local generator; metadata timestamps describe supplied
packaging time, not measured compilation duration. Go standard-library/runtime
licensing is included; scanners are absent. The generated SBOM is a bounded build
inventory, not a complete transitive component analysis.

Metadata generation requires both public archives and the separately stored
private BUILD-METADATA.json, and refuses existing metadata or overlapping paths.
Its deterministic UUID binds version, time and hashes. Public users can run
`verify-public-release.ps1` with `-DistributionPath`, `-Version` and a trusted
`-PackageVerifierPath` without accessing internal evidence. This validates archive
composition and hashes, not publisher identity or approval.

The release workflow runs Go tests/vet, both builds, archive composition verification
and adversarial metadata checks. For the latter, use `scripts/release/test-release-metadata.ps1`
with `-OutputBase`, `-GoPath`, `-FixtureDistributionPath` pointing at the verified `dist`,
`-FixtureEvidencePath` pointing at the associated private `evidence`,
and `-PackageVerifierPath` pointing at the trusted compiled helper. It mutates only
new test copies and never runs packaged contents. Tests cover absence of one platform,
extra private payloads, duplicate fields, wrong versions and malformed metadata.

The self-audit command writes its JSON result outside the audited directory and compares the
target manifest before and after inspection. It rejects an output path inside the target.

## Verify the signed tag and public hashes

The owner selected a signed `v0.2.0` tag and public checksums; build provenance
and SBOM stay internal. The workflow does not publish keyless attestations.
Before release, record the owner's trusted signing identity and key, approve
the exact clean main commit and final public bytes, then prepare a signed tag
whose annotation includes this exact field:

```text
SHA256SUMS.txt SHA256: APPROVED_64_LOWERCASE_HEX_DIGEST
```

The value must be the SHA-256 of the final `SHA256SUMS.txt`. A signed tag that
only names a commit does not authenticate separately uploaded binary archives.
Signing and publication require their own exact approval; local preparation
does not create a tag or install trust keys.

After the approved tag is available in a trusted local checkout, verify its
signature against the separately trusted owner key, check its peeled commit,
and compare the signed checksum-manifest digest with the downloaded file:

```sh
git verify-tag v0.2.0
git rev-parse 'v0.2.0^{commit}'
git cat-file tag v0.2.0
sha256sum SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

On Windows, use the same Git checks and `Get-FileHash -Algorithm SHA256` for
the manifest and each listed archive. A cryptographically valid signature from
an unknown key is insufficient. The trusted key, commit, signed digest and
archive hashes must all match the independently approved values. Missing or
mismatched evidence prevents verification. Obtain the expected signer fingerprint
through a trusted maintainer channel; this guide alone does not prove a signature.

## Smoke test after verification and extraction

Use an existing inert synthetic directory first. The path below is an example;
substitute the prepared directory outside the source checkout:

```powershell
$paoSyntheticTarget = 'D:\staging\pao-synthetic-target'
& .\pao.exe version
& .\pao.exe doctor
& .\pao.exe inspect --target $paoSyntheticTarget
& .\pao.exe plan --target $paoSyntheticTarget --profile fast --dry-run
```

On Linux substitute `./pao`. `plan --dry-run` must not launch adapters. A real
audit requires exact local setup, tool approval and verified provider isolation.
No successful smoke test replaces exact-candidate native scanner acceptance on
Windows 11 and Ubuntu 24.04 LTS with the selected Docker Desktop versions.
