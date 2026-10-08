#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputBase, [Parameter(Mandatory)][string]$GoPath, [Parameter(Mandatory)][string]$FixtureDistributionPath, [Parameter(Mandatory)][string]$FixtureEvidencePath, [Parameter(Mandatory)][string]$PackageVerifierPath)
$ErrorActionPreference = 'Stop'
$build = Get-Content -LiteralPath (Join-Path $FixtureEvidencePath 'BUILD-METADATA.json') -Raw | ConvertFrom-Json
$version = $build.version
$asOf = [datetime]$build.as_of
$sbomFile = "pao-$version.cdx.json"
$root = Join-Path ([IO.Path]::GetFullPath($OutputBase)) ('release-metadata-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$passed = [Collections.Generic.List[string]]::new()
function New-Fixture([string]$Name) {
    $dir = Join-Path (Join-Path $root $Name) 'evidence'
    $dist = Get-PublicDirectory $dir
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    [IO.Directory]::CreateDirectory($dist) | Out-Null
    foreach ($name in @("pao-$version-windows-amd64.zip", "pao-$version-linux-amd64.tar.gz")) { [IO.File]::Copy((Join-Path $FixtureDistributionPath $name), (Join-Path $dist $name), $false) }
    [IO.File]::Copy((Join-Path $FixtureEvidencePath 'BUILD-METADATA.json'), (Join-Path $dir 'BUILD-METADATA.json'), $false)
    & (Join-Path $PSScriptRoot 'generate-release-metadata.ps1') -DistributionPath $dist -EvidencePath $dir -Version $version -AsOf $asOf -GoPath $GoPath | Out-Null
    return $dir
}
function Get-PublicDirectory([string]$EvidenceDirectory) { return (Join-Path (Split-Path -Parent $EvidenceDirectory) 'dist') }
function Update-Checksums([string]$Dir) {
    foreach ($directory in @($Dir,(Get-PublicDirectory $Dir))) {
    $lines = foreach ($file in (Get-ChildItem -LiteralPath $directory -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name)) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $file.Name
    }
    [IO.File]::WriteAllLines((Join-Path $directory 'SHA256SUMS.txt'), $lines)
    }
}
function Assert-Rejected([string]$Name, [scriptblock]$Mutate) {
    $dir = New-Fixture $Name
    & $Mutate $dir
    Update-Checksums $dir
    $refused = $false
    try { & (Join-Path $PSScriptRoot 'verify-release.ps1') -DistributionPath (Get-PublicDirectory $dir) -EvidencePath $dir -PackageVerifierPath $PackageVerifierPath | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw "Verifier accepted invalid metadata: $Name" }
    $passed.Add($Name)
}
$first = New-Fixture 'valid'
$second = New-Fixture 'repeat'
$sbom = Get-Content -LiteralPath (Join-Path $first $sbomFile) -Raw | ConvertFrom-Json
if ($sbom.serialNumber -cnotmatch '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') { throw 'Generated SBOM has an invalid UUIDv5 serial' }
if ((Get-FileHash -LiteralPath (Join-Path $first $sbomFile)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $second $sbomFile)).Hash) { throw 'Same input produced a different SBOM' }
$result = & (Join-Path $PSScriptRoot 'verify-release.ps1') -DistributionPath (Get-PublicDirectory $first) -EvidencePath $first -PackageVerifierPath $PackageVerifierPath | ConvertFrom-Json
if ($result.status -ne 'VERIFIED' -or -not $result.provenance_subjects_verified -or
    $result.full_schema_validation -or $result.signature_verified -or $result.release_approved) { throw 'Invalid verification claims' }
$passed.Add('valid-repeatable-sbom')
$before = (Get-FileHash -LiteralPath (Join-Path $first 'SHA256SUMS.txt')).Hash
$refused = $false
try { & (Join-Path $PSScriptRoot 'generate-release-metadata.ps1') -DistributionPath (Get-PublicDirectory $first) -EvidencePath $first -Version $version -AsOf $asOf -GoPath $GoPath | Out-Null } catch { $refused = $true }
if (-not $refused -or $before -ne (Get-FileHash -LiteralPath (Join-Path $first 'SHA256SUMS.txt')).Hash) { throw 'Existing release metadata was not preserved' }
& (Join-Path $PSScriptRoot 'verify-release.ps1') -DistributionPath (Get-PublicDirectory $first) -EvidencePath $first -PackageVerifierPath $PackageVerifierPath | Out-Null
$passed.Add('refuse-existing-metadata')
$empty = Join-Path $root 'empty-candidate'
[IO.Directory]::CreateDirectory($empty) | Out-Null
$refused = $false
try { & (Join-Path $PSScriptRoot 'generate-release-metadata.ps1') -DistributionPath $empty -EvidencePath $first -Version '0.2.0-test' -AsOf ([datetime]'2026-09-05T00:00:00Z') -GoPath $GoPath | Out-Null } catch { $refused = $true }
if (-not $refused -or @(Get-ChildItem -LiteralPath $empty -Force).Count) { throw 'Empty candidate was accepted or modified' }
$passed.Add('refuse-empty-candidate')
Assert-Rejected 'invalid-sbom-json' { param($dir) [IO.File]::WriteAllText((Join-Path $dir $sbomFile), '{') }
Assert-Rejected 'invalid-serial' { param($dir) $path=Join-Path $dir $sbomFile; $bom=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $bom.serialNumber='urn:uuid:pao-invalid'; [IO.File]::WriteAllText($path, ($bom | ConvertTo-Json -Depth 12)) }
Assert-Rejected 'invalid-provenance-json' { param($dir) [IO.File]::WriteAllText((Join-Path $dir 'pao-provenance.intoto.json'), '{}') }
Assert-Rejected 'wrong-subject-hash' { param($dir) $path=Join-Path $dir 'pao-provenance.intoto.json'; $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $p.subject[0].digest.sha256='0'*64; [IO.File]::WriteAllText($path, ($p | ConvertTo-Json -Depth 16)) }
Assert-Rejected 'missing-subject' { param($dir) $path=Join-Path $dir 'pao-provenance.intoto.json'; $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $p.subject=@(); [IO.File]::WriteAllText($path, ($p | ConvertTo-Json -Depth 16)) }
Assert-Rejected 'duplicate-subject' { param($dir) $path=Join-Path $dir 'pao-provenance.intoto.json'; $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $p.subject=@($p.subject)+@($p.subject[0]); [IO.File]::WriteAllText($path, ($p | ConvertTo-Json -Depth 16)) }
Assert-Rejected 'uncovered-binary' { param($dir) $path=Join-Path $dir 'pao-provenance.intoto.json'; $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $p.subject=@($p.subject | Where-Object name -Like '*.cdx.json'); [IO.File]::WriteAllText($path, ($p | ConvertTo-Json -Depth 16)) }
Assert-Rejected 'duplicate-json-key' { param($dir) $path=Join-Path $dir $sbomFile; $json=Get-Content -LiteralPath $path -Raw; [IO.File]::WriteAllText($path, $json.Replace('"bomFormat": "CycloneDX"','"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"')) }
Assert-Rejected 'ambiguous-json-key' { param($dir) $path=Join-Path $dir $sbomFile; $json=Get-Content -LiteralPath $path -Raw; [IO.File]::WriteAllText($path, $json.Replace('"bomFormat": "CycloneDX"','"bomFormat": "CycloneDX", "BomFormat": "CycloneDX"')) }
Assert-Rejected 'array-instead-of-format' { param($dir) $path=Join-Path $dir $sbomFile; $bom=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $bom.bomFormat=@('CycloneDX'); [IO.File]::WriteAllText($path, ($bom | ConvertTo-Json -Depth 12)) }
Assert-Rejected 'array-instead-of-predicate-type' { param($dir) $path=Join-Path $dir 'pao-provenance.intoto.json'; $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $p.predicateType=@('https://slsa.dev/provenance/v1'); [IO.File]::WriteAllText($path, ($p | ConvertTo-Json -Depth 16)) }
Assert-Rejected 'oversized-metadata' { param($dir) [IO.File]::WriteAllText((Join-Path $dir $sbomFile), (' ' * (16MB + 1))) }
Assert-Rejected 'invalid-utf8-metadata' { param($dir) [IO.File]::WriteAllBytes((Join-Path $dir $sbomFile), [byte[]]@(123,255,125)) }
Assert-Rejected 'non-object-root' { param($dir) [IO.File]::WriteAllText((Join-Path $dir $sbomFile), '[]') }
Assert-Rejected 'missing-linux-package' { param($dir) [IO.File]::Delete((Join-Path (Get-PublicDirectory $dir) "pao-$version-linux-amd64.tar.gz")) }
Assert-Rejected 'extra-private-config' { param($dir) [IO.File]::WriteAllText((Join-Path $dir 'private-config.json'), '{}') }
Assert-Rejected 'wrong-sbom-version' { param($dir) $path=Join-Path $dir $sbomFile; $bom=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $bom.metadata.component.version='9.9.9'; [IO.File]::WriteAllText($path, ($bom | ConvertTo-Json -Depth 12)) }
foreach ($privateName in @('BUILD-METADATA.json','pao-provenance.intoto.json',$sbomFile)) {
    Assert-Rejected ('private-evidence-in-public-' + $privateName) { param($dir) [IO.File]::Copy((Join-Path $dir $privateName),(Join-Path (Get-PublicDirectory $dir) $privateName),$false) }
}
& (Join-Path $PSScriptRoot 'verify-public-release.ps1') -DistributionPath (Get-PublicDirectory $first) -Version $version -PackageVerifierPath $PackageVerifierPath | Out-Null
$passed.Add('public-verification-needs-no-private-evidence')
& (Join-Path $PSScriptRoot 'compare-public-builds.ps1') -FirstDistributionPath (Get-PublicDirectory $first) -SecondDistributionPath (Get-PublicDirectory $second) | Out-Null
$passed.Add('compare-identical-public-bytes')
[IO.File]::AppendAllText((Join-Path (Get-PublicDirectory $second) "pao-$version-windows-amd64.zip"), 'changed')
Update-Checksums $second
$refused = $false
try { & (Join-Path $PSScriptRoot 'compare-public-builds.ps1') -FirstDistributionPath (Get-PublicDirectory $first) -SecondDistributionPath (Get-PublicDirectory $second) | Out-Null } catch { $refused = $true }
if (-not $refused) { throw 'Different build bytes were accepted.' }
$passed.Add('compare-rejects-different-public-bytes')
[pscustomobject]@{Status='PASSED';Count=$passed.Count;Checks=$passed.ToArray();SyntheticRoot=$root} | ConvertTo-Json -Depth 4
