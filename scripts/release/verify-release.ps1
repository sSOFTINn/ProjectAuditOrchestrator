#Requires -Version 7.2
# Read-only envelope/integrity verification, not schema or signature validation.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DistributionPath, [Parameter(Mandatory)][string]$EvidencePath, [Parameter(Mandatory)][string]$PackageVerifierPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$dist = [IO.Path]::GetFullPath($DistributionPath)
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if ($dist -eq $evidence -or $dist.StartsWith($evidence + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $evidence.StartsWith($dist + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Public distribution and private evidence must not overlap.' }
& (Join-Path $PSScriptRoot '../../tools/local-package/Verify-LocalPackage.ps1') -PackagePath $dist | Out-Null
& (Join-Path $PSScriptRoot '../../tools/local-package/Verify-LocalPackage.ps1') -PackagePath $evidence | Out-Null
if (Get-ChildItem -LiteralPath @($dist,$evidence) -Directory -Force) { throw 'Release directories must not contain subdirectories.' }
$sboms = @(Get-ChildItem -LiteralPath $evidence -Filter '*.cdx.json' -File -Force)
if ($sboms.Count -ne 1) { throw 'Exactly one CycloneDX SBOM is required.' }

function Assert-UniqueJsonFields([System.Text.Json.JsonElement]$Element) {
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw 'Duplicate or ambiguous JSON property.' }
            Assert-UniqueJsonFields $property.Value
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-UniqueJsonFields $item }
    }
}
function Read-Metadata([string]$Path) {
    $reader = [IO.StreamReader]::new($Path, [Text.UTF8Encoding]::new($false,$true), $false)
    try {
        $buffer = [char[]]::new(16MB + 1)
        $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
        if ($count -eq 0 -or $count -gt 16MB) { throw 'Metadata is empty or exceeds the limit.' }
        $json = [string]::new($buffer, 0, $count)
    } finally { $reader.Dispose() }
    $document = [System.Text.Json.JsonDocument]::Parse($json)
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'Metadata root must be an object.' }
        Assert-UniqueJsonFields $document.RootElement
    } finally { $document.Dispose() }
    return ($json | ConvertFrom-Json -AsHashtable -Depth 64)
}
$bom = Read-Metadata $sboms[0].FullName
$build = Read-Metadata (Join-Path $evidence 'BUILD-METADATA.json')
if ($build.version -isnot [string] -or $build.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $build.revision -isnot [string] -or $build.revision -cnotmatch '^[0-9a-f]{40}$' -or $build.source_tree_sha256 -isnot [string] -or $build.source_tree_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $build.source_state -cnotin @('clean','modified')) { throw 'Invalid build metadata.' }
$version = $build.version
$required = @("pao-$version-windows-amd64.zip", "pao-$version-linux-amd64.tar.gz", 'SHA256SUMS.txt')
$actualNames = @(Get-ChildItem -LiteralPath $dist -File -Force | ForEach-Object Name)
if ($actualNames.Count -ne $required.Count -or @($actualNames | Where-Object { $_ -cnotin $required }).Count) { throw 'Public distribution requires exactly both platform archives and checksums; private evidence and extra files are forbidden.' }
$requiredEvidence = @("pao-$version.cdx.json", 'BUILD-METADATA.json', 'pao-provenance.intoto.json', 'SHA256SUMS.txt')
$actualEvidence = @(Get-ChildItem -LiteralPath $evidence -File -Force | ForEach-Object Name)
if ($actualEvidence.Count -ne $requiredEvidence.Count -or @($actualEvidence | Where-Object { $_ -cnotin $requiredEvidence }).Count) { throw 'Private evidence composition differs.' }
if ($bom.bomFormat -isnot [string] -or $bom.bomFormat -cne 'CycloneDX' -or
    $bom.specVersion -isnot [string] -or $bom.specVersion -cne '1.5' -or
    $bom.serialNumber -isnot [string] -or
    $bom.serialNumber -cnotmatch '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
    $bom.version -isnot [long] -or $bom.version -lt 1 -or
    $bom.components -isnot [array] -or $bom.components.Count -lt 1) {
    throw 'Invalid CycloneDX envelope.'
}
if ($bom.metadata.component.version -cne $version -or $bom.metadata.timestamp -cne $build.as_of -or $bom.components[0].version -cne $version -or $bom.components[1].version -cne $build.go_version) { throw 'SBOM/build identity mismatch.' }
$provenance = Read-Metadata (Join-Path $evidence 'pao-provenance.intoto.json')
if ($provenance._type -isnot [string] -or $provenance._type -cne 'https://in-toto.io/Statement/v1' -or
    $provenance.predicateType -isnot [string] -or $provenance.predicateType -cne 'https://slsa.dev/provenance/v1' -or
    $provenance.subject -isnot [array] -or $provenance.subject.Count -lt 1 -or
    $provenance.predicate -isnot [Collections.IDictionary]) {
    throw 'Invalid provenance envelope.'
}
if ($provenance.predicate.buildDefinition.externalParameters.version -cne $version -or $provenance.predicate.buildDefinition.internalParameters.go_version -cne $build.go_version -or $provenance.predicate.buildDefinition.internalParameters.source_state -cne $build.source_state -or $provenance.predicate.buildDefinition.internalParameters.source_tree_sha256 -cne $build.source_tree_sha256 -or $provenance.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit -cne $build.revision) { throw 'Provenance/build identity mismatch.' }
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($file in (Get-ChildItem -LiteralPath @($dist,$evidence) -File -Force | Where-Object { $_.Name -notin @('SHA256SUMS.txt','pao-provenance.intoto.json') })) {
    $expected.Add($file.Name, (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())
}
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($subject in $provenance.subject) {
    if ($subject -isnot [Collections.IDictionary] -or $subject.name -isnot [string] -or
        -not $expected.ContainsKey($subject.name) -or -not $seen.Add($subject.name) -or
        $subject.digest -isnot [Collections.IDictionary] -or $subject.digest.sha256 -isnot [string] -or
        $subject.digest.sha256 -cne $expected[$subject.name]) { throw 'Invalid or mismatched provenance subject.' }
}
if ($seen.Count -ne $expected.Count) { throw 'Provenance does not cover all release artifacts.' }
foreach ($platform in @('windows','linux')) {
    $extension = if ($platform -eq 'windows') { 'zip' } else { 'tar.gz' }
    & $PackageVerifierPath -mode verify -path (Join-Path $dist "pao-$version-$platform-amd64.$extension") -platform $platform -version $version -metadata (Join-Path $evidence 'BUILD-METADATA.json') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$platform package composition validation failed." }
}
[pscustomobject]@{
    distribution=$dist; evidence=$evidence; status='VERIFIED'; integrity_verified=$true; private_evidence_excluded=$true
    metadata_envelopes_verified=$true; provenance_subjects_verified=$true
    package_composition_verified=$true; version=$version; source_state=$build.source_state
    full_schema_validation=$false; signature_verified=$false; release_approved=$false
} | ConvertTo-Json -Compress
