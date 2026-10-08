#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DistributionPath,

    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [Parameter(Mandatory)]
    [string]$Version,

    [Parameter(Mandatory)]
    [datetime]$AsOf,

    [string]$GoPath = 'go'
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'Version must be a safe SemVer value without a leading v.'
}
$dist = [IO.Path]::GetFullPath($DistributionPath)
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if ($dist -eq $evidence -or $dist.StartsWith($evidence + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $evidence.StartsWith($dist + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Public distribution and private evidence must be separate non-overlapping directories.' }
foreach ($directory in @($dist, $evidence)) {
if ($directory.StartsWith('\\') -or $directory.StartsWith('//')) { throw 'Use local candidate directories.' }
$ancestor = $directory
while ($ancestor) {
    $entry = Get-Item -LiteralPath $ancestor -Force
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse paths are not allowed.' }
    $parent = [IO.Path]::GetDirectoryName($ancestor)
    if ($parent -eq $ancestor) { break }
    $ancestor = $parent
}
}
$artifacts = @(Get-ChildItem -LiteralPath $dist -Force)
$privateArtifacts = @(Get-ChildItem -LiteralPath $evidence -Force)
if (@($artifacts + $privateArtifacts) | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Linked release artifacts are not allowed.' }
if (@($artifacts + $privateArtifacts) | Where-Object PSIsContainer) {
    throw 'Distribution directory must not contain subdirectories.'
}
$required = @("pao-$Version-windows-amd64.zip", "pao-$Version-linux-amd64.tar.gz")
if ($artifacts.Count -ne $required.Count -or @($artifacts | Where-Object { $_.Name -cnotin $required }).Count) { throw 'Exactly the two versioned public archives are required; no other input is allowed.' }
if ($privateArtifacts.Count -ne 1 -or $privateArtifacts[0].Name -cne 'BUILD-METADATA.json') { throw 'Private evidence must initially contain only BUILD-METADATA.json; existing evidence is never overwritten.' }
$created = $AsOf.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$goVersion = (& $GoPath env GOVERSION).Trim()
if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go[0-9]+\.[0-9]+\.[0-9]+$') { throw 'A usable local Go toolchain is required.' }
$build = Get-Content -LiteralPath (Join-Path $evidence 'BUILD-METADATA.json') -Raw | ConvertFrom-Json
if ($build.version -cne $Version -or $build.go_version -cne $goVersion -or ([datetime]$build.as_of).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') -cne $created -or $build.revision -cnotmatch '^[0-9a-f]{40}$' -or $build.source_tree_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $build.source_state -cnotin @('clean','modified')) { throw 'Build metadata differs from the requested release identity.' }
foreach ($platform in @('windows','linux')) {
    $extension = if ($platform -eq 'windows') { 'zip' } else { 'tar.gz' }
    $archiveHash = (Get-FileHash -LiteralPath (Join-Path $dist "pao-$Version-$platform-amd64.$extension") -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($build.pao_sha256.$platform -cnotmatch '^[0-9a-f]{64}$' -or $build.archives_sha256.$platform -cne $archiveHash) { throw 'Build metadata does not bind the exact public archive bytes.' }
}

# RFC 4122 UUIDv5: DNS namespace bytes in network order, followed by a stable
# name bound to version, time and artifact contents. No private path is included.
$identities = @(@($artifacts + $privateArtifacts) | Sort-Object Name | ForEach-Object {
    $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
})
$namespace = [Convert]::FromHexString('6ba7b8109dad11d180b400c04fd430c8')
$name = [Text.Encoding]::UTF8.GetBytes("pao.dev/release/$Version/$created/" + ($identities -join ';'))
$uuidBytes = [Security.Cryptography.SHA1]::HashData([byte[]]($namespace + $name))
$uuidBytes[6] = ($uuidBytes[6] -band 15) -bor 80
$uuidBytes[8] = ($uuidBytes[8] -band 63) -bor 128
$uuidHex = [Convert]::ToHexString($uuidBytes[0..15]).ToLowerInvariant()
$serial = 'urn:uuid:{0}-{1}-{2}-{3}-{4}' -f $uuidHex.Substring(0,8), $uuidHex.Substring(8,4), $uuidHex.Substring(12,4), $uuidHex.Substring(16,4), $uuidHex.Substring(20,12)

$components = @(
    [ordered]@{ type = 'application'; name = 'project-audit-orchestrator'; version = $Version; licenses = @(@{ license = @{ id = 'Apache-2.0' } }) },
    [ordered]@{ type = 'framework'; name = 'go'; version = $goVersion }
)
$sbom = [ordered]@{
    bomFormat = 'CycloneDX'
    specVersion = '1.5'
    serialNumber = $serial
    version = 1
    metadata = [ordered]@{
        timestamp = $created
        component = $components[0]
    }
    components = $components
}
$sbomPath = Join-Path $evidence "pao-$Version.cdx.json"
$sbom | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $sbomPath -Encoding utf8NoBOM

$subjects = @()
Get-ChildItem -LiteralPath @($dist,$evidence) -File -Force | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Name -ne 'pao-provenance.intoto.json' } | Sort-Object Name | ForEach-Object {
    $subjects += [ordered]@{ name = $_.Name; digest = [ordered]@{ sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } }
}
$builderID = 'https://pao.dev/release/local-metadata-generator/v1'
$runMetadata = [ordered]@{ startedOn = $created; finishedOn = $created }
if ($env:GITHUB_ACTIONS -eq 'true' -and $env:GITHUB_REPOSITORY -ceq 'sSOFTINn/ProjectAuditOrchestrator' -and $env:GITHUB_RUN_ID -match '^[0-9]+$') {
    $builderID = 'https://github.com/sSOFTINn/ProjectAuditOrchestrator/.github/workflows/release.yml'
    $runMetadata.invocationId = $env:GITHUB_RUN_ID
}
$provenance = [ordered]@{
    '_type' = 'https://in-toto.io/Statement/v1'
    subject = $subjects
    predicateType = 'https://slsa.dev/provenance/v1'
    predicate = [ordered]@{
        buildDefinition = [ordered]@{
            buildType = 'https://pao.dev/release/v1'
            externalParameters = [ordered]@{ version = $Version }
            internalParameters = [ordered]@{ go_version = $goVersion; source_state = $build.source_state; source_tree_sha256 = $build.source_tree_sha256 }
            resolvedDependencies = @([ordered]@{ uri = 'git+https://github.com/sSOFTINn/ProjectAuditOrchestrator'; digest = [ordered]@{ gitCommit = $build.revision } })
        }
        runDetails = [ordered]@{
            builder = [ordered]@{ id = $builderID }
            metadata = $runMetadata
        }
    }
}
$provenancePath = Join-Path $evidence 'pao-provenance.intoto.json'
$provenance | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $provenancePath -Encoding utf8NoBOM

foreach ($directory in @($dist,$evidence)) {
$checksumLines = Get-ChildItem -LiteralPath $directory -File -Force | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
}
[IO.File]::WriteAllText((Join-Path $directory 'SHA256SUMS.txt'), ($checksumLines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
}
