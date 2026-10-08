#Requires -Version 7.2
# Verify the public payload without requiring or publishing internal evidence.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DistributionPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version,
    [Parameter(Mandatory)][string]$PackageVerifierPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$dist = [IO.Path]::GetFullPath($DistributionPath)
& (Join-Path $PSScriptRoot '../../tools/local-package/Verify-LocalPackage.ps1') -PackagePath $dist | Out-Null
$required = @("pao-$Version-windows-amd64.zip", "pao-$Version-linux-amd64.tar.gz", 'SHA256SUMS.txt')
$files = @(Get-ChildItem -LiteralPath $dist -Force)
if ($files.Count -ne $required.Count -or @($files | Where-Object { $_.PSIsContainer -or $_.Name -cnotin $required }).Count) { throw 'Public payload must contain only the two archives and their SHA-256 manifest.' }
foreach ($platform in @('windows','linux')) {
    $extension = if ($platform -eq 'windows') { 'zip' } else { 'tar.gz' }
    & $PackageVerifierPath -mode verify -path (Join-Path $dist "pao-$Version-$platform-amd64.$extension") -platform $platform -version $Version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$platform public package validation failed." }
}
[pscustomobject]@{status='PUBLIC_PAYLOAD_VERIFIED';version=$Version;private_evidence_excluded=$true;signature_verified=$false;release_approved=$false} | ConvertTo-Json -Compress
