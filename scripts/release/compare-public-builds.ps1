#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FirstDistributionPath, [Parameter(Mandatory)][string]$SecondDistributionPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$first = [IO.Path]::GetFullPath($FirstDistributionPath)
$second = [IO.Path]::GetFullPath($SecondDistributionPath)
if ($first -eq $second) { throw 'Reproducibility requires two distinct build outputs.' }
foreach ($directory in @($first,$second)) {
    & (Join-Path $PSScriptRoot '../../tools/local-package/Verify-LocalPackage.ps1') -PackagePath $directory | Out-Null
}
$names = @(Get-ChildItem -LiteralPath $first -Force | ForEach-Object Name | Sort-Object -CaseSensitive)
$secondNames = @(Get-ChildItem -LiteralPath $second -Force | ForEach-Object Name | Sort-Object -CaseSensitive)
if ($names.Count -ne 3 -or (Compare-Object $names $secondNames -CaseSensitive)) { throw 'Public build file sets differ.' }
$windows = @($names | Where-Object { $_ -cmatch '^pao-([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-windows-amd64.zip$' })
if ($windows.Count -ne 1 -or $names -cnotcontains 'SHA256SUMS.txt') { throw 'Unexpected public file set.' }
$version = $windows[0].Substring(4, $windows[0].Length - 4 - '-windows-amd64.zip'.Length)
if ($names -cnotcontains "pao-$version-linux-amd64.tar.gz") { throw 'Missing matching Linux archive.' }
foreach ($name in $names) {
    if ((Get-FileHash -LiteralPath (Join-Path $first $name) -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath (Join-Path $second $name) -Algorithm SHA256).Hash) { throw "Build bytes differ: $name" }
}
[pscustomobject]@{status='IDENTICAL_PUBLIC_BYTES';files=$names;version=$version;independent_reproduction=$false;release_approved=$false} | ConvertTo-Json -Compress
