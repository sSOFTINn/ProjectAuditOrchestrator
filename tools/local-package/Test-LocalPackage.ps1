#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputBase)
$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot 'Verify-LocalPackage.ps1'
$testRoot = Join-Path ([IO.Path]::GetFullPath($OutputBase)) ('package-checks-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$passed = [Collections.Generic.List[string]]::new()
function New-Fixture([string]$Name) {
    $path = Join-Path $testRoot $Name
    [IO.Directory]::CreateDirectory((Join-Path $path 'nested')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $path 'nested/data.txt'), 'synthetic bytes')
    # Must never be executed by the verifier.
    [IO.File]::WriteAllText((Join-Path $path 'never-run.ps1'), 'throw "checker executed package code"')
    $lines = foreach ($name in @('nested/data.txt','never-run.ps1')) {
        '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $path $name)).Hash.ToLowerInvariant(), $name
    }
    [IO.File]::WriteAllLines((Join-Path $path 'SHA256SUMS.txt'), $lines)
    return $path
}
function Assert-Rejected([string]$Name, [scriptblock]$Mutation) {
    $path = New-Fixture $Name
    & $Mutation $path
    $rejected = $false
    try { & $checker -PackagePath $path | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted invalid fixture: $Name" }
    $passed.Add($Name)
}
if (-not (Test-Path -LiteralPath $checker -PathType Leaf)) { throw 'Checker not implemented yet' }
$good = New-Fixture 'valid'
$before = @(Get-ChildItem -LiteralPath $good -Recurse -File | Get-FileHash)
$result = & $checker -PackagePath $good
if ($result.Status -ne 'LOCAL_INTEGRITY_VERIFIED' -or $result.ReleaseApproved -ne $false -or $result.Files -ne 2) { throw 'Incorrect success boundary' }
$after = @(Get-ChildItem -LiteralPath $good -Recurse -File | Get-FileHash)
if (@(Compare-Object $before $after -Property Path,Hash).Count) { throw 'Checker modified fixture' }
$passed.Add('valid-read-only-no-execution')
Assert-Rejected 'tampered' { param($p) [IO.File]::WriteAllText((Join-Path $p 'nested/data.txt'), 'changed') }
Assert-Rejected 'missing' { param($p) [IO.File]::Move((Join-Path $p 'nested/data.txt'), (Join-Path $testRoot 'preserved-missing.txt')) }
Assert-Rejected 'extra-hidden' { param($p) [IO.File]::WriteAllText((Join-Path $p '.private.json'), 'SYNTHETIC_PRIVATE') }
Assert-Rejected 'duplicate' { param($p) $f=Join-Path $p 'SHA256SUMS.txt'; [IO.File]::AppendAllText($f, [IO.File]::ReadAllLines($f)[0]+"`n") }
Assert-Rejected 'case-alias' { param($p) $f=Join-Path $p 'SHA256SUMS.txt'; [IO.File]::AppendAllText($f, [IO.File]::ReadAllLines($f)[0].Replace('nested/data.txt','NESTED/DATA.TXT')+"`n") }
foreach ($name in @('../outside','/absolute','C:/absolute','nested/../data.txt','nested/data.txt:stream','nested./data.txt','SHA256SUMS.txt')) {
    $badName = $name
    Assert-Rejected ('unsafe-' + $passed.Count) { param($p) [IO.File]::WriteAllText((Join-Path $p 'SHA256SUMS.txt'), (('a'*64)+'  '+$badName+"`n")) }
}
Assert-Rejected 'malformed' { param($p) [IO.File]::WriteAllText((Join-Path $p 'SHA256SUMS.txt'), 'not a checksum') }
Assert-Rejected 'empty' { param($p) [IO.File]::WriteAllText((Join-Path $p 'SHA256SUMS.txt'), '') }
Assert-Rejected 'oversized-list' { param($p) [IO.File]::WriteAllText((Join-Path $p 'SHA256SUMS.txt'), ('x'*65537)) }
$wrongHashRejected = $false
try { & $checker -PackagePath $good -ExpectedChecksumsSHA256 ('0'*64) | Out-Null } catch { $wrongHashRejected=$true }
if (-not $wrongHashRejected) { throw 'External checksum pin ignored' }
$passed.Add('external-checksum-pin')
if ($IsWindows) {
    # A junction only inside this unique synthetic tree; never traversed or deleted.
    $junctionFixture = New-Fixture 'junction'
    New-Item -ItemType Junction -Path (Join-Path $junctionFixture 'linked') -Target (Join-Path $good 'nested') | Out-Null
    $rejected=$false
    try { & $checker -PackagePath $junctionFixture | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Junction was accepted' }
    $passed.Add('junction')
    $rejected=$false
    try { & $checker -PackagePath (Join-Path $junctionFixture 'linked') | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Root junction was accepted' }
    $passed.Add('root-junction')
}
[pscustomobject]@{Status='PASSED';Count=$passed.Count;Checks=$passed.ToArray();SyntheticRoot=$testRoot} | ConvertTo-Json -Depth 4
