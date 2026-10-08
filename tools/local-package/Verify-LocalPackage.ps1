#Requires -Version 7.2
# Read-only integrity check. Never invokes a packaged executable or script.
[CmdletBinding()]
param(
    [string]$PackagePath = $PSScriptRoot,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedChecksumsSHA256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($PackagePath)
if ($root.StartsWith('\\') -or $root.StartsWith('//')) { throw 'Use a local package directory.' }
# Check every existing ancestor without resolving through a junction/symlink.
$ancestor = $root
while ($ancestor) {
    $item = Get-Item -LiteralPath $ancestor -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse paths are not allowed.' }
    $parent = [IO.Path]::GetDirectoryName($ancestor)
    if ($parent -eq $ancestor) { break }
    $ancestor = $parent
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Package directory is missing.' }
$sums = Join-Path $root 'SHA256SUMS.txt'
$info = Get-Item -LiteralPath $sums -Force
if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $info.Length -gt 65536 -or $info.Length -eq 0) { throw 'Invalid checksum list.' }
$stream = [IO.File]::Open($sums,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
    $buffer = [byte[]]::new(65537)
    $length = 0
    while ($length -lt $buffer.Length) {
        $read = $stream.Read($buffer,$length,$buffer.Length-$length)
        if ($read -eq 0) { break }
        $length += $read
    }
    if ($length -gt 65536 -or $length -eq 0) { throw 'Checksum list exceeds the limit or is empty.' }
    $bytes = [byte[]]::new($length)
    [Array]::Copy($buffer,$bytes,$length)
} finally { $stream.Dispose() }
$listDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
if ($ExpectedChecksumsSHA256 -and $listDigest -cne $ExpectedChecksumsSHA256) { throw 'Checksum list does not match the separately recorded hash.' }
$utf8 = [Text.UTF8Encoding]::new($false,$true)
$lines = $utf8.GetString($bytes).TrimEnd("`r","`n").Split("`n")
if ($lines.Count -gt 128) { throw 'Too many checksum entries.' }
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($rawLine in $lines) {
    $line = $rawLine.TrimEnd("`r")
    if ($line -cnotmatch '^([a-f0-9]{64})  ([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)$') { throw 'Malformed checksum entry.' }
    $hash, $name = $Matches[1], $Matches[2]
    if ($name -ieq 'SHA256SUMS.txt' -or $name.Length -gt 240) { throw 'Invalid checksum path.' }
    foreach ($part in $name.Split('/')) {
        if ($part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'Unsafe checksum path.' }
    }
    if (-not $expected.TryAdd($name,$hash)) { throw 'Duplicate checksum path.' }
}
$actual = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
$pending = [Collections.Generic.Stack[string]]::new()
$pending.Push($root)
$entries = 0
while ($pending.Count -gt 0) {
    $dir = $pending.Pop()
    foreach ($entry in ([IO.DirectoryInfo]::new($dir)).EnumerateFileSystemInfos()) {
        $entries++
        if ($entries -gt 512) { throw 'Package tree exceeds the limit.' }
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Package contains a reparse point.' }
        $relative = [IO.Path]::GetRelativePath($root,$entry.FullName).Replace('\','/')
        if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            if (-not @($expected.Keys | Where-Object { $_.StartsWith($relative+'/',[StringComparison]::Ordinal) }).Count) { throw 'Unexpected package directory.' }
            $pending.Push($entry.FullName)
        } elseif ($relative -cne 'SHA256SUMS.txt') {
            if (-not $expected.ContainsKey($relative) -or -not $actual.TryAdd($relative,$entry.FullName)) { throw 'Unexpected or ambiguous package file.' }
        }
    }
}
if ($actual.Count -ne $expected.Count) { throw 'A listed package file is missing.' }
foreach ($name in $expected.Keys) {
    $hash = (Get-FileHash -LiteralPath $actual[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $expected[$name]) { throw "Checksum mismatch: $name" }
}
[pscustomobject]@{
    Status='LOCAL_INTEGRITY_VERIFIED'
    Files=$actual.Count
    ChecksumsSHA256=$listDigest
    ReleaseApproved=$false
    ScannerReadinessChecked=$false
    SignatureVerified=$false
}
