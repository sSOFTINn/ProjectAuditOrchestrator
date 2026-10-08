[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArchivePath,

    [string]$ChecksumsPath = (Join-Path $PSScriptRoot 'toolchain/go-1.27.1-checksums.txt')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
    throw "Go archive was not found: $ArchivePath"
}
if (-not (Test-Path -LiteralPath $ChecksumsPath -PathType Leaf)) {
    throw "Checksum pin was not found: $ChecksumsPath"
}

$archiveName = [IO.Path]::GetFileName($ArchivePath)
$expectedLine = Get-Content -LiteralPath $ChecksumsPath |
    Where-Object { $_ -match '^[0-9a-f]{64}\s{2}' -and $_ -like "*  $archiveName" } |
    Select-Object -First 1
if (-not $expectedLine) {
    throw "No checksum pin exists for archive: $archiveName"
}

$expected = ($expectedLine -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    throw "Go archive checksum mismatch for $archiveName. Expected $expected, got $actual."
}

[pscustomobject]@{
    archive = $archiveName
    sha256 = $actual
    status = 'VERIFIED'
} | ConvertTo-Json -Compress
