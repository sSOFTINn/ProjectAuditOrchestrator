#Requires -Version 7.2
# Historical, exact-snapshot local repair; the caller must authorize both paths.
# No network or ACL/chmod changes; never run as a general database updater.
# Copy bytes into new Windows files; do not carry inaccessible Linux metadata over.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$DestinationPath
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This historical repair supports Windows only.' }
foreach ($paoPath in @($SourcePath, $DestinationPath)) {
    if ($paoPath -notmatch '^[A-Za-z]:\\[^:]+' -or $paoPath -ne [IO.Path]::GetFullPath($paoPath)) { throw 'Use clean absolute local paths.' }
}
$paoSource = $SourcePath.TrimEnd('\')
$paoDestination = $DestinationPath.TrimEnd('\')
if ($paoSource -eq $paoDestination -or $paoSource.StartsWith($paoDestination + '\', [StringComparison]::OrdinalIgnoreCase) -or $paoDestination.StartsWith($paoSource + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Source and destination must be separate.' }
$paoExpected = [ordered]@{
    'metadata.json' = '7972609e63c4e6b3d1c5bfc61bff788e6161999bf4eea7b34dfde76171894d17'
    'empty-probe/go.mod' = 'd178b39bcc4864e9a99dbe73a8680d6b5fa64046faefac0a35a8d6f5dcf9a8c3'
    'osv-scalibr/Go/all.zip' = 'a86d1a964d8cfff608ea12112ffe04011c477ceee072b12763eebc998d1521e4'
}
function Assert-PaoNoLinks([string]$Path) {
    $paoInspect = [IO.Path]::GetFullPath($Path)
    while ($paoInspect) {
        if (Test-Path -LiteralPath $paoInspect) {
            if ((Get-Item -LiteralPath $paoInspect -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path refused' }
        }
        $paoInspect = [IO.Path]::GetDirectoryName($paoInspect)
    }
}
Assert-PaoNoLinks $paoSource
Assert-PaoNoLinks $paoDestination
if (Test-Path -LiteralPath $paoDestination) { throw 'Destination exists; immutable copy will not be overwritten' }
# Visit directories only after checking they are ordinary directories.
$paoQueue = [Collections.Generic.Queue[string]]::new()
$paoQueue.Enqueue($paoSource)
$paoObserved = @()
while ($paoQueue.Count) {
    foreach ($paoEntry in Get-ChildItem -LiteralPath $paoQueue.Dequeue() -Force) {
        if ($paoEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Source link refused' }
        if ($paoEntry.PSIsContainer) { $paoQueue.Enqueue($paoEntry.FullName) }
        else { $paoObserved += $paoEntry.FullName.Substring($paoSource.Length + 1).Replace('\','/') }
    }
}
if ($paoObserved.Count -ne $paoExpected.Count) { throw 'Unexpected source file set' }
foreach ($paoRelative in $paoObserved) {
    if (-not $paoExpected.Contains($paoRelative)) { throw 'Undeclared source file' }
    if ((Get-FileHash -LiteralPath (Join-Path $paoSource $paoRelative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $paoExpected[$paoRelative]) { throw 'Source digest mismatch' }
}
New-Item -ItemType Directory -Path $paoDestination -ErrorAction Stop | Out-Null
foreach ($paoRelative in $paoExpected.Keys) {
    $paoInput = Join-Path $paoSource $paoRelative
    $paoOutput = Join-Path $paoDestination $paoRelative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($paoOutput)) | Out-Null
    $paoReader = [IO.File]::Open($paoInput, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $paoWriter = [IO.File]::Open($paoOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $paoReader.CopyTo($paoWriter); $paoWriter.Flush($true) } finally { $paoWriter.Dispose() }
    } finally { $paoReader.Dispose() }
    foreach ($paoVerifyPath in @($paoInput, $paoOutput)) {
        if ((Get-FileHash -LiteralPath $paoVerifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $paoExpected[$paoRelative]) { throw 'Copy integrity verification failed' }
    }
}
[ordered]@{ Source=$paoSource; Destination=$paoDestination; ByteIdentical=$true; SourceUnchanged=$true; MetadataAndApprovalAgePreserved=$true; Files=$paoExpected; RuntimeReadCheck='REQUIRED' } | ConvertTo-Json -Depth 5
