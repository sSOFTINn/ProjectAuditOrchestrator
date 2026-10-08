[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StatePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$AdapterID
)

$ErrorActionPreference = 'Stop'
$manifestName = 'pao-state-manifest.json'
$root = (Resolve-Path -LiteralPath $StatePath -ErrorAction Stop).Path

if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Prepared state is not a directory: $StatePath"
}
if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Prepared state root must not be a reparse point: $root"
}
$reparsePoint = Get-ChildItem -LiteralPath $root -Force -Recurse |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
    Select-Object -First 1
if ($null -ne $reparsePoint) {
    throw "Prepared state must not contain reparse points: $($reparsePoint.FullName)"
}

$entries = @(
    Get-ChildItem -LiteralPath $root -File -Force -Recurse |
        Where-Object { $_.Name -ne $manifestName } |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($root.Length).TrimStart([char]'\').Replace('\', '/')
            [ordered]@{
                path   = $relative
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
)

if ($entries.Count -eq 0) {
    throw "Prepared state has no files: $root"
}

$manifest = [ordered]@{
    api_version = 'pao.dev/prepared-state/v1alpha1'
    adapter_id  = $AdapterID
    files       = $entries
}
$outputPath = Join-Path $root $manifestName
$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($outputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    state_path     = $root
    manifest_path  = $outputPath
    adapter_id     = $AdapterID
    file_count     = $entries.Count
    manifest_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
