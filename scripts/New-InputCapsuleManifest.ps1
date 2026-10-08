[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$AdapterID,

    [Parameter(Mandatory)]
    [ValidateSet('rule-pack', 'license-data', 'database', 'trusted-config')]
    [string]$Kind
)

$ErrorActionPreference = 'Stop'
$manifestName = 'pao-input-manifest.json'
$root = (Resolve-Path -LiteralPath $InputPath -ErrorAction Stop).Path

if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Input capsule is not a directory: $InputPath"
}
if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Input capsule root must not be a reparse point: $root"
}
$reparsePoint = Get-ChildItem -LiteralPath $root -Force -Recurse |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
    Select-Object -First 1
if ($null -ne $reparsePoint) {
    throw "Input capsule must not contain reparse points: $($reparsePoint.FullName)"
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
    throw "Input capsule has no files: $root"
}

$manifest = [ordered]@{
    api_version = 'pao.dev/input-capsule/v1alpha1'
    adapter_id  = $AdapterID
    kind        = $Kind
    files       = $entries
}
$outputPath = Join-Path $root $manifestName
$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($outputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    input_path      = $root
    manifest_path   = $outputPath
    adapter_id      = $AdapterID
    kind            = $Kind
    file_count      = $entries.Count
    manifest_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
