[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StatePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._/-]+/$')]
    [string]$PathPrefix
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $StatePath -ErrorAction Stop).Path
$manifestPath = Join-Path $root 'pao-state-manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 10
if ($manifest.api_version -ne 'pao.dev/prepared-state/v1alpha1') {
    throw "Unsupported prepared-state manifest: $manifestPath"
}
$entries = @(
    $manifest.files |
        Where-Object { $_.path.StartsWith($PathPrefix, [StringComparison]::Ordinal) } |
        Sort-Object path
)
if ($entries.Count -eq 0) {
    throw "No prepared-state files matched the exact prefix: $PathPrefix"
}

$canonical = [Text.StringBuilder]::new()
foreach ($entry in $entries) {
    if ($entry.path -notmatch '^[A-Za-z0-9._/+@=-]+$' -or $entry.sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Unsafe prepared-state manifest entry: $($entry.path)"
    }
    [void]$canonical.Append($entry.path).Append([char]0).Append($entry.sha256).Append("`n")
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($canonical.ToString())
$hash = [Security.Cryptography.SHA256]::HashData($bytes)

[pscustomobject]@{
    state_path      = $root
    adapter_id      = $manifest.adapter_id
    path_prefix     = $PathPrefix
    file_count      = $entries.Count
    subset_sha256   = [Convert]::ToHexString($hash).ToLowerInvariant()
    state_manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress
