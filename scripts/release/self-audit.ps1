[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PaoPath,

    [Parameter(Mandatory)]
    [string]$TargetPath,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $TargetPath).Path
$output = [IO.Path]::GetFullPath($OutputPath)
$targetPrefix = $target.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($output.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Self-audit output must be outside the audited target directory.'
}

# A release self-audit must cover the exact Git source that is going to be
# released.  Do not hash local caches, build output or other ignored files:
# besides making the result non-reproducible, those files can make a clean
# source audit needlessly expensive.
$git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
$dirty = & $git.Source -C $target status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0) { throw 'Cannot read Git status for the self-audit target.' }
if ($dirty) { throw 'Self-audit requires a clean working tree and an immutable commit.' }
$commit = (& $git.Source -C $target rev-parse --verify 'HEAD^{commit}').Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Self-audit requires a resolvable immutable Git commit.' }

$outputDirectory = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$capsule = Join-Path $outputDirectory ("pao-self-audit-" + $commit)
if (Test-Path -LiteralPath $capsule) { throw "Self-audit source capsule already exists: $capsule" }
[System.IO.Directory]::CreateDirectory($capsule) | Out-Null
$archive = Join-Path $capsule 'source.zip'
& $git.Source -C $target archive --format=zip --output=$archive $commit
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw 'Cannot create the immutable self-audit source capsule.' }
Expand-Archive -LiteralPath $archive -DestinationPath $capsule -Force
Remove-Item -LiteralPath $archive -Force

$beforeJson = & $PaoPath inspect --target $capsule
if ($LASTEXITCODE -ne 0) { throw "PAO self-audit failed before comparison with exit code $LASTEXITCODE" }
$before = $beforeJson | ConvertFrom-Json
$afterJson = & $PaoPath inspect --target $capsule
if ($LASTEXITCODE -ne 0) { throw "PAO self-audit failed after comparison with exit code $LASTEXITCODE" }
$after = $afterJson | ConvertFrom-Json
if (-not $after.snapshot.target_id -or -not $after.snapshot.manifest_hash) { throw 'PAO self-audit did not return a target snapshot.' }
if ($before.snapshot.manifest_hash -ne $after.snapshot.manifest_hash) { throw 'PAO self-audit changed the target manifest.' }

$afterJson | Set-Content -LiteralPath $output -Encoding utf8NoBOM
