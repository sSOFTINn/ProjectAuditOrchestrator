#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version,
    [Parameter(Mandatory)][datetime]$AsOf,
    [Parameter(Mandatory)][string]$GoPath,
    [switch]$AllowDirty
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$output = [IO.Path]::GetFullPath($OutputPath)
if ($output.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Build output must be outside the source tree.' }
if (Test-Path -LiteralPath $output) { throw 'Use a new output directory; existing candidates are never overwritten.' }
$ancestor = Split-Path -Parent $output
while ($ancestor) {
    if (Test-Path -LiteralPath $ancestor) {
        if (((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked output ancestor is not allowed.' }
    }
    $parent = Split-Path -Parent $ancestor
    if ($parent -eq $ancestor) { break }; $ancestor = $parent
}
if ($output.StartsWith('\\') -or $output.StartsWith('//')) { throw 'Use a local staging directory.' }
$go = (Get-Command $GoPath -CommandType Application -ErrorAction Stop).Source
function Get-SourceIdentity {
    $names = @(& git -C $root -c core.quotepath=false ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate source files.' }
    $uniqueNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $names) { [void]$uniqueNames.Add($name) }
    $sortedNames = [string[]]@($uniqueNames)
    [Array]::Sort($sortedNames, [StringComparer]::Ordinal)
    $lines = foreach ($name in $sortedNames) {
        $path = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { "deleted  $name"; continue }
        $entry = Get-Item -LiteralPath $path -Force
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked source file is not allowed.' }
        '{0}  {1}' -f (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(), $name.Replace('\','/')
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}
Push-Location $root
$envNames = @('GOTOOLCHAIN','GOPROXY','GOSUMDB','GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOFLAGS','GOWORK','GOEXPERIMENT')
$savedEnv = @{}
foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    $env:GOTOOLCHAIN = 'local'; $env:GOPROXY = 'off'; $env:GOSUMDB = 'off'; $env:CGO_ENABLED = '0'; $env:GOFLAGS = ''; $env:GOWORK = 'off'; $env:GOAMD64 = 'v1'; $env:GOEXPERIMENT = ''
    $env:GOOS = ''; $env:GOARCH = ''
    $revision = (& git rev-parse --verify 'HEAD^{commit}').Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -cnotmatch '^[0-9a-f]{40}$') { throw 'A source commit is required.' }
    $dirty = @(& git status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read source status.' }
    if ($dirty.Count -and (-not $AllowDirty -or $Version -notmatch '-')) { throw 'Modified sources require -AllowDirty and a prerelease version.' }
    if ($Version -notmatch '-') {
        $mainMatches = $false
        foreach ($mainRef in @('refs/heads/main','refs/remotes/origin/main')) {
            $mainCommit = & git show-ref --verify --hash $mainRef 2>$null
            if ($LASTEXITCODE -eq 0 -and $mainCommit -ceq $revision) { $mainMatches = $true }
        }
        if (-not $mainMatches) { throw 'A stable release requires the selected clean main commit; fetch/approve it before building.' }
    }
    $state = if ($dirty.Count) { 'modified' } else { 'clean' }
    $sourceDigest = Get-SourceIdentity
    $goVersion = (& $go env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -cne 'go1.27.1') { throw 'The exact Go 1.27.1 reference toolchain is required; no download is attempted.' }
    $goRoot = (& $go env GOROOT).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the Go license.' }
    [IO.Directory]::CreateDirectory($output) | Out-Null
    $dist = Join-Path $output 'dist'; $work = Join-Path $output 'work'; $evidence = Join-Path $output 'evidence'
    [IO.Directory]::CreateDirectory($dist) | Out-Null
    [IO.Directory]::CreateDirectory($work) | Out-Null
    [IO.Directory]::CreateDirectory($evidence) | Out-Null
    $env:GOOS='linux'; $env:GOARCH='amd64'
    $sandbox = Join-Path $work 'pao-sandbox-linux-amd64'
    & $go build -trimpath -buildvcs=false -o $sandbox ./cmd/pao-sandbox
    if ($LASTEXITCODE -ne 0) { throw 'PAO sandbox supervisor build failed.' }
    $sandboxHash = (Get-FileHash -LiteralPath $sandbox -Algorithm SHA256).Hash.ToLowerInvariant()
    $env:GOOS=''; $env:GOARCH=''
    $metadata = [ordered]@{ version=$Version; revision=$revision; source_state=$state; source_tree_sha256=$sourceDigest; sandbox_sha256=$sandboxHash; go_version=$goVersion; as_of=$AsOf.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); pao_sha256=[ordered]@{}; archives_sha256=[ordered]@{} }
    $helper = Join-Path $work $(if ($IsWindows) { 'package-verifier.exe' } else { 'package-verifier' })
    & $go build -trimpath -buildvcs=false -o $helper ./scripts/release/package
    if ($LASTEXITCODE -ne 0) { throw 'Package verifier build failed.' }
    $ids = @('gitleaks','grype','opengrep','osv-scanner','reuse','sbomqs','scancode','syft','trivy','zizmor')
    foreach ($platform in @('windows','linux')) {
        $stage = Join-Path $work $platform
        [IO.Directory]::CreateDirectory($stage) | Out-Null
        $env:GOOS = $platform; $env:GOARCH = 'amd64'
        $binary = if ($platform -eq 'windows') { 'pao.exe' } else { 'pao' }
        $prefix = 'github.com/sSOFTINn/ProjectAuditOrchestrator/internal/buildinfo'
        & $go build -trimpath -buildvcs=false -ldflags "-X $prefix.Version=$Version -X $prefix.Revision=$revision -X $prefix.SourceState=$state -X $prefix.SourceTreeSHA256=sha256:$sourceDigest -X $prefix.SandboxSHA256=sha256:$sandboxHash" -o (Join-Path $stage $binary) ./cmd/pao
        if ($LASTEXITCODE -ne 0) { throw "$platform build failed." }
        $metadata.pao_sha256[$platform] = (Get-FileHash -LiteralPath (Join-Path $stage $binary) -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::Copy($sandbox, (Join-Path $stage 'pao-sandbox-linux-amd64'), $false)
        $inputs = [ordered]@{
            'audit.json'='tools/public-package/templates/audit.json'
            'toolchain.catalog.json'='tools/public-package/templates/toolchain.catalog.json'
            'docker-provider.json'='tools/public-package/templates/docker-provider.json'
            'START_HERE.uk.md'='docs/public-start.uk.md'
            'LICENSE'='LICENSE'; 'NOTICE'='NOTICE'
        }
        foreach ($id in $ids) { $inputs["adapters/$id/manifest.json"] = "adapters/$id/manifest.json" }
        foreach ($name in $inputs.Keys) {
            $source = Join-Path $root $inputs[$name]
            $entry = Get-Item -LiteralPath $source -Force
            if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Invalid package input: $name" }
            $destination = Join-Path $stage $name
            [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
            if ($name -ceq 'START_HERE.uk.md') {
                $guide = [IO.File]::ReadAllText($source).Replace('@PAO_VERSION@', $Version).Replace('@PAO_TAG@', "v$Version").Replace('@PAO_REVISION@', $revision)
                if ($guide -cmatch '@PAO_[A-Z_]+@') { throw 'The public guide has an unresolved package token.' }
                [IO.File]::WriteAllText($destination, $guide, [Text.UTF8Encoding]::new($false))
            } else {
                [IO.File]::Copy($source, $destination, $false)
            }
        }
        [IO.Directory]::CreateDirectory((Join-Path $stage 'licenses')) | Out-Null
        [IO.File]::Copy((Join-Path $goRoot 'LICENSE'), (Join-Path $stage 'licenses/GO-LICENSE.txt'), $false)
        $publicVersion = [ordered]@{version=$Version; platform=$platform; architecture='amd64'} | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $stage 'VERSION.json'), $publicVersion + "`n", [Text.UTF8Encoding]::new($false))
    }
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'BUILD-METADATA.json') -Encoding utf8NoBOM
    foreach ($platform in @('windows','linux')) {
        $stage = Join-Path $work $platform
        $extension = if ($platform -eq 'windows') { 'zip' } else { 'tar.gz' }
        & $helper -mode pack -stage $stage -path (Join-Path $dist "pao-$Version-$platform-amd64.$extension") -platform $platform -version $Version -metadata (Join-Path $evidence 'BUILD-METADATA.json')
        if ($LASTEXITCODE -ne 0) { throw "$platform package composition failed." }
        $metadata.archives_sha256[$platform] = (Get-FileHash -LiteralPath (Join-Path $dist "pao-$Version-$platform-amd64.$extension") -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'BUILD-METADATA.json') -Encoding utf8NoBOM
    $env:GOOS = ''; $env:GOARCH = ''
    if ((Get-SourceIdentity) -cne $sourceDigest) { throw 'Source changed during build; candidate is incomplete. Build again in a new directory.' }
    $nativeBinary = if ($IsWindows) { Join-Path $work 'windows/pao.exe' } else { Join-Path $work 'linux/pao' }
    $actualVersion = (& $nativeBinary version).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -cne $Version) { throw 'Built binary version differs from the package version.' }
    $doctor = & $nativeBinary doctor | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $doctor.version -cne $Version -or $doctor.revision -cne $revision -or $doctor.source_state -cne $state) { throw 'Built binary identity mismatch.' }
    & (Join-Path $PSScriptRoot 'generate-release-metadata.ps1') -DistributionPath $dist -EvidencePath $evidence -Version $Version -AsOf $AsOf -GoPath $go
    & (Join-Path $PSScriptRoot 'verify-release.ps1') -DistributionPath $dist -EvidencePath $evidence -PackageVerifierPath $helper
} finally {
    foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) }
    Pop-Location
}
