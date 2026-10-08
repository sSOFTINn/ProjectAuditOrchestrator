[CmdletBinding()]
param(
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Find-DockerCli {
    $command = Get-Command -Name 'docker.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return [string]$command.Source
    }
    $standardPath = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $standardPath -PathType Leaf) {
        return $standardPath
    }
    return $null
}

function Get-OptionalFeatureState {
    param([Parameter(Mandatory)][string]$Name)
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        return [string]$feature.State
    }
    catch {
        return 'UNKNOWN_REQUIRES_ELEVATION_OR_WINDOWS_FEATURE_ACCESS'
    }
}

$dockerPath = Find-DockerCli
$dockerCli = $null -ne $dockerPath
$dockerEngine = $false
if ($dockerCli) {
    & $dockerPath version --format '{{.Server.Version}}' *> $null
    $dockerEngine = $LASTEXITCODE -eq 0
}
$wslCli = Test-CommandAvailable -Name 'wsl.exe'
$wslState = if ($wslCli) {
    $status = & wsl.exe --status 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { 'AVAILABLE' } else { 'NOT_READY' }
}
else {
    'NOT_INSTALLED'
}

$requirements = @(
    [pscustomobject]@{ id = 'docker-desktop-engine'; ready = $dockerEngine; detail = 'Docker Desktop Linux engine is present, but presence is not a provider approval.' }
    [pscustomobject]@{ id = 'container-vm-provider-review'; ready = $false; detail = 'Requires a reviewed immutable runtime and proof bundle before production scanner execution.' }
    [pscustomobject]@{ id = 'wsl2-runtime'; ready = ($wslState -eq 'AVAILABLE'); detail = 'WSL2 is a common Windows prerequisite for Docker Desktop, but it is not itself a PAO execution provider.' }
    [pscustomobject]@{ id = 'repository-read-only'; ready = $false; detail = 'Requires provider-specific bind-mount proof before execution.' }
    [pscustomobject]@{ id = 'temporary-write-only'; ready = $false; detail = 'Requires provider-specific scratch-storage proof before execution.' }
    [pscustomobject]@{ id = 'network-denied'; ready = $false; detail = 'Requires provider-specific network isolation proof before execution.' }
    [pscustomobject]@{ id = 'resource-and-process-limits'; ready = $false; detail = 'Requires provider-specific CPU, memory, timeout and process-tree proof before execution.' }
    [pscustomobject]@{ id = 'clean-runtime'; ready = $false; detail = 'Requires an approved immutable image/runtime identity before execution.' }
)

$result = [ordered]@{
    status = if (($requirements | Where-Object { -not $_.ready }).Count -eq 0) { 'READY_FOR_REVIEW' } else { 'POLICY_BLOCKED' }
    note = 'This is a non-mutating readiness check. READY_FOR_REVIEW is not authorization to launch scanners.'
    observed = [ordered]@{
        docker_cli = $dockerCli
		docker_engine = $dockerEngine
		docker_path = $dockerPath
        wsl_cli = $wslCli
        wsl_runtime = $wslState
        hyper_v = Get-OptionalFeatureState -Name 'Microsoft-Hyper-V-All'
        virtual_machine_platform = Get-OptionalFeatureState -Name 'VirtualMachinePlatform'
        windows_subsystem_for_linux = Get-OptionalFeatureState -Name 'Microsoft-Windows-Subsystem-Linux'
    }
    requirements = $requirements
}

if ($AsJson) {
    $result | ConvertTo-Json -Depth 5
}
else {
    [pscustomobject]$result
}
