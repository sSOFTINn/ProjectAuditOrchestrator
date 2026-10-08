[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AcceptDockerDesktopTerms
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WslRuntimeState {
    if ($null -eq (Get-Command -Name 'wsl.exe' -ErrorAction SilentlyContinue)) {
        return 'NOT_INSTALLED'
    }
    & wsl.exe --status *> $null
    if ($LASTEXITCODE -eq 0) { return 'AVAILABLE' }
    return 'NOT_READY'
}

if (-not $AcceptDockerDesktopTerms) {
    throw 'Refusing installation: rerun only after accepting Docker Desktop terms with -AcceptDockerDesktopTerms.'
}
if (-not (Test-IsAdministrator)) {
    throw 'Run this script from an elevated PowerShell session. It will not request or bypass elevation.'
}

$wslState = Get-WslRuntimeState
if ($wslState -ne 'AVAILABLE') {
    if ($PSCmdlet.ShouldProcess('Windows Subsystem for Linux', 'Install WSL runtime without a default Linux distribution')) {
        & wsl.exe --install --no-distribution
        if ($LASTEXITCODE -ne 0) {
            throw "WSL installation failed with exit code $LASTEXITCODE."
        }
    }
    [pscustomobject]@{
        status = 'REBOOT_REQUIRED'
        next_action = 'Restart Windows, then rerun this script to install Docker Desktop.'
        scanner_started = $false
        target_touched = $false
    }
    return
}

if ($null -eq (Get-Command -Name 'winget.exe' -ErrorAction SilentlyContinue)) {
    throw 'Winget is required for this reviewed installation path but is not available.'
}
if ($PSCmdlet.ShouldProcess('Docker Desktop', 'Install the exact package Docker.DockerDesktop from the winget source')) {
    & winget.exe install --exact --id Docker.DockerDesktop --source winget --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop installation failed with exit code $LASTEXITCODE."
    }
}
[pscustomobject]@{
    status = 'DOCKER_DESKTOP_INSTALLED_REVIEW_REQUIRED'
    next_action = 'Start Docker Desktop once, complete its visible onboarding, then run Test-ContainerVmReadiness.ps1 -AsJson.'
    scanner_started = $false
    target_touched = $false
}
