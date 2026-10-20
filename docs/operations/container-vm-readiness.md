# Readiness for a `container-vm` execution provider

PAO deliberately cannot run an adapter merely because a local `docker` command exists. On Windows and Linux,
the execution provider must be separately reviewed to prove all controls required by an adapter
manifest: VM-backed isolation, read-only target access, temporary-write-only storage, denied network,
sanitized environment, process-tree control, CPU/memory limits and a clean runtime identity.

This is a preparation guide, not authorization to install software or audit a target.

## Safe diagnostic

On Windows, run in PowerShell 7 from the repository root:

```powershell
.\scripts\Test-ContainerVmReadiness.ps1 -AsJson
```

The script only reads command/Windows-feature status. It neither enables Windows features nor starts
Docker, WSL, a VM, a scanner or a target process. `POLICY_BLOCKED` is the correct result until every
control has provider-specific proof.

## Authorized installation path

After the user has explicitly confirmed their right to use Docker Desktop and approved a possible
restart, open an **elevated** PowerShell 7 session in the repository root and run:

```powershell
.\scripts\Install-ContainerVmPrerequisites.ps1 -AcceptDockerDesktopTerms
```

The script refuses to run without both elevation and this explicit terms parameter. If WSL needs to
be enabled, it installs no Linux distribution, stops with `REBOOT_REQUIRED` and does not install
Docker in the same step. After the restart, rerun the command. It never starts a scanner or touches
an audit target.

## Required evidence before any launch

1. The user explicitly authorizes installation/configuration of the chosen provider.
2. A provider review identifies its immutable image/runtime digest and proves it is VM-backed for the
   operating mode in use. Docker Desktop on Windows can be a candidate, but the CLI's existence is
   not enough evidence.
3. A non-production synthetic target verifies read-only mounting, a distinct writable scratch area,
   `network=none`, environment allowlisting, CPU/memory limits, timeout/cancellation and no child
   process escape.
4. The exact scanner binary, database, rule pack and configuration are imported locally and recorded
   with their digests. No install, update or download may happen during an audit.
5. A maintainer reviews the evidence and changes the host configuration from blocked to verified.

Only then may a provider be connected to `HostRunner`. Until then, `pao plan --dry-run`, `inspect` and
`audit --no-adapters` remain the supported non-executing commands.

## Local Docker Desktop acceptance test

After Docker Desktop reports its engine as running and the owner approves this
synthetic acceptance run, use a trusted checkout of the selected PAO revision
and an already installed, verified Go 1.27.1 toolchain. Run from that checkout's
root with ordinary user privileges. On Linux the current user and group must
both be non-root; the test uses the current numeric UID:GID so private inputs
can retain their `0700`/`0600` permissions.

These opt-in commands build a static Go fixture and a unique local `FROM scratch`
image. They create synthetic files and several bounded containers, then remove
only their owned containers and uniquely named image. They pull no image and
do not start a third-party scanner or inspect an audit target. Replace the
example Go and Docker paths with verified absolute regular-file paths; do not
substitute a symlink or an ambient remote Docker context.

Windows, PowerShell 7:

```powershell
$paoGo = 'D:\tools\go1.27.1\bin\go.exe'
$paoDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$paoEnvironmentNames = @('PAO_DOCKER_INTEGRATION','PAO_GO_PATH','PAO_DOCKER_PATH','GOTOOLCHAIN','GOPROXY','GOSUMDB')
$paoSavedEnvironment = @{}
foreach ($paoName in $paoEnvironmentNames) {
    $paoSavedEnvironment[$paoName] = [Environment]::GetEnvironmentVariable($paoName)
}
try {
    $env:GOTOOLCHAIN = 'local'
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $paoGoVersion = & $paoGo env GOVERSION
    if ($LASTEXITCODE -ne 0 -or $paoGoVersion -cne 'go1.27.1') { throw 'Approved Go 1.27.1 is required.' }
    $env:PAO_DOCKER_INTEGRATION = '1'
    $env:PAO_GO_PATH = $paoGo
    $env:PAO_DOCKER_PATH = $paoDocker
    & $paoGo test ./internal/runner -run '^TestDockerHostSyntheticIsolationAcceptance$' -count=1 -v
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic Docker Desktop acceptance failed.' }
} finally {
    foreach ($paoName in $paoEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($paoName, $paoSavedEnvironment[$paoName])
    }
}
```

Ubuntu 24.04 AMD64, `sh`, from the same selected source revision:

```sh
(
    set -eu
    pao_go='/absolute/path/to/go1.27.1/bin/go'
    pao_docker='/absolute/path/to/regular/docker'
    export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
    test "$(id -u)" -ne 0
    test "$(id -g)" -ne 0
    test "$("$pao_go" env GOVERSION)" = 'go1.27.1'
    export PAO_DOCKER_INTEGRATION=1 PAO_GO_PATH="$pao_go" PAO_DOCKER_PATH="$pao_docker"
    "$pao_go" test ./internal/runner -run '^TestDockerHostSyntheticIsolationAcceptance$' -count=1 -v
)
```

Require exit code zero and an explicit `PASS` for the named test, with no `SKIP`.
Record the source revision, Go/Docker versions, operating system, test output
and cleanup result. Windows evidence does not establish Ubuntu acceptance.
The Linux endpoint must be the current user's Docker Desktop socket at
`$HOME/.docker/desktop/docker.sock`; ordinary/rootless Docker Engine is unsupported.

When it passes, the fixture proves that Docker uses the Linux engine, the target bind mount rejects writes, a distinct
temporary mount accepts writes, an undeclared host path is rejected, `network=none` leaves no active
non-loopback interface, and the container is removed after completion. It does not authorize a real
scanner: a reviewed runtime image and a verified imported toolchain are still required.
