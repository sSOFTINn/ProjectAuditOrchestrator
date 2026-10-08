# Readiness for a `container-vm` execution provider

PAO deliberately cannot run an adapter merely because a local `docker` command exists. On Windows,
the execution provider must be separately reviewed to prove all controls required by an adapter
manifest: VM-backed isolation, read-only target access, temporary-write-only storage, denied network,
sanitized environment, process-tree control, CPU/memory limits and a clean runtime identity.

This is a preparation guide, not authorization to install software or audit a target.

## Safe diagnostic

Run in PowerShell 7 from the repository root:

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

After Docker Desktop reports its engine as running, this opt-in command builds a static Go fixture and
a local `FROM scratch` runtime. It pulls no image and does not start a scanner or inspect an audit
target:

```powershell
$env:PAO_DOCKER_INTEGRATION = '1'
$env:PAO_GO_PATH = (Resolve-Path '.toolchain/go-sdk/bin/go.exe')
& '.toolchain/go-sdk/bin/go.exe' test ./internal/runner -run TestDockerHostSyntheticIsolationAcceptance -count=1
Remove-Item Env:PAO_DOCKER_INTEGRATION, Env:PAO_GO_PATH
```

The fixture proves that Docker uses the Linux engine, the target bind mount rejects writes, a distinct
temporary mount accepts writes, an undeclared host path is rejected, `network=none` leaves no active
non-loopback interface, and the container is removed after completion. It does not authorize a real
scanner: a reviewed runtime image and a verified imported toolchain are still required.
