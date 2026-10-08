#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputBase)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows ACL fixture tests require Windows.' }
if (-not [IO.Path]::IsPathFullyQualified($OutputBase)) { throw 'OutputBase must be absolute.' }
$base = Get-Item -LiteralPath $OutputBase -Force
if (-not $base.PSIsContainer -or ($base.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'OutputBase must be an existing non-reparse directory.'
}
$root = Join-Path $base.FullName ('state-acl-tests-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$verifier = Join-Path $PSScriptRoot 'verify-state-acl.ps1'
$passed = [Collections.Generic.List[string]]::new()

function New-Fixture([string]$Name) {
    $path = Join-Path $root $Name
    [IO.Directory]::CreateDirectory($path) | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $owner, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $path -AclObject $acl
    [IO.Directory]::CreateDirectory((Join-Path $path 'raw\nested')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $path 'raw\nested\synthetic.json'), '{"synthetic":true}')
    return $path
}

function Add-Grant([string]$Path, [string]$Sid, [string]$Rights) {
    $item = Get-Item -LiteralPath $Path -Force
    $existing = Get-Acl -LiteralPath $Path
    $acl = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    # Persist only the synthetic discretionary ACL. Copying an entire security
    # descriptor can request the unrelated privileged SACL/owner operations.
    $sections = [Security.AccessControl.AccessControlSections]::Access
    $acl.SetSecurityDescriptorSddlForm($existing.GetSecurityDescriptorSddlForm($sections), $sections)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($Sid), $Rights, 'Allow'))
    [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
}

function Assert-Rejected([string]$Name, [string]$Path, [string]$Expected) {
    $rejected = $false
    try { & $verifier -StateDirectory $Path | Out-Null }
    catch { $rejected = $_.Exception.Message -like $Expected }
    if (-not $rejected) { throw "ACL verifier accepted invalid fixture or failed unexpectedly: $Name" }
    $passed.Add($Name)
}

$valid = New-Fixture 'owner-only'
$before = (Get-Acl -LiteralPath $valid).Sddl
& $verifier -StateDirectory $valid | Out-Null
if ((Get-Acl -LiteralPath $valid).Sddl -ne $before) { throw 'Read-only verification changed ACL.' }
$passed.Add('owner-only-subtree-read-only-verification')

foreach ($sid in @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')) {
    $fixture = New-Fixture ('root-' + $sid)
    Add-Grant $fixture $sid 'Write'
    Assert-Rejected ('root-write-' + $sid) $fixture '*permits broad write access*'
}

$childDirectory = New-Fixture 'child-directory-grant'
Add-Grant (Join-Path $childDirectory 'raw\nested') 'S-1-5-11' 'Modify'
Assert-Rejected 'child-directory-write' $childDirectory '*permits broad write access*'
$childFile = New-Fixture 'child-file-grant'
Add-Grant (Join-Path $childFile 'raw\nested\synthetic.json') 'S-1-1-0' 'ChangePermissions'
Assert-Rejected 'child-file-change-permissions' $childFile '*permits broad write access*'

$readOnly = New-Fixture 'read-only-grant'
Add-Grant $readOnly 'S-1-1-0' 'ReadAndExecute'
& $verifier -StateDirectory $readOnly | Out-Null
$passed.Add('read-only-is-not-write')

$outside = New-Fixture 'outside-junction'
$withJunction = New-Fixture 'junction-child'
$junction = Join-Path $withJunction 'redirect'
New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
Assert-Rejected 'reject-child-junction' $withJunction '*refuses reparse points*'
Assert-Rejected 'reject-root-junction' $junction '*refuses reparse points*'
Assert-Rejected 'reject-junction-ancestor' (Join-Path $junction 'raw') '*refuses reparse points*'
# Remove only the exact synthetic junction itself, without traversing its target.
if ((Get-Item -LiteralPath $junction -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    [IO.Directory]::Delete($junction)
}

& $verifier -FixtureRoot $root | Out-Null
$passed.Add('default-synthetic-fixture')
[pscustomobject]@{ Status = 'PASSED'; Count = $passed.Count; Checks = $passed.ToArray(); SyntheticRoot = $root } | ConvertTo-Json -Depth 4
