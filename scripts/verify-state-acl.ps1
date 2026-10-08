#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$StateDirectory,
    [string]$FixtureRoot = [System.IO.Path]::GetTempPath()
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows state-directory ACL verification requires Windows.' }
$createdFixture = $false
$fixturePath = $null

function Assert-NoReparsePath([string]$Path) {
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path.StartsWith('\\')) {
        throw 'State-directory ACL verification requires an absolute local path.'
    }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "State-directory ACL verification refuses reparse points: $cursor"
        }
        $parent = [IO.Directory]::GetParent($cursor)
        $cursor = if ($parent) { $parent.FullName } else { $null }
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
        Assert-NoReparsePath $FixtureRoot
        $fixturePath = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) ('pao-state-acl-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($fixturePath) | Out-Null
        $createdFixture = $true
        $StateDirectory = $fixturePath

        # Only the synthetic fixture is provisioned. Explicit StateDirectory
        # verification never changes owner, inheritance, or access rules.
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $owner, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $fixturePath -AclObject $acl
        [IO.Directory]::CreateDirectory((Join-Path $fixturePath 'raw')) | Out-Null
        [IO.File]::WriteAllText((Join-Path $fixturePath 'raw\synthetic.txt'), 'synthetic ACL fixture')
    }

    Assert-NoReparsePath $StateDirectory
    $resolved = [IO.Path]::GetFullPath($StateDirectory)
    if (-not [IO.Directory]::Exists($resolved)) { throw 'State directory does not exist.' }

    # SID matching is independent of Windows display language and account-name
    # localization. Check mutation bits precisely; FullControl as an OR mask
    # would accidentally treat a read-only ACE as a write grant.
    $unsafeSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')
    $unsafeRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership

    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($resolved)
    $checked = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "State-directory ACL verification refuses reparse points: $current"
        }
        $acl = Get-Acl -LiteralPath $current
        foreach ($entry in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($entry.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $unsafeSids -contains $entry.IdentityReference.Value -and
                (($entry.FileSystemRights -band $unsafeRights) -ne 0)) {
                throw "State-directory ACL permits broad write access: $($entry.IdentityReference.Value) at $current"
            }
        }
        $checked++
        if ($item.PSIsContainer) {
            # Deliberately avoid recursive enumeration: reject each reparse
            # point before any attempt to enumerate its destination.
            foreach ($child in Get-ChildItem -LiteralPath $current -Force) {
                $pending.Push($child.FullName)
            }
        }
    }
    Write-Output "Windows state-directory ACL policy verified: $resolved ($checked objects)"
}
finally {
    if ($createdFixture -and $fixturePath -and [IO.Directory]::Exists($fixturePath)) {
        $expectedParent = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
        $actualParent = [IO.Directory]::GetParent([IO.Path]::GetFullPath($fixturePath)).FullName.TrimEnd('\')
        if ($actualParent -ne $expectedParent -or [IO.Path]::GetFileName($fixturePath) -notmatch '^pao-state-acl-[0-9a-f]{32}$') {
            throw 'Refusing cleanup outside the exact generated ACL fixture.'
        }
        Assert-NoReparsePath $fixturePath
        Remove-Item -LiteralPath $fixturePath -Recurse -Force
    }
}
