# Portable execution fixture for the actual Windows installer helper.
# The WMI transport, typed object factory, SID conversion and file ACL adapter
# are substituted. This does not validate native Windows WMI or stop any VM.
param([Parameter(Mandatory = $true)] [string] $HelperPath,
    [Parameter(Mandatory = $true)] [string] $FixtureRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $HelperPath

# Native API-shaped objects deliberately have no projected WMI methods. This
# reproduces the Windows ManagementObject shape that rejected the original
# helper, while running the real Invoke-RiverLBWmiMethod adapter below.
Add-Type -TypeDefinition @'
using System;
public sealed class RiverLBFixtureWmiObject {
    public Func<string, object> ParameterFactory;
    public Func<string, object, object, object> MethodHandler;
    public object GetMethodParameters(string name) { return ParameterFactory(name); }
    public object InvokeMethod(string name, object input, object options) { return MethodHandler(name, input, options); }
}
'@

function Assert-Fixture {
    param([bool] $Condition, [string] $Message)
    if (!$Condition) { throw $Message }
}

function New-FixtureTrustee {
    param([byte] $Value)
    [pscustomobject]@{SID = [byte[]]@($Value); SIDLength = 1; SIDString = 'fixture'; Name = 'unchanged'; Domain = 'fixture'}
}

function New-FixtureAce {
    param([byte] $Sid, [uint32] $Mask, [uint32] $Type = 0, [uint32] $Flags = 0)
    [pscustomobject]@{AccessMask = $Mask; AceFlags = $Flags; AceType = $Type;
        GuidObjectType = $null; GuidInheritedObjectType = $null; Trustee = New-FixtureTrustee $Sid}
}

function Copy-FixtureDescriptor {
    param($Descriptor)
    $copy = [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($Descriptor, 20))
    $copy | Add-Member -MemberType ScriptMethod -Name Clone -Value { Copy-FixtureDescriptor $this } -Force
    return $copy
}

function Reset-Fixture {
    param([string] $Mode = 'success')
    $script:mode = $Mode
    $script:readCount = 0; $script:rawReads = 0; $script:sets = 0; $script:rawSets = 0; $script:protected = 0; $script:privilegeChecks = 0
    $script:original = [pscustomobject]@{ControlFlags = 0x9414; Owner = New-FixtureTrustee 9; Group = New-FixtureTrustee 10;
        DACL = @((New-FixtureAce 2 0x3f 1), (New-FixtureAce 1 0x2 1), (New-FixtureAce 3 0x13 0 0x12));
        SACL = @((New-FixtureAce 4 0x21 2 0xc0))}
    $script:state = Copy-FixtureDescriptor $script:original
    $script:initialBytes = [Text.Encoding]::UTF8.GetBytes((Get-RiverLBDescriptorSnapshot $script:original))
    $script:backup = Join-Path $FixtureRoot ($Mode + '-' + [Guid]::NewGuid().ToString('N') + '.sd')
}

function Assert-RiverLBSecurityPrivilege {
    $script:privilegeChecks++
    if ($script:mode -eq 'privilege-fail') { throw 'Missing fixture SeSecurityPrivilege' }
}

function Get-RiverLBSidBytes {
    param([string] $AccountSid)
    Assert-Fixture ($AccountSid -ceq 'S-1-5-21-1005') 'Algorithm requested a different SID'
    return ,([byte[]]@(1))
}

function New-RiverLBWmiInstance {
    param([string] $ClassName)
    if ($ClassName -ceq 'Win32_Trustee') {
        return [pscustomobject]@{SID = $null; SIDLength = $null; SIDString = $null; Name = $null; Domain = $null}
    }
    Assert-Fixture ($ClassName -ceq 'Win32_ACE') 'Unexpected WMI class factory'
    return [pscustomobject]@{AccessMask = $null; AceFlags = $null; AceType = $null;
        GuidObjectType = $null; GuidInheritedObjectType = $null; Trustee = $null}
}

function Protect-RiverLBSecurityBackup {
    param([string] $Path)
    Assert-Fixture ($Path -ceq $script:backup) 'Backup protected an unexpected path'
    $script:protected++
    if ($script:mode -eq 'backup-protect-fail') { throw 'Fixture backup ACL failure' }
}

$script:securityBackend = [pscustomobject]@{}
$script:securityBackend | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
    $script:readCount++
    $code = if ($script:mode -eq 'read-return-fail' -and $script:readCount -eq 1) { 9 } elseif ($script:mode -eq 'verify-return-fail' -and $script:sets -eq 1) { 2 } else { 0 }
    [pscustomobject]@{ReturnValue = $code; Descriptor = Copy-FixtureDescriptor $script:state}
}
$script:securityBackend | Add-Member -MemberType ScriptMethod -Name GetSD -Value {
    $script:rawReads++
    $bytes = if ($script:mode -eq 'concurrent-change' -and $script:rawReads -eq 2) { [byte[]]@(99) } else { $script:initialBytes }
    [pscustomobject]@{ReturnValue = $(if ($script:mode -eq 'raw-return-fail') { 2 } else { 0 }); SD = $bytes}
}
$script:securityBackend | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptor -Value {
    param($Descriptor)
    $script:sets++
    Assert-Fixture (Test-Path -LiteralPath $script:backup) 'Mutation occurred before backup'
    Assert-Fixture ($script:protected -gt 0) 'Mutation occurred before backup ACL protection'
    $script:state = Copy-FixtureDescriptor $Descriptor
    if ($script:sets -eq 1) {
        switch ($script:mode) {
            'wrong-mask' { $script:state.DACL[2].AccessMask = 0x23 }
            'wrong-flags' { $script:state.DACL[2].AceFlags = 2 }
            'wrong-sid' { $script:state.DACL[2].Trustee.SID = [byte[]]@(42) }
            'changed-deny' { $script:state.DACL[0].AccessMask = 0 }
            'changed-owner' { $script:state.Owner.SID = [byte[]]@(42) }
            'changed-group' { $script:state.Group.SID = [byte[]]@(42) }
            'changed-sacl' { $script:state.SACL[0].AccessMask = 0 }
            'changed-control' { $script:state.ControlFlags = 4 }
            'changed-order' { $script:state.DACL = @($script:state.DACL[1], $script:state.DACL[0], $script:state.DACL[2], $script:state.DACL[3]) }
            'set-throw' { throw 'Fixture setter threw after mutation' }
        }
    }
    [pscustomobject]@{ReturnValue = $(if (($script:mode -eq 'set-return-fail' -and $script:sets -eq 1) -or ($script:mode -eq 'rollback-fail' -and $script:sets -gt 1)) { 21 } else { 0 })}
}
$script:securityBackend | Add-Member -MemberType ScriptMethod -Name SetSD -Value {
    param([byte[]] $Bytes)
    $script:rawSets++
    Assert-Fixture ([Convert]::ToBase64String($Bytes) -ceq [Convert]::ToBase64String($script:initialBytes)) 'Rollback did not use the raw original bytes'
    $script:state = Copy-FixtureDescriptor $script:original
    [pscustomobject]@{ReturnValue = 0}
}
$script:converterBackend = [pscustomobject]@{}
$script:converterBackend | Add-Member -MemberType ScriptMethod -Name BinarySDToWin32SD -Value {
    param([byte[]] $Bytes)
    Assert-Fixture ([Convert]::ToBase64String($Bytes) -ceq [Convert]::ToBase64String($script:initialBytes)) 'Converter received unexpected raw descriptor'
    $decoded = Copy-FixtureDescriptor $script:original
    if ($script:mode -eq 'missing-sacl') { $decoded.SACL = $null }
    [pscustomobject]@{ReturnValue = $(if ($script:mode -eq 'decode-return-fail') { 8 } else { 0 }); Descriptor = $decoded}
}
function New-FixtureWmiParameters {
    param([string] $Name)
    [pscustomobject]@{Properties = @{$Name = [pscustomobject]@{Name = $Name; Value = $null}}}
}
function ConvertTo-FixtureWmiOutput {
    param($Result)
    [pscustomobject]@{Properties = @($Result.PSObject.Properties | ForEach-Object { [pscustomobject]@{Name = $_.Name; Value = $_.Value} })}
}
$script:security = [RiverLBFixtureWmiObject]::new()
$script:security.ParameterFactory = {
    param($MethodName)
    switch ($MethodName) {
        'GetSecurityDescriptor' { return $null }
        'GetSD' { return $null }
        'SetSecurityDescriptor' { return New-FixtureWmiParameters 'Descriptor' }
        'SetSD' { return New-FixtureWmiParameters 'SD' }
        default { throw ('Unexpected method metadata request: ' + $MethodName) }
    }
}
$script:security.MethodHandler = {
    param($MethodName, $InputParameters, $Options)
    Assert-Fixture ($null -eq $Options) 'Adapter did not use the synchronous three-argument overload'
    $result = switch ($MethodName) {
        'GetSecurityDescriptor' {
            Assert-Fixture ($null -eq $InputParameters) 'Read method unexpectedly received input parameters'
            $script:securityBackend.GetSecurityDescriptor()
        }
        'GetSD' {
            Assert-Fixture ($null -eq $InputParameters) 'Raw read unexpectedly received input parameters'
            $script:securityBackend.GetSD()
        }
        'SetSecurityDescriptor' { $script:securityBackend.SetSecurityDescriptor($InputParameters.Properties['Descriptor'].Value) }
        'SetSD' { $script:securityBackend.SetSD($InputParameters.Properties['SD'].Value) }
        default { throw ('Unexpected WMI method invocation: ' + $MethodName) }
    }
    return ConvertTo-FixtureWmiOutput $result
}
$script:converter = [RiverLBFixtureWmiObject]::new()
$script:converter.ParameterFactory = {
    param($MethodName)
    Assert-Fixture ($MethodName -ceq 'BinarySDToWin32SD') 'Unexpected converter method metadata'
    return New-FixtureWmiParameters 'BinarySD'
}
$script:converter.MethodHandler = {
    param($MethodName, $InputParameters, $Options)
    Assert-Fixture ($MethodName -ceq 'BinarySDToWin32SD' -and $null -eq $Options) 'Unexpected converter invocation'
    return ConvertTo-FixtureWmiOutput ($script:converterBackend.BinarySDToWin32SD($InputParameters.Properties['BinarySD'].Value))
}
function New-RiverLBWmiObject {
    param([string] $ClassName, [switch] $Singleton)
    if ($ClassName -ceq '__SystemSecurity' -and $Singleton) { return $script:security }
    Assert-Fixture ($ClassName -ceq 'Win32_SecurityDescriptorHelper' -and !$Singleton) 'Unexpected WMI object construction'
    return $script:converter
}

Reset-Fixture
$projectedMethodFailed = $false
try { $script:security.GetSecurityDescriptor() | Out-Null } catch { $projectedMethodFailed = $true }
Assert-Fixture $projectedMethodFailed 'Fixture failed to reproduce the absent projected WMI method'
$before = $script:state | ConvertTo-Json -Depth 20 -Compress
Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup
Assert-Fixture ($script:sets -eq 1 -and $script:rawSets -eq 0 -and $script:state.DACL.Count -eq 4) 'Read grant did not append exactly one ACE'
$added = $script:state.DACL[2]
Assert-Fixture ($added.AccessMask -eq 33 -and $added.AceFlags -eq 0 -and $added.AceType -eq 0) 'Added ACE widened the requested rights'
Assert-Fixture ([Convert]::ToBase64String([byte[]]$added.Trustee.SID) -ceq 'AQ==') 'Added ACE targets a different SID'
Assert-Fixture ($null -eq $added.Trustee.Name -and $null -eq $added.Trustee.Domain) 'Added trustee supplied an account name instead of only its SID'
$withoutGrant = Copy-FixtureDescriptor $script:state
$withoutGrant.DACL = @($withoutGrant.DACL[0], $withoutGrant.DACL[1], $withoutGrant.DACL[3])
Assert-Fixture (($withoutGrant | ConvertTo-Json -Depth 20 -Compress) -ceq $before) 'Original DACL, denies, owner, group, SACL or flags changed'
Assert-Fixture (($script:state.DACL[3].AceFlags -band 0x10) -ne 0) 'New explicit ACE was placed after inherited entries'
Assert-Fixture ([Convert]::ToBase64String([IO.File]::ReadAllBytes($script:backup)) -ceq [Convert]::ToBase64String($script:initialBytes)) 'Original raw bytes were not backed up'
Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup
Assert-Fixture ($script:sets -eq 1 -and $script:rawSets -eq 0) 'Rerun was not idempotent'

# First backup is retained even if a later administrator legitimately changes
# namespace policy before a later grant attempt.
$retained = [IO.File]::ReadAllBytes($script:backup)
Save-RiverLBOriginalSecurityDescriptor $script:backup ([byte[]]@(99))
Assert-Fixture ([Convert]::ToBase64String([IO.File]::ReadAllBytes($script:backup)) -ceq [Convert]::ToBase64String($retained)) 'Rerun overwrote the first backup'

foreach ($mode in @('no-inherited', 'null-sacl', 'empty-sacl', 'empty-dacl')) {
    Reset-Fixture $mode
    if ($mode -eq 'no-inherited') { $script:original.DACL[2].AceFlags = 0 }
    if ($mode -eq 'null-sacl') { $script:original.SACL = $null; $script:original.ControlFlags = 0x9404 }
    if ($mode -eq 'empty-sacl') { $script:original.SACL = @() }
    if ($mode -eq 'empty-dacl') { $script:original.DACL = @() }
    $script:state = Copy-FixtureDescriptor $script:original
    $script:initialBytes = [Text.Encoding]::UTF8.GetBytes((Get-RiverLBDescriptorSnapshot $script:original))
    Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup
    Assert-Fixture ($script:sets -eq 1) ('Valid descriptor was rejected: ' + $mode)
    $index = if ($mode -eq 'no-inherited') { 3 } elseif ($mode -eq 'empty-dacl') { 0 } else { 2 }
    Assert-Fixture ($script:state.DACL[$index].AccessMask -eq 33 -and $script:state.DACL[$index].AceFlags -eq 0) ('Valid descriptor grant was not explicit/narrow: ' + $mode)
    Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup
    Assert-Fixture ($script:sets -eq 1) ('Valid descriptor rerun was not idempotent: ' + $mode)
}
foreach ($mode in @('empty-backup', 'directory-backup')) {
    Reset-Fixture $mode
    if ($mode -eq 'empty-backup') { [IO.File]::WriteAllBytes($script:backup, [byte[]]@()) }
    else { New-Item -ItemType Directory -Path $script:backup | Out-Null }
    $failed = $false
    try { Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup } catch { $failed = $true }
    Assert-Fixture ($failed -and $script:sets -eq 0 -and $script:rawSets -eq 0) ('Invalid backup still permitted a mutation: ' + $mode)
}

foreach ($mode in @('privilege-fail', 'read-return-fail', 'raw-return-fail', 'decode-return-fail', 'missing-sacl', 'concurrent-change', 'backup-protect-fail', 'deny', 'null-dacl', 'no-dacl-flag')) {
    Reset-Fixture $mode
    if ($mode -eq 'deny') { $script:state.DACL += New-FixtureAce 1 0x20 1 }
    if ($mode -eq 'null-dacl') { $script:state.DACL = $null }
    if ($mode -eq 'no-dacl-flag') { $script:state.ControlFlags = 0x10 }
    $failed = $false
    try { Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup } catch { $failed = $true }
    Assert-Fixture ($failed -and $script:sets -eq 0 -and $script:rawSets -eq 0) ('Precondition failure still mutated security: ' + $mode)
}
foreach ($mode in @('wrong-mask', 'wrong-flags', 'wrong-sid', 'changed-deny', 'changed-owner', 'changed-group', 'changed-sacl', 'changed-control', 'changed-order', 'verify-return-fail', 'set-return-fail', 'set-throw')) {
    Reset-Fixture $mode
    $failed = $false
    try { Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup } catch { $failed = $_.Exception.Message -like '*original descriptor was restored*' }
    Assert-Fixture ($failed -and $script:sets -eq 2 -and $script:rawSets -eq 1) ('Failed verification did not restore both full and raw descriptors: ' + $mode)
    Assert-Fixture ((Get-RiverLBDescriptorSnapshot $script:state) -ceq (Get-RiverLBDescriptorSnapshot $script:original)) ('Rollback changed security: ' + $mode)
}
Reset-Fixture 'rollback-fail'
# Force the first verification failure, followed by a failing full restore.
$script:securityBackend | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
    [pscustomobject]@{ReturnValue = $(if ($script:sets -eq 1) { 2 } else { 0 }); Descriptor = Copy-FixtureDescriptor $script:state}
} -Force
$failed = $false
try { Grant-RiverLBCimv2Read -AccountSid 'S-1-5-21-1005' -BackupPath $script:backup } catch { $failed = $_.Exception.Message -like '*automatic restoration could not be verified*' }
Assert-Fixture ($failed -and $script:rawSets -eq 1) 'Rollback failure was hidden or prevented raw restoration'
Write-Output 'PASS PowerShell WMI prerequisite: explicit native API invocation without projected methods; exact SID/mask 33/flags 0; existing policy/SACL preservation; backup retention; idempotency; precondition failures; verified rollback'
