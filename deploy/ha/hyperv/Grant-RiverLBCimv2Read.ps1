# Windows PowerShell 5.1 installer helper. Dot-source only from a trusted directory.
# This prerequisite is for the observed SSH/S4U root\cimv2 connection denial.
# Namespace rights: https://learn.microsoft.com/windows/win32/wmisdk/namespace-access-rights-constants
# SACL/ControlFlags: https://learn.microsoft.com/windows/win32/wmisdk/setsecuritydescriptor-method-in-class---systemsecurity
function Assert-RiverLBWmiResult {
    param($Result, [string] $Operation)
    if ($null -eq $Result -or $null -eq $Result.ReturnValue -or $Result.ReturnValue -ne 0) {
        throw ('WMI security operation failed: ' + $Operation + '. No SSH configuration was activated.')
    }
}

function Assert-RiverLBSecurityPrivilege {
    # ManagementScope.EnablePrivileges enables assigned privileges on WMI calls. Require
    # SeSecurityPrivilege to be assigned so a missing SACL is never assumed empty.
    $privileges = & (Join-Path $env:SystemRoot 'System32/whoami.exe') /priv /fo csv /nh
    if ($LASTEXITCODE -ne 0 -or ($privileges -join "`n") -notmatch '"SeSecurityPrivilege"') {
        throw 'The installer requires an administrator token with SeSecurityPrivilege to preserve WMI auditing.'
    }
}

function New-RiverLBWmiObject {
    param([ValidateSet('__SystemSecurity', 'Win32_SecurityDescriptorHelper', 'Win32_ACE', 'Win32_Trustee')] [string] $ClassName,
        [switch] $Singleton)
    Add-Type -AssemblyName System.Management
    $scope = [System.Management.ManagementScope]::new('\\.\root\cimv2')
    $scope.Options.EnablePrivileges = $true
    $scope.Options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $scope.Connect()
    if ($Singleton) {
        if ($ClassName -cne '__SystemSecurity') { throw 'Only the namespace security singleton is supported.' }
        $object = [System.Management.ManagementObject]::new($scope, [System.Management.ManagementPath]::new('__SystemSecurity=@'), $null)
    } else {
        $object = [System.Management.ManagementClass]::new($scope, [System.Management.ManagementPath]::new($ClassName), $null)
    }
    $object.PSBase.Get()
    return $object
}

function Get-RiverLBWmiSecurity {
    New-RiverLBWmiObject -ClassName '__SystemSecurity' -Singleton
}

function Invoke-RiverLBWmiMethod {
    param($Object, [string] $MethodName, [hashtable] $Arguments = @{})
    # Use the documented .NET API, independent of PowerShell's projected WMI
    # methods (which are absent on some returned ManagementObject instances).
    # https://learn.microsoft.com/dotnet/api/system.management.managementobject.invokemethod
    $parameters = $Object.PSBase.GetMethodParameters($MethodName)
    foreach ($name in $Arguments.Keys) {
        if ($null -eq $parameters -or $null -eq $parameters.Properties[$name]) {
            throw ('WMI method is missing its required input parameter: ' + $MethodName + '.' + $name)
        }
        $parameters.Properties[$name].Value = $Arguments[$name]
    }
    $output = $Object.PSBase.InvokeMethod($MethodName, $parameters, $null)
    if ($null -eq $output) { throw ('WMI method returned no output: ' + $MethodName) }
    $values = [ordered]@{}
    foreach ($property in $output.Properties) { $values[$property.Name] = $property.Value }
    return [pscustomobject] $values
}

function New-RiverLBWmiInstance {
    param([ValidateSet('Win32_ACE', 'Win32_Trustee')] [string] $ClassName)
    (New-RiverLBWmiObject -ClassName $ClassName).PSBase.CreateInstance()
}

function Get-RiverLBSidBytes {
    param([string] $AccountSid)
    $sid = [Security.Principal.SecurityIdentifier]::new($AccountSid)
    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)
    return ,$bytes
}

function Get-RiverLBBinarySecurityDescriptor {
    param([byte[]] $Bytes)
    $helper = New-RiverLBWmiObject -ClassName 'Win32_SecurityDescriptorHelper'
    $result = Invoke-RiverLBWmiMethod $helper 'BinarySDToWin32SD' @{BinarySD = $Bytes}
    Assert-RiverLBWmiResult $result 'decode original descriptor'
    if ($null -eq $result.Descriptor) { throw 'WMI returned an empty original security descriptor.' }
    return $result.Descriptor
}

function ConvertTo-RiverLBTrusteeSnapshot {
    param($Trustee)
    if ($null -eq $Trustee) { return $null }
    # Name/Domain/SIDString/SIDLength are display/derived data; providers can
    # populate them when reading a trustee that was created using only its SID.
    [ordered]@{ SID = [Convert]::ToBase64String([byte[]] $Trustee.SID) }
}

function ConvertTo-RiverLBAceSnapshot {
    param($Ace)
    [ordered]@{ AccessMask = $Ace.AccessMask; AceFlags = $Ace.AceFlags; AceType = $Ace.AceType;
        GuidObjectType = $Ace.GuidObjectType; GuidInheritedObjectType = $Ace.GuidInheritedObjectType;
        Trustee = ConvertTo-RiverLBTrusteeSnapshot $Ace.Trustee }
}

function Get-RiverLBDescriptorSnapshot {
    param($Descriptor)
    # Compare security-bearing fields, including ACE order and SID identities.
    # WMI TIME_CREATED and object-path metadata are not security descriptor fields.
    [ordered]@{ ControlFlags = $Descriptor.ControlFlags;
        Owner = ConvertTo-RiverLBTrusteeSnapshot $Descriptor.Owner;
        Group = ConvertTo-RiverLBTrusteeSnapshot $Descriptor.Group;
        DACL = if ($null -eq $Descriptor.DACL) { $null } else { ,@($Descriptor.DACL | ForEach-Object { ConvertTo-RiverLBAceSnapshot $_ }) };
        SACL = if ($null -eq $Descriptor.SACL) { $null } else { ,@($Descriptor.SACL | ForEach-Object { ConvertTo-RiverLBAceSnapshot $_ }) } } | ConvertTo-Json -Depth 12 -Compress
}

function Protect-RiverLBSecurityBackup {
    param([string] $Path)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Save-RiverLBOriginalSecurityDescriptor {
    param([string] $BackupPath, [byte[]] $Bytes)
    if (Test-Path -LiteralPath $BackupPath) {
        $existing = Get-Item -LiteralPath $BackupPath -Force
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $existing.Length -eq 0) {
            throw 'The original WMI security descriptor backup is not a regular nonempty file.'
        }
        Protect-RiverLBSecurityBackup $BackupPath
        return
    }
    # Never overwrite the first backup on an installer rerun. The parent directory
    # already permits writes only by SYSTEM/Administrators when this helper runs.
    $stream = [IO.File]::Open($BackupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
    Protect-RiverLBSecurityBackup $BackupPath
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($BackupPath)) -cne [Convert]::ToBase64String($Bytes)) {
        throw 'The original WMI security descriptor backup could not be verified.'
    }
}

function Grant-RiverLBCimv2Read {
    param([Parameter(Mandatory = $true)] [string] $AccountSid,
        [Parameter(Mandatory = $true)] [string] $BackupPath)
    Assert-RiverLBSecurityPrivilege
    $sidBytes = Get-RiverLBSidBytes $AccountSid
    $sidKey = [Convert]::ToBase64String($sidBytes)
    $security = Get-RiverLBWmiSecurity
    $originalResult = Invoke-RiverLBWmiMethod $security 'GetSecurityDescriptor'
    Assert-RiverLBWmiResult $originalResult 'read namespace descriptor'
    $original = $originalResult.Descriptor
    if ($null -eq $original -or $null -eq $original.DACL -or ($original.ControlFlags -band 4) -eq 0) {
        throw 'The WMI namespace must have an existing DACL; its access policy was left unchanged.'
    }
    $originalSnapshot = Get-RiverLBDescriptorSnapshot $original
    $rights = 0
    foreach ($entry in $original.DACL) {
        if ([Convert]::ToBase64String([byte[]] $entry.Trustee.SID) -ceq $sidKey) {
            if ($entry.AceType -eq 1 -and ($entry.AceFlags -band 8) -eq 0 -and ($entry.AccessMask -band 0x21) -ne 0) {
                throw 'An existing WMI deny ACE blocks the fencing account. Its access policy was left unchanged.'
            }
            if ($entry.AceType -eq 0 -and $entry.AceFlags -eq 0) { $rights = $rights -bor $entry.AccessMask }
        }
    }
    if (($rights -band 0x21) -eq 0x21) { return }

    $rawResult = Invoke-RiverLBWmiMethod $security 'GetSD'
    Assert-RiverLBWmiResult $rawResult 'back up namespace descriptor'
    $originalBytes = [byte[]] $rawResult.SD
    if ($originalBytes.Length -eq 0 -or (Get-RiverLBDescriptorSnapshot (Get-RiverLBBinarySecurityDescriptor $originalBytes)) -cne $originalSnapshot) {
        throw 'The full WMI descriptor could not be backed up consistently; its access policy was left unchanged.'
    }
    Save-RiverLBOriginalSecurityDescriptor $BackupPath $originalBytes
    $updated = $original.Clone()
    $trustee = New-RiverLBWmiInstance 'Win32_Trustee'
    $trustee.SID = $sidBytes
    $ace = New-RiverLBWmiInstance 'Win32_ACE'
    $ace.AccessMask = 0x21 # Enable Account/read + Remote Enable only.
    $ace.AceFlags = 0    # This namespace only; no inheritance to children.
    $ace.AceType = 0     # Allow. Existing ACEs, including denies, stay in order.
    $ace.Trustee = $trustee
    # Keep explicit ACEs before inherited ACEs. Inserting here preserves the
    # relative order of every existing deny/allow entry in the namespace.
    $entries = [Collections.Generic.List[object]]::new()
    $inserted = $false
    foreach ($entry in $original.DACL) {
        if (!$inserted -and ($entry.AceFlags -band 0x10) -ne 0) { $entries.Add($ace); $inserted = $true }
        $entries.Add($entry)
    }
    if (!$inserted) { $entries.Add($ace) }
    $updated.DACL = $entries.ToArray()
    $expectedSnapshot = Get-RiverLBDescriptorSnapshot $updated
    $unchanged = Invoke-RiverLBWmiMethod $security 'GetSD'
    Assert-RiverLBWmiResult $unchanged 'check for concurrent namespace changes'
    if ([Convert]::ToBase64String([byte[]] $unchanged.SD) -cne [Convert]::ToBase64String($originalBytes)) {
        throw 'WMI namespace security changed during installation; retry after reviewing its access policy.'
    }
    try {
        Assert-RiverLBWmiResult (Invoke-RiverLBWmiMethod $security 'SetSecurityDescriptor' @{Descriptor = $updated}) 'grant namespace read access'
        $verified = Invoke-RiverLBWmiMethod $security 'GetSecurityDescriptor'
        Assert-RiverLBWmiResult $verified 'verify namespace read access'
        if ((Get-RiverLBDescriptorSnapshot $verified.Descriptor) -cne $expectedSnapshot) {
            throw 'WMI namespace read access verification failed.'
        }
    } catch {
        # SetSD restores raw DACL bytes. Restore the full original descriptor as
        # well because SetSD alone does not restore owner/group/SACL fields.
        $rollbackFailed = $false
        try { Assert-RiverLBWmiResult (Invoke-RiverLBWmiMethod $security 'SetSecurityDescriptor' @{Descriptor = $original}) 'restore full namespace descriptor' } catch { $rollbackFailed = $true }
        # Attempt the raw DACL restore even if the full restore returned an error.
        try { Assert-RiverLBWmiResult (Invoke-RiverLBWmiMethod $security 'SetSD' @{SD = $originalBytes}) 'restore raw namespace descriptor' } catch { $rollbackFailed = $true }
        try {
            $restored = Invoke-RiverLBWmiMethod $security 'GetSecurityDescriptor'
            Assert-RiverLBWmiResult $restored 'verify restored namespace descriptor'
            if ((Get-RiverLBDescriptorSnapshot $restored.Descriptor) -cne $originalSnapshot) { throw 'Restored descriptor differs.' }
        } catch { $rollbackFailed = $true }
        if ($rollbackFailed) {
            throw ('WMI security update failed and automatic restoration could not be verified. Stop installation and restore the protected backup: ' + $BackupPath)
        }
        throw 'WMI namespace read access could not be verified; the original descriptor was restored. No SSH configuration was activated.'
    }
}
