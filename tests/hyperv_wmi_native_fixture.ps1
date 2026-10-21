# Read-only native Windows WMI qualification. Never invokes either setter,
# persists a WMI object, changes an ACL, restarts a service, or contacts Hyper-V.
param([Parameter(Mandatory = $true)] [string] $HelperPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT') { throw 'Native WMI qualification requires Windows.' }
. $HelperPath
Assert-RiverLBSecurityPrivilege
$security = Get-RiverLBWmiSecurity
if ($security -isnot [System.Management.ManagementObject] -or !$security.PSBase.Scope.Options.EnablePrivileges) {
    throw 'Native security singleton was not bound with enabled privileges.'
}
if ($security.PSBase.Path.RelativePath -cne '__SystemSecurity=@') { throw 'Native singleton path differs.' }
$original = Invoke-RiverLBWmiMethod $security 'GetSecurityDescriptor'
Assert-RiverLBWmiResult $original 'native read-only descriptor query'
$raw = Invoke-RiverLBWmiMethod $security 'GetSD'
Assert-RiverLBWmiResult $raw 'native read-only binary query'
if ($null -eq $original.Descriptor -or ([byte[]] $raw.SD).Length -eq 0) { throw 'Native WMI returned an empty descriptor.' }
$decoded = Get-RiverLBBinarySecurityDescriptor ([byte[]] $raw.SD)
if ((Get-RiverLBDescriptorSnapshot $decoded) -cne (Get-RiverLBDescriptorSnapshot $original.Descriptor)) {
    throw 'Native raw and typed descriptor snapshots differ.'
}
# Validate the exact setter parameter objects without invoking those methods.
$typedParameters = $security.PSBase.GetMethodParameters('SetSecurityDescriptor')
$typedParameters.Properties['Descriptor'].Value = $original.Descriptor
$rawParameters = $security.PSBase.GetMethodParameters('SetSD')
$rawParameters.Properties['SD'].Value = [byte[]] $raw.SD
if ($typedParameters.Properties['Descriptor'].Type -ne [System.Management.CimType]::Object -or
    $rawParameters.Properties['SD'].Type -ne [System.Management.CimType]::UInt8 -or !$rawParameters.Properties['SD'].IsArray) {
    throw 'Native setter parameter schemas differ.'
}
# Construct only transient typed ACE/trustee instances; no Put/Invoke setter.
$ace = New-RiverLBWmiInstance 'Win32_ACE'
$trustee = New-RiverLBWmiInstance 'Win32_Trustee'
$trustee.SID = Get-RiverLBSidBytes 'S-1-5-32-544'
$ace.Trustee = $trustee
$ace.AccessMask = 0x21; $ace.AceFlags = 0; $ace.AceType = 0
$copy = $original.Descriptor.Clone()
$copy.DACL = @($copy.DACL) + @($ace)
$typedParameters.Properties['Descriptor'].Value = $copy
Write-Output 'PASS native Windows WMI (read-only): bound singleton; explicit read/conversion calls; full descriptor agreement; typed setter schemas and transient ACE construction'
