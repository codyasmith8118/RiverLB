#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
Install the restricted RiverLB SSH receiver on a single, fixed Hyper-V host.
Run from a trusted copy of this directory. No VM is stopped by installation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [Guid[]] $AllowedVMIds,
    [Parameter(Mandatory = $true)] [string[]] $AppliancePublicKeys,
    [Parameter(Mandatory = $true)] [System.Net.IPAddress[]] $ApplianceAddresses,
    [ValidatePattern('^[a-z_][a-z0-9_.-]{0,19}$')] [string] $UserName = 'riverlb-fence'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($AllowedVMIds.Count -lt 1 -or $AllowedVMIds.Count -gt 64 -or $ApplianceAddresses.Count -lt 1 -or $ApplianceAddresses.Count -gt 8) { throw 'Provide the VM GUIDs and source IP addresses for this HA pair.' }
Import-Module Hyper-V -ErrorAction Stop
foreach ($id in $AllowedVMIds) { Get-VM -Id $id -ErrorAction Stop | Out-Null }
Get-Service sshd -ErrorAction Stop | Out-Null
$sshd = Join-Path $env:SystemRoot 'System32/OpenSSH/sshd.exe'
$sshKeygen = Join-Path $env:SystemRoot 'System32/OpenSSH/ssh-keygen.exe'
$sshdConfig = Join-Path $env:ProgramData 'ssh/sshd_config'
$hostKey = Join-Path $env:ProgramData 'ssh/ssh_host_ed25519_key.pub'
if (!(Test-Path -LiteralPath $sshd) -or !(Test-Path -LiteralPath $sshdConfig) -or !(Test-Path -LiteralPath $hostKey)) { throw 'Install and start Windows OpenSSH Server first; its configuration and Ed25519 host key must exist.' }
$sourceReceiver = Join-Path $PSScriptRoot 'riverlb-hyperv-fence.ps1'
if (!(Test-Path -LiteralPath $sourceReceiver)) { throw 'Keep the receiver beside this installer.' }
$wmiReadHelper = Join-Path $PSScriptRoot 'Grant-RiverLBCimv2Read.ps1'
if (!(Test-Path -LiteralPath $wmiReadHelper)) { throw 'Keep the WMI read prerequisite helper beside this installer.' }
. $wmiReadHelper
$keys = @($AppliancePublicKeys | ForEach-Object {
    $key = $_.Trim()
    if ($key -cnotmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]*)?$') { throw 'Provide plain Ed25519 public keys without authorized_keys options.' }
    $blob = [Convert]::FromBase64String($Matches[1])
    if ($blob.Length -ne 51 -or [Text.Encoding]::ASCII.GetString($blob, 4, 11) -cne 'ssh-ed25519' -or $blob[3] -ne 11 -or $blob[18] -ne 32) { throw 'Invalid Ed25519 public key.' }
    'ssh-ed25519 ' + [Convert]::ToBase64String($blob)
} | Select-Object -Unique)
if ($keys.Count -lt 1 -or $keys.Count -gt 8) { throw 'Provide the public keys from the RiverLB appliances.' }

$installParent = Join-Path $env:ProgramData 'RiverLB'
$installRoot = Join-Path $installParent 'Fencing'
foreach ($path in @($installParent, $installRoot)) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'The installation directory cannot be a reparse point.' }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}
$settingsFile = Join-Path $installRoot 'allowed-vms.json'
$existingUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($null -ne $existingUser) {
    if (!(Test-Path -LiteralPath $settingsFile) -or (Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json).UserName -cne $UserName) { throw 'This local account already exists and is not a RiverLB fencing account. Choose a new dedicated username.' }
} else {
    $random = New-Object byte[] 48
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $password = ConvertTo-SecureString ([Convert]::ToBase64String($random) + 'aA1!') -AsPlainText -Force
    New-LocalUser -Name $UserName -Password $password -PasswordNeverExpires -UserMayNotChangePassword -Description 'Restricted RiverLB Hyper-V power fencing' | Out-Null
    [Array]::Clear($random, 0, $random.Length)
    $password.Dispose()
}
$account = Get-LocalUser -Name $UserName
$hypervGroup = Get-LocalGroup -SID 'S-1-5-32-578'
if (!(Get-LocalGroupMember -Group $hypervGroup | Where-Object SID -eq $account.SID)) {
    Add-LocalGroupMember -Group $hypervGroup -Member $account
}
$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
if (Get-LocalGroupMember -Group $administrators | Where-Object SID -eq $account.SID) { throw 'The dedicated fencing account must not be a member of Administrators.' }

# Only SYSTEM/Administrators can modify the script, keys or VM allowlist.
foreach ($path in @($installParent, $installRoot)) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $path -AclObject $acl
}
# Key-authenticated SSH uses a Network/S4U token. Grant only the observed
# root\cimv2 read prerequisite, with no methods, writes or child inheritance.
Grant-RiverLBCimv2Read -AccountSid $account.SID.Value -BackupPath (Join-Path $installRoot 'root-cimv2-original.sd')
$utf8 = [Text.UTF8Encoding]::new($false)
$receiver = Join-Path $installRoot 'riverlb-hyperv-fence.ps1'
Copy-Item -LiteralPath $sourceReceiver -Destination $receiver -Force
[IO.File]::WriteAllText($settingsFile, ([ordered]@{UserName = $UserName; AllowedVMIds = @($AllowedVMIds | ForEach-Object { $_.ToString('D') } | Select-Object -Unique)} | ConvertTo-Json), $utf8)
$sources = ($ApplianceAddresses | ForEach-Object ToString | Select-Object -Unique) -join ','
[IO.File]::WriteAllLines((Join-Path $installRoot 'authorized_keys'), @($keys | ForEach-Object { 'restrict,from="' + $sources + '" ' + $_ }), $utf8)

# A Match block confines this account to the fixed receiver. Other SSH users keep their policy.
$original = [IO.File]::ReadAllText($sshdConfig)
$startMarker = '# BEGIN RIVERLB HYPERV FENCING'
$endMarker = '# END RIVERLB HYPERV FENCING'
$pattern = '(?ms)^' + [regex]::Escape($startMarker) + '\r?\n.*?^' + [regex]::Escape($endMarker) + '\r?\n?'
$base = [regex]::Replace($original, $pattern, '')
if ($base -match ('(?im)^\s*Match\s+User\s+.*\b' + [regex]::Escape($UserName) + '\b')) { throw 'An existing SSH Match User block already configures this account. Review it before installing.' }
$receiverPath = $receiver.Replace('\', '/')
$powerShell = (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe').Replace('\', '/')
$keysPath = (Join-Path $installRoot 'authorized_keys').Replace('\', '/')
$block = @"
$startMarker
Match User $UserName
    AuthenticationMethods publickey
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile "$keysPath"
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTTY no
    ForceCommand "$powerShell" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "$receiverPath"
Match all
$endMarker
"@
try {
    [IO.File]::WriteAllText($sshdConfig, $base.TrimEnd() + "`r`n`r`n" + $block + "`r`n", $utf8)
    & $sshd -t -f $sshdConfig
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH rejected the fencing Match block.' }
    Restart-Service sshd -ErrorAction Stop
} catch {
    [IO.File]::WriteAllText($sshdConfig, $original, $utf8)
    throw 'OpenSSH configuration was restored. Inspect local sshd validation/service errors before retrying.'
}
Write-Host 'Restricted Hyper-V fencing receiver installed. No virtual machines were stopped.'
Write-Host ('SSH username: ' + $UserName)
Write-Host 'Pinned host public key (verify the fingerprint directly on this host):'
Get-Content -LiteralPath $hostKey
& $sshKeygen -lf $hostKey -E sha256
$AllowedVMIds | ForEach-Object { Get-VM -Id $_ } | Select-Object Name, Id, State | Format-Table -AutoSize
