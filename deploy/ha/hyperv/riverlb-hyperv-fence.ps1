# Restricted SSH receiver. Install with Install-RiverLBFencing.ps1 on the Hyper-V host.
# Requests contain data only; no supplied command is evaluated or run as PowerShell.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$stage = 'command'
$localSession = $null
try {
    if ($env:SSH_ORIGINAL_COMMAND -cne 'riverlb-fence-v1') { throw 'Unsupported SSH command' }
    $stage = 'read'
    $requestBuffer = [Text.StringBuilder]::new()
    while ($requestBuffer.Length -le 4096) {
        $character = [Console]::In.Read()
        if ($character -eq -1 -or $character -eq 10) { break }
        [void]$requestBuffer.Append([char]$character)
    }
    if ($requestBuffer.Length -eq 0 -or $requestBuffer.Length -gt 4096) { throw 'Invalid request size' }
    # Windows text-mode pipes send CRLF; a CR-only buffer is still empty input.
    $requestText = $requestBuffer.ToString()
    if ([string]::IsNullOrWhiteSpace($requestText)) { throw 'Invalid request size' }
    $stage = 'parse'
    $request = $requestText | ConvertFrom-Json
    $stage = 'validate'
    $fields = @($request.PSObject.Properties.Name)
    if (@($fields | Where-Object { $_ -notin @('version', 'action', 'timeout', 'vm_id') }).Count -gt 0) { throw 'Unknown request property' }
    if ($request.version -ne 1 -or $request.action -cnotin @('list', 'status', 'off', 'on')) { throw 'Unsupported operation' }
    if (($request.timeout -isnot [int] -and $request.timeout -isnot [long]) -or $request.timeout -lt 5 -or $request.timeout -gt 120) { throw 'Invalid timeout' }
    $stage = 'settings'
    $settings = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'allowed-vms.json') -Raw | ConvertFrom-Json
    $allowed = @($settings.AllowedVMIds | ForEach-Object { ([Guid]$_).ToString('D') })
    if ($allowed.Count -lt 1 -or $allowed.Count -gt 64) { throw 'Invalid VM allowlist' }
    $stage = 'import-module'
    Import-Module Hyper-V -ErrorAction Stop
    $stage = 'local-session'
    # Omitting ComputerName selects local DCOM/COM rather than WS-Man. Keep
    # Hyper-V operations local to this host without remote credentials or WinRM.
    # The generic connection probe can require access outside Hyper-V's namespace.
    # Each allowlisted Get-VM query below still checks the actual provider access.
    $localSession = New-CimSession -SkipTestConnection -ErrorAction Stop
    if ($request.action -ceq 'list') {
        if ($fields -contains 'vm_id') { throw 'List does not accept a VM target' }
        $stage = 'list-vm'
        $machines = @($allowed | ForEach-Object {
            $vm = Get-VM -Id ([Guid]$_) -CimSession $localSession -ErrorAction Stop
            [ordered]@{vm_id = $vm.Id.ToString('D'); name = $vm.Name; state = $(if ($vm.State.ToString() -ceq 'Off') { 'off' } else { 'on' })}
        })
        [ordered]@{version = 1; ok = $true; machines = $machines} | ConvertTo-Json -Compress -Depth 4
        exit 0
    }
    $stage = 'target'
    if ($request.vm_id -isnot [string] -or $request.vm_id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'Invalid VM GUID' }
    if ($allowed -notcontains $request.vm_id) { throw 'VM is not allowlisted' }
    $vm = Get-VM -Id ([Guid]$request.vm_id) -CimSession $localSession -ErrorAction Stop
    $stage = 'power'
    if ($request.action -ceq 'off' -and $vm.State.ToString() -cne 'Off') {
        # Hard power-off works for paused or unresponsive guests. Shutdown/Save cannot prove fencing.
        Stop-VM -VM $vm -TurnOff -Force -Confirm:$false -ErrorAction Stop | Out-Null
    }
    if ($request.action -ceq 'on' -and $vm.State.ToString() -cne 'Running') {
        Start-VM -VM $vm -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($request.timeout)
    $stage = 'confirm'
    do {
        $vm = Get-VM -Id ([Guid]$request.vm_id) -CimSession $localSession -ErrorAction Stop
        $state = $vm.State.ToString()
        if ($request.action -ceq 'status' -or ($request.action -ceq 'off' -and $state -ceq 'Off') -or ($request.action -ceq 'on' -and $state -ceq 'Running')) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (($request.action -ceq 'off' -and $state -cne 'Off') -or ($request.action -ceq 'on' -and $state -cne 'Running')) { throw 'Power state was not confirmed' }
    [ordered]@{version = 1; ok = $true; vm_id = $vm.Id.ToString('D'); state = $(if ($state -ceq 'Off') { 'off' } else { 'on' })} | ConvertTo-Json -Compress
    exit 0
} catch {
    # Fixed stages, a sanitized type name and an ErrorCategory enum locate failures
    # without echoing request data, credentials or exception messages from the host.
    $exceptionType = $_.Exception.GetType().Name
    if ($exceptionType -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,95}$') { $exceptionType = 'UnknownException' }
    $category = [System.Management.Automation.ErrorCategory]$_.CategoryInfo.Category
    # Numeric HRESULTs identify access/transport failures without host error text.
    # Limit the exception chain so diagnostic output stays bounded.
    $exception = $_.Exception
    $codes = @()
    for ($depth = 0; $depth -lt 3 -and $null -ne $exception; $depth++) {
        $codes += ('0x{0:X8}' -f ([int64]$exception.HResult -band 4294967295))
        $exception = $exception.InnerException
    }
    [Console]::Error.WriteLine(('RiverLB Hyper-V fencing receiver rejected or could not confirm the operation (stage={0}; type={1}; category={2}; hresult={3}).' -f $stage, $exceptionType, $category, ($codes -join ',')))
    exit 1
} finally {
    if ($null -ne $localSession) {
        try { Remove-CimSession -CimSession $localSession -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}
