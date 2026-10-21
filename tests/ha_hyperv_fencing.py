"""Restricted Hyper-V fence agent contracts; --ssh-smoke uses a disposable real sshd.

The SSH smoke receiver simulates VM states. It does not contact Windows or stop VMs.
Windows receiver execution and actual Hyper-V fencing remain lab qualification.
"""
import base64
from contextlib import redirect_stdout
import getpass
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / 'deploy/ha/agents/fence_riverlb_hyperv'
loader = importlib.machinery.SourceFileLoader('hyperv_fence', str(AGENT))
spec = importlib.util.spec_from_loader(loader.name, loader)
agent = importlib.util.module_from_spec(spec)
loader.exec_module(agent)
VM = 'f0f8a92b-51d4-4be4-93b4-9086d7be98e2'
OTHER_VM = '05ed78e4-1638-456b-84ac-e65a6d812900'
KEY = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + b'\x01' * 32).decode()


class HyperV(unittest.TestCase):
    def values(self, **changes):
        return dict(ipaddr='192.0.2.30', login='riverlb-fence', identity_file='/etc/riverlb/ha-sync-ed25519',
                    ssh_host_key=KEY, plug=VM, **changes)

    def test_metadata_and_stdin_contract(self):
        metadata = ET.fromstring(agent.metadata())
        self.assertEqual(metadata.get('name'), 'fence_riverlb_hyperv')
        self.assertEqual({a.get('name') for a in metadata.findall('./actions/action')},
                         {'on', 'off', 'reboot', 'status', 'list', 'list-status', 'monitor', 'metadata', 'validate-all'})
        values = agent.arguments([], io.StringIO('action=status\nipaddr=192.0.2.30\nplug=' + VM + '\npcmk_host_list=a b\n'))
        self.assertEqual(values, {'action': 'status', 'ipaddr': '192.0.2.30', 'plug': VM})
        self.assertEqual(agent.arguments(['--action', 'metadata'], io.StringIO()), {'action': 'metadata'})
        for value in ('action=list\naction=off\n', 'ssh_options=ProxyCommand=sh\n', 'not-a-parameter', 'x' * 16385):
            with self.assertRaises(ValueError):
                agent.arguments([], io.StringIO(value))

    def test_configuration_rejects_injection_unpinned_and_invalid_targets(self):
        with patch.object(agent, 'private_file', side_effect=lambda value: value):
            self.assertEqual(agent.configuration(self.values())['plug'], VM)
            for field, value in [('ipaddr', '-oProxyCommand=id'), ('ipaddr', 'host;id'),
                                 ('login', 'user@host'), ('login', 'user;id'), ('plug', VM + ';id'),
                                 ('plug', 'riverlb-a'), ('ipport', '65536'), ('power_timeout', '121'),
                                 ('ssh_host_key', 'command="id" ' + KEY), ('ssh_host_key', KEY + '\n' + KEY)]:
                values = self.values()
                values[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    agent.configuration(values)
            values = self.values()
            del values['ssh_host_key']
            with self.assertRaises(ValueError):
                agent.configuration(values)
            values['known_hosts'] = '/etc/riverlb/known_hosts'
            self.assertIn('known_hosts', agent.configuration(values))
            values['ssh_host_key'] = KEY
            with self.assertRaises(ValueError):
                agent.configuration(values)

    def test_pacemaker_node_context_does_not_override_the_mapped_vm(self):
        # Pacemaker adds nodename alongside the GUID selected by pcmk_host_map.
        payload = 'action=off\nnodename=riverlb-b\nplug=' + VM + '\n'
        values = agent.arguments([], io.StringIO(payload))
        self.assertEqual(values, {'action': 'off', 'plug': VM})
        with patch.object(agent, 'configuration', side_effect=lambda values: values), \
                patch.object(agent, 'transport', return_value={'vm_id': VM, 'state': 'off'}) as send:
            self.assertEqual(agent.execute(values), 0)
            self.assertEqual(send.call_args.args, (values, 'off', VM))
            send.reset_mock()
            with self.assertRaises(ValueError):
                agent.execute(agent.arguments([], io.StringIO('action=off\nnodename=' + VM + '\n')))
            send.assert_not_called()
        with self.assertRaises(ValueError):
            agent.arguments([], io.StringIO(payload + 'nodename=riverlb-a\n'))

    def test_key_paths_require_root_private_files_and_safe_ancestors(self):
        def attributes(path):
            return SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o600) if path.name == 'identity' else (stat.S_IFDIR | 0o700))
        target = Path('/etc/riverlb/fencing/identity')
        with patch.object(Path, 'resolve', lambda path: path), patch.object(Path, 'lstat', attributes):
            self.assertEqual(agent.private_file(str(target)), str(target))
            with self.assertRaises(ValueError):
                agent.private_file('/tmp/identity')
            for bad in (SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o600),
                        SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o640),
                        SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o600)):
                with patch.object(Path, 'lstat', lambda path: bad if path == target else attributes(path)):
                    with self.assertRaises(ValueError):
                        agent.private_file(str(target))
            with patch.object(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777) if str(path) == '/etc/riverlb' else attributes(path)):
                with self.assertRaises(ValueError):
                    agent.private_file(str(target))

    def test_host_pin_is_private_temporary_and_removed_after_request(self):
        with patch.object(agent, 'ssh_request') as send:
            def inspect(values, action, target):
                pin = Path(values['known_hosts'])
                self.assertEqual(pin.stat().st_mode & 0o777, 0o600)
                self.assertEqual(pin.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(pin.read_text(), '[192.0.2.30]:2222 ' + KEY + '\n')
                self.pin = pin
                return {'version': 1, 'ok': True}
            send.side_effect = inspect
            agent.transport(dict(self.values(), ipport=2222), 'list')
            self.assertFalse(self.pin.exists())

    def test_power_off_requires_correct_guid_and_confirmed_off(self):
        with patch.object(agent, 'configuration', side_effect=lambda values: values):
            for reply in ({'vm_id': OTHER_VM, 'state': 'off'}, {'vm_id': VM, 'state': 'on'},
                          {'vm_id': VM, 'state': 'paused'}, {'state': 'off'}):
                with patch.object(agent, 'transport', return_value=reply), self.assertRaises(ValueError):
                    agent.execute(self.values(action='off'))
            with patch.object(agent, 'transport', return_value={'vm_id': VM, 'state': 'off'}):
                self.assertEqual(agent.execute(self.values(action='off')), 0)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(agent.execute(self.values(action='status')), 2)
            with patch.object(agent, 'transport', side_effect=[{'vm_id': VM, 'state': 'off'}, {'vm_id': VM, 'state': 'on'}]) as call:
                self.assertEqual(agent.execute(self.values(action='reboot')), 0)
                self.assertEqual([c.args[1] for c in call.call_args_list], ['off', 'on'])

    def test_discovery_and_monitor_never_send_power_actions(self):
        reply = {'machines': [{'vm_id': VM, 'name': 'RiverLB, A\ncontrol', 'state': 'on'}]}
        with patch.object(agent, 'configuration', side_effect=lambda values: values), patch.object(agent, 'transport', return_value=reply) as send:
            for action in ('list', 'list-status', 'monitor'):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(agent.execute(self.values(action=action)), 0)
                self.assertEqual(send.call_args.args[1], 'list')
                self.assertNotIn('\ncontrol', output.getvalue())
                if action == 'monitor':
                    self.assertEqual(output.getvalue(), '')

    def test_windows_receiver_uses_only_fixed_allowlisted_hard_power_operations(self):
        receiver = (ROOT / 'deploy/ha/hyperv/riverlb-hyperv-fence.ps1').read_text()
        installer = (ROOT / 'deploy/ha/hyperv/Install-RiverLBFencing.ps1').read_text()
        self.assertIn("$env:SSH_ORIGINAL_COMMAND -cne 'riverlb-fence-v1'", receiver)
        self.assertIn("$allowed -notcontains $request.vm_id", receiver)
        self.assertIn('Stop-VM -VM $vm -TurnOff -Force -Confirm:$false', receiver)
        self.assertIn("$state -cne 'Off'", receiver)
        self.assertNotIn('Invoke-Expression', receiver)
        self.assertNotIn('Invoke-Command', receiver)
        self.assertNotIn('$_.Exception.Message', receiver)
        self.assertIn('$_.Exception.GetType().Name', receiver)
        self.assertIn('[System.Management.Automation.ErrorCategory]$_.CategoryInfo.Category', receiver)
        self.assertIn('$localSession = New-CimSession -SkipTestConnection -ErrorAction Stop', receiver)
        self.assertEqual(receiver.count('-CimSession $localSession -ErrorAction Stop'), 3)
        self.assertIn('Remove-CimSession -CimSession $localSession', receiver)
        self.assertNotIn('New-CimSession -ComputerName', receiver)
        self.assertNotIn('New-CimSession -Credential', receiver)
        self.assertIn('AuthenticationMethods publickey', installer)
        self.assertIn('PasswordAuthentication no', installer)
        self.assertIn('AllowTcpForwarding no', installer)
        self.assertIn('ForceCommand', installer)
        self.assertIn('-NonInteractive -ExecutionPolicy RemoteSigned -File', installer)
        self.assertNotIn('Set-ExecutionPolicy', installer)
        self.assertNotIn('ExecutionPolicy Bypass', installer)
        self.assertIn('ReadAndExecute', installer)
        self.assertIn('. $wmiReadHelper', installer)
        self.assertIn("Grant-RiverLBCimv2Read -AccountSid $account.SID.Value -BackupPath (Join-Path $installRoot 'root-cimv2-original.sd')", installer)
        self.assertLess(installer.index('Set-Acl -LiteralPath $path -AclObject $acl'), installer.index('Grant-RiverLBCimv2Read -AccountSid'))
        self.assertLess(installer.index('Grant-RiverLBCimv2Read -AccountSid'), installer.index('Restart-Service sshd'))
        helper = (ROOT / 'deploy/ha/hyperv/Grant-RiverLBCimv2Read.ps1').read_text()
        self.assertIn("[System.Management.ManagementScope]::new('\\\\.\\root\\cimv2')", helper)
        self.assertIn('$scope.Options.EnablePrivileges = $true', helper)
        self.assertIn("[System.Management.ManagementPath]::new('__SystemSecurity=@')", helper)
        self.assertIn('$Object.PSBase.GetMethodParameters($MethodName)', helper)
        self.assertIn('$Object.PSBase.InvokeMethod($MethodName, $parameters, $null)', helper)
        self.assertNotIn('Get-WmiObject', helper)


def fixture_receiver(statefile):
    """Fixed command used only by the temporary OpenSSH test server."""
    if os.environ.get('SSH_ORIGINAL_COMMAND') != agent.REMOTE_COMMAND:
        return 1
    request = json.loads(sys.stdin.readline(4097))
    if request.get('version') != 1 or request.get('action') not in ('list', 'status', 'off', 'on'):
        return 1
    statefile = Path(statefile)
    state = statefile.read_text().strip()
    if request['action'] == 'list':
        result = {'machines': [{'vm_id': VM, 'name': 'fixture', 'state': state}]}
    else:
        if request.get('vm_id') != VM:
            return 1
        if request['action'] in ('on', 'off'):
            state = request['action']
            statefile.write_text(state)
        result = {'vm_id': VM, 'state': state}
    print(json.dumps({'version': 1, 'ok': True, **result}))
    return 0


def ssh_smoke():
    for command in ('sshd', 'ssh', 'ssh-keygen'):
        if not shutil.which(command):
            raise SystemExit(command + ' is required for --ssh-smoke')
    with tempfile.TemporaryDirectory(prefix='riverlb-hyperv-ssh-test-') as directory:
        root = Path(directory)
        for name in ('host', 'identity', 'wrong'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)], check=True)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        statefile = root / 'state'
        statefile.write_text('on')
        (root / 'authorized').write_text((root / 'identity.pub').read_text())
        # Fixture service has no external listener and never inherits host SSH configuration.
        (root / 'sshd_config').write_text('\n'.join([
            'Port ' + str(port), 'ListenAddress 127.0.0.1', 'HostKey ' + str(root / 'host'),
            'PidFile ' + str(root / 'sshd.pid'), 'AuthorizedKeysFile ' + str(root / 'authorized'),
            'UsePAM no', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
            'PubkeyAuthentication yes', 'PermitRootLogin yes', 'StrictModes no',
            'AllowTcpForwarding no', 'AllowAgentForwarding no', 'PermitTTY no',
            'ForceCommand /usr/bin/python3 ' + str(Path(__file__).resolve()) + ' --receiver ' + str(statefile),
        ]) + '\n')
        with (root / 'sshd.log').open('w') as log:
            process = subprocess.Popen([shutil.which('sshd'), '-D', '-e', '-f', str(root / 'sshd_config')], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError('Disposable sshd failed: ' + (root / 'sshd.log').read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise AssertionError('Disposable sshd startup timed out')
                        time.sleep(.1)
                values = dict(ipaddr='127.0.0.1', ipport=port, login=getpass.getuser(), identity_file=str(root / 'identity'),
                              ssh_host_key=agent.host_public_key((root / 'host.pub').read_text().strip()), power_timeout=5, plug=VM)
                assert agent.transport(values, 'list')['machines'][0]['vm_id'] == VM
                assert agent.confirmed_state(values, 'status', VM) == 'on'
                assert agent.confirmed_state(values, 'off', VM) == 'off'
                assert agent.confirmed_state(values, 'on', VM) == 'on'
                for invalid in (dict(values, ssh_host_key=(root / 'wrong.pub').read_text().strip()),
                                dict(values, identity_file=str(root / 'wrong'))):
                    try:
                        agent.transport(invalid, 'list')
                        raise AssertionError('Untrusted SSH connection unexpectedly succeeded')
                    except ValueError:
                        pass
                try:
                    agent.confirmed_state(values, 'off', OTHER_VM)
                    raise AssertionError('Unknown VM target unexpectedly succeeded')
                except ValueError:
                    pass
                with patch.object(agent, 'REMOTE_COMMAND', 'arbitrary-command'):
                    try:
                        agent.transport(values, 'list')
                        raise AssertionError('Arbitrary SSH command unexpectedly succeeded')
                    except ValueError:
                        pass
            finally:
                process.terminate()
                process.wait(timeout=5)
    print('PASS real OpenSSH: pinned host, key authentication, fixed receiver, read-only discovery/status, simulated power confirmation and rejection paths')


def powershell_smoke(executable):
    """Execute the real receiver using fixture Hyper-V cmdlets, never a Windows host."""
    with tempfile.TemporaryDirectory(prefix='riverlb-hyperv-powershell-test-') as directory:
        root = Path(directory)
        modules = root / 'Modules'
        module = modules / 'Hyper-V'
        module.mkdir(parents=True)
        (module / 'Hyper-V.psm1').write_text(r'''
if ($env:RIVERLB_HYPERV_FIXTURE_IMPORT_FAIL -eq '1') { throw $env:RIVERLB_HYPERV_FIXTURE_SECRET }
function New-CimSession {
    [CmdletBinding()]
    param([switch]$SkipTestConnection, [string[]]$ComputerName, [PSCredential]$Credential)
    if (!$SkipTestConnection) { throw 'Generic connection probe requires additional access' }
    if ($PSBoundParameters.ContainsKey('ComputerName') -or $PSBoundParameters.ContainsKey('Credential')) { throw 'Session must use local DCOM without remote credentials' }
    if ($env:RIVERLB_HYPERV_FIXTURE_SESSION_FAIL -eq '1') { throw $env:RIVERLB_HYPERV_FIXTURE_SECRET }
    $script:localSession = [pscustomobject]@{FixtureLocalDCOM=$true}
    'created' | Add-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_SESSION_LOG
    $script:localSession
}
function Remove-CimSession {
    [CmdletBinding()]
    param($CimSession)
    if (![object]::ReferenceEquals($CimSession, $script:localSession)) { throw 'Removed a different session' }
    'removed' | Add-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_SESSION_LOG
}
function Get-VM {
    [CmdletBinding()]
    param([Guid]$Id, [Parameter(Mandatory=$true)]$CimSession)
    if (![object]::ReferenceEquals($CimSession, $script:localSession)) { throw 'Query did not reuse the local session' }
    if ($env:RIVERLB_HYPERV_FIXTURE_VM_FAIL -eq '1') { throw $env:RIVERLB_HYPERV_FIXTURE_SECRET }
    if ($Id.ToString('D') -cne $env:RIVERLB_HYPERV_FIXTURE_ID) { throw 'Unknown VM fixture' }
    [pscustomobject]@{Id=$Id; Name='fixture'; State=(Get-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_STATE -Raw).Trim(); Session=$CimSession}
}
function Stop-VM {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($VM, [switch]$TurnOff, [switch]$Force)
    if (![object]::ReferenceEquals($VM.Session, $script:localSession)) { throw 'Power command lost its local session' }
    if ($env:RIVERLB_HYPERV_FIXTURE_POWER_FAIL -eq '1') { throw $env:RIVERLB_HYPERV_FIXTURE_SECRET }
    if (!$TurnOff -or !$Force -or $ConfirmPreference -ne 'None') { throw 'Hard power-off flags were not provided' }
    'hard-off' | Add-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_LOG
    if ($env:RIVERLB_HYPERV_FIXTURE_REFUSE_OFF -ne '1') { Set-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_STATE -Value 'Off' }
}
function Start-VM {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($VM)
    if (![object]::ReferenceEquals($VM.Session, $script:localSession)) { throw 'Power command lost its local session' }
    'on' | Add-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_LOG
    Set-Content -LiteralPath $env:RIVERLB_HYPERV_FIXTURE_STATE -Value 'Running'
}
Export-ModuleMember -Function New-CimSession,Remove-CimSession,Get-VM,Stop-VM,Start-VM
''')
        receiver = root / 'riverlb-hyperv-fence.ps1'
        receiver.write_text((ROOT / 'deploy/ha/hyperv/riverlb-hyperv-fence.ps1').read_text())
        (root / 'allowed-vms.json').write_text(json.dumps({'AllowedVMIds': [VM]}))
        state = root / 'state'
        state.write_text('Paused')
        log = root / 'power.log'
        session_log = root / 'session.log'
        environment = {**os.environ, 'PSModulePath': str(modules), 'SSH_ORIGINAL_COMMAND': agent.REMOTE_COMMAND,
                       'RIVERLB_HYPERV_FIXTURE_STATE': str(state), 'RIVERLB_HYPERV_FIXTURE_LOG': str(log),
                       'RIVERLB_HYPERV_FIXTURE_SESSION_LOG': str(session_log),
                       'RIVERLB_HYPERV_FIXTURE_ID': VM, 'RIVERLB_HYPERV_FIXTURE_SECRET': 'PRIVATE-request-and-host-error-marker',
                       'XDG_CACHE_HOME': str(root / 'cache'),
                       'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data')}
        def call(action, target=VM, raw=None, **changes):
            request = {'version': 1, 'action': action, 'timeout': 5}
            if action != 'list':
                request['vm_id'] = target
            before = session_log.read_text() if session_log.exists() else ''
            result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', str(receiver)],
                                    input=raw if raw is not None else json.dumps(request) + '\n', text=True, capture_output=True,
                                    env={**environment, **changes}, timeout=15)
            after = session_log.read_text() if session_log.exists() else ''
            result.session_events = after[len(before):].splitlines()
            assert result.session_events in ([], ['created', 'removed']), 'Local CIM session leaked or was not reused'
            return result
        def failure(result, stage):
            assert result.returncode != 0 and not result.stdout.strip(), 'Receiver accepted an invalid operation'
            expected = ('RiverLB Hyper-V fencing receiver rejected or could not confirm the operation '
                        r'\(stage=' + stage + r'; type=[A-Za-z][A-Za-z0-9]{0,95}; category=[A-Za-z]+; '
                        r'hresult=0x[0-9A-F]{8}(?:,0x[0-9A-F]{8}){0,2}\)\.\n')
            assert re.fullmatch(expected, result.stderr), result.stderr
            assert environment['RIVERLB_HYPERV_FIXTURE_SECRET'] not in result.stderr, 'Receiver exposed private error/request data'
        result = call('list')
        assert result.returncode == 0, result.stderr
        assert result.session_events == ['created', 'removed'], 'Successful list did not dispose its local CIM session'
        assert json.loads(result.stdout)['machines'][0]['vm_id'] == VM
        result = call('status')
        assert result.returncode == 0 and json.loads(result.stdout)['state'] == 'on', result.stderr
        assert not log.exists(), 'Discovery/status executed a power operation'
        result = call('off')
        assert result.returncode == 0 and json.loads(result.stdout)['state'] == 'off', result.stderr
        assert log.read_text().strip() == 'hard-off'
        result = call('on')
        assert result.returncode == 0 and json.loads(result.stdout)['state'] == 'on', result.stderr
        before = log.read_text()
        failure(call('off', OTHER_VM), 'target')
        failure(call('off', VM + ';arbitrary'), 'target')
        failure(call('list', SSH_ORIGINAL_COMMAND='arbitrary-command'), 'command')
        failure(call('list', raw='\n'), 'read')
        failure(call('list', raw='{"private": "' + environment['RIVERLB_HYPERV_FIXTURE_SECRET'] + '"\n'), 'parse')
        failure(call('list', raw=json.dumps({'version': 1, 'action': 'list', 'timeout': 5,
                                           'private': environment['RIVERLB_HYPERV_FIXTURE_SECRET']}) + '\n'), 'validate')
        settings = root / 'allowed-vms.json'
        settings.rename(root / 'settings-backup.json')
        failure(call('list'), 'settings')
        (root / 'settings-backup.json').rename(settings)
        failure(call('list', RIVERLB_HYPERV_FIXTURE_IMPORT_FAIL='1'), 'import-module')
        failure(call('list', RIVERLB_HYPERV_FIXTURE_SESSION_FAIL='1'), 'local-session')
        failure(call('list', RIVERLB_HYPERV_FIXTURE_VM_FAIL='1'), 'list-vm')
        failure(call('status', RIVERLB_HYPERV_FIXTURE_VM_FAIL='1'), 'target')
        failure(call('off', RIVERLB_HYPERV_FIXTURE_POWER_FAIL='1'), 'power')
        assert log.read_text() == before, 'Rejected requests still executed a power operation'
        state.write_text('Paused')
        result = call('off', RIVERLB_HYPERV_FIXTURE_REFUSE_OFF='1')
        failure(result, 'confirm')
        scripts = [str(path) for path in (ROOT / 'deploy/ha/hyperv').glob('*.ps1')]
        parse = '''$failed=$false; foreach($file in ($env:RIVERLB_HYPERV_PARSE_FILES|ConvertFrom-Json)){$tokens=$null;$parseErrors=$null;[System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$parseErrors)|Out-Null;if($parseErrors.Count){$failed=$true;$parseErrors|Out-String|Write-Error}};if($failed){exit 1}'''
        parsed = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', parse],
                                text=True, capture_output=True, env={**environment, 'RIVERLB_HYPERV_PARSE_FILES': json.dumps(scripts)}, timeout=15)
        assert parsed.returncode == 0, parsed.stderr
    print('PASS PowerShell: actual receiver parsing/execution, GUID allowlist, read-only discovery, hard-off confirmation and private stage diagnostics')


def installer_summary_smoke(executable):
    """Exercise the actual summary with the Windows scalar Get-VM Id contract."""
    with tempfile.TemporaryDirectory(prefix='riverlb-hyperv-summary-test-') as directory:
        root = Path(directory)
        environment = {**os.environ, 'XDG_CACHE_HOME': str(root / 'cache'),
                       'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data'),
                       'RIVERLB_INSTALLER': str(ROOT / 'deploy/ha/hyperv/Install-RiverLBFencing.ps1')}
        script = r'''
$ErrorActionPreference = 'Stop'
$script:seen = [Collections.Generic.List[string]]::new()
function Get-VM {
    [CmdletBinding()]
    param([Nullable[Guid]]$Id)
    $script:seen.Add($Id.ToString('D'))
    [pscustomobject]@{Name='fixture'; Id=$Id; State='Running'}
}
[Guid[]]$AllowedVMIds = @('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:RIVERLB_INSTALLER,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'Installer parsing failed' }
$statement=if ($env:RIVERLB_OLD_SUMMARY -eq '1') { 'Get-VM -Id $AllowedVMIds | Select-Object Name, Id, State | Format-Table -AutoSize' } else { $ast.EndBlock.Statements[-1].Extent.Text }
& ([scriptblock]::Create($statement)) | Out-Null
if ($script:seen.Count -ne 2 -or $script:seen[0] -cne $AllowedVMIds[0].ToString('D') -or $script:seen[1] -cne $AllowedVMIds[1].ToString('D')) { throw 'VM summary did not query both GUIDs individually' }
'''
        def run(**changes):
            return subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', script],
                                  text=True, capture_output=True, env={**environment, **changes}, timeout=15)
        before = run(RIVERLB_OLD_SUMMARY='1')
        assert before.returncode != 0, 'Fixture did not reproduce the Windows scalar-Guid binding failure'
        after = run()
        assert after.returncode == 0, after.stderr
    print('PASS PowerShell installer: both VM GUIDs reported using the scalar Get-VM Id contract')


def wmi_prerequisite_smoke(executable):
    """Run the real DACL algorithm with portable WMI/SID/file-ACL adapters."""
    with tempfile.TemporaryDirectory(prefix='riverlb-hyperv-wmi-test-') as directory:
        root = Path(directory)
        environment = {**os.environ, 'XDG_CACHE_HOME': str(root / 'cache'),
                       'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data')}
        result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File',
                                 str(ROOT / 'tests/hyperv_wmi_fixture.ps1'), '-HelperPath',
                                 str(ROOT / 'deploy/ha/hyperv/Grant-RiverLBCimv2Read.ps1'), '-FixtureRoot', str(root)],
                                text=True, capture_output=True, env=environment, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())


def native_wmi_prerequisite_smoke(executable):
    """Read native Windows WMI and validate input schemas without any setters."""
    result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
                             '-File', str(ROOT / 'tests/hyperv_wmi_native_fixture.ps1'), '-HelperPath',
                             str(ROOT / 'deploy/ha/hyperv/Grant-RiverLBCimv2Read.ps1')],
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout.strip())


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--receiver':
        sys.exit(fixture_receiver(sys.argv[2]))
    if sys.argv[1:] == ['--ssh-smoke']:
        ssh_smoke()
    elif len(sys.argv) == 3 and sys.argv[1] == '--powershell-smoke':
        powershell_smoke(sys.argv[2])
        installer_summary_smoke(sys.argv[2])
        wmi_prerequisite_smoke(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == '--powershell-native-wmi-smoke':
        native_wmi_prerequisite_smoke(sys.argv[2])
    else:
        unittest.main()
