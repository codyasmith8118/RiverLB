"""HA GUI helper contracts using disposable files and fixed-command fixtures."""
import base64
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('ha_deploy',str(ROOT/'deploy/ha/riverlb-ha-deploy'))
spec=importlib.util.spec_from_loader(loader.name,loader);helper=importlib.util.module_from_spec(spec);loader.exec_module(helper)
KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'\x01'*32).decode()
METADATA='''<resource-agent shortdesc="VMware REST"><longdesc>Remote power API</longdesc><parameters>
<parameter name="action" required="1"><content type="string" default="reboot"/></parameter>
<parameter name="ipaddr" deprecated="1"><content type="string"/></parameter>
<parameter name="ip" required="1" obsoletes="ipaddr"><content type="string"/><shortdesc>Server address</shortdesc></parameter>
<parameter name="passwd" deprecated="1"><content type="string"/></parameter>
<parameter name="password" obsoletes="passwd"><content type="string" default="must-not-leak"/></parameter>
<parameter name="plug" required="1"><content type="string"/></parameter>
<parameter name="ssl_secure"><content type="boolean" default="1"/></parameter>
<parameter name="auth"><content type="select"><option value="md5"/><option value="none"/></content></parameter>
<parameter name="password_script"><content type="string"/></parameter>
<parameter name="ssh_path"><content type="string"/></parameter>
<parameter name="debug_file"><content type="string"/></parameter>
<parameter name="verbose_level"><content type="integer"/></parameter>
<parameter name="api_path"><content type="string" default="/rest"/></parameter>
</parameters><actions><action name="off"/><action name="on"/><action name="reboot"/><action name="list"/><action name="status"/></actions></resource-agent>'''


class Deployment(unittest.TestCase):
    def test_sync_service_uses_the_prepared_ssh_configuration(self):
        service=(ROOT/'deploy/ha/riverlb-ha-sshd.service').read_text()
        self.assertIn('ExecStart=/usr/sbin/sshd -D -f '+str(helper.SSH_CONFIG)+'\n',service)
        deployment=(ROOT/'deploy/ha/riverlb-ha-deploy.service').read_text()
        paths=next(line.split('=',1)[1].split() for line in deployment.splitlines() if line.startswith('ReadWritePaths='))
        self.assertIn('/var/lib/selinux',paths)
        self.assertIn('-/sys/fs/selinux',paths)

    def test_deployment_sandbox_handles_fresh_and_prepared_pcsd_state(self):
        deployment=(ROOT/'deploy/ha/riverlb-ha-deploy.service').read_text()
        paths=next(line.split('=',1)[1].split() for line in deployment.splitlines() if line.startswith('ReadWritePaths='))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            # A fresh image has the base SELinux state and the deployment
            # tmpfiles directory, but pcsd has not created its own state yet.
            for path in ('etc','var/lib/selinux','run/riverlb-ha-deploy'):
                (root/path).mkdir(parents=True,exist_ok=True)
            pcsd=root/'var/lib/pcsd'
            self.assertFalse(pcsd.exists())
            missing=[path for path in paths if not path.startswith('-') and not (root/path.lstrip('/')).exists()]
            self.assertEqual(missing,[], 'Missing mandatory sandbox paths prevent the preparation helper from starting')
            # The vendor service creates the state outside this helper's
            # namespace. A later authentication job must still write there.
            pcsd.mkdir()
            self.assertIn(pcsd,[root/path.lstrip('-/') for path in paths])
            self.assertNotIn(root/'var/lib',[root/path.lstrip('-/') for path in paths])
        self.assertIn('ProtectSystem=strict\n',deployment)

    def test_keys_require_plain_ed25519_and_matching_fingerprint(self):
        self.assertEqual(helper.public_key(KEY),KEY)
        for bad in ('command="id" '+KEY,KEY+'\n'+KEY,'ssh-ed25519 ;echo secret','ssh-rsa AAAA'):
            with self.assertRaises(ValueError):helper.public_key(bad)

    def test_trust_is_private_pinned_and_forced_receive_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);group={'node_id':'a','peer_id':'b','local_address':'192.0.2.10','peer_address':'192.0.2.20'}
            with patch.object(helper,'ROOT',root),patch.object(helper,'AUTHORIZED',root/'authorized'),patch.object(helper,'COROSYNC',root/'corosync'),patch.object(helper,'group_settings',return_value=group),patch.object(helper,'run',return_value=''):
                request={'action':'trust','peer_sync_key':KEY,'peer_host_key':KEY,'peer_host_fingerprint':helper.fingerprint(KEY)}
                helper.execute(request)
                content=(root/'authorized').read_text()
                self.assertTrue(content.startswith('restrict,command="/usr/bin/riverlb ha --socket /run/riverlb/ha.sock receive" '))
                self.assertEqual((root/'authorized').stat().st_mode&0o777,0o600)
                self.assertEqual((root/'ha-known-hosts').read_text(),'[192.0.2.20]:2223 '+KEY+'\n')
                request['peer_host_fingerprint']='SHA256:wrong'
                with self.assertRaisesRegex(ValueError,'fingerprint'):helper.execute(request)
                (root/'corosync').touch()
                with self.assertRaisesRegex(ValueError,'Existing cluster'):helper.execute(request)

    def test_preparation_sets_password_over_stdin_and_does_not_reload_firewall(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'ha.json').write_text('{}');calls=[]
            group={'node_id':'a','peer_id':'b','local_address':'192.0.2.10','peer_address':'192.0.2.20'}
            def run(*args,input=None):
                calls.append((args,input))
                if args[0].endswith('ip'):return json.dumps([{'ifname':'eth0','addr_info':[{'local':'192.0.2.10'}]}])
                if args[0].endswith('ssh-keygen') and '-y' in args:return KEY
                if args[0].endswith('semanage'):return 'ssh_port_t tcp 22, 2223'
                return ''
            with patch.object(helper,'ROOT',root),patch.object(helper,'HOST',root/'host'),patch.object(helper,'AUTHORIZED',root/'authorized'),patch.object(helper,'SSH_CONFIG',root/'sshd_config'),patch.object(helper,'COROSYNC',root/'corosync'),patch.object(helper,'run',side_effect=run),patch.object(helper.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'management\n','')):
                helper.prepare({'cluster_password':'ephemeral-cluster-password'},group)
                self.assertTrue(any(args[0].endswith('chpasswd') and data=='hacluster:ephemeral-cluster-password\n' for args,data in calls))
                self.assertTrue(all('ephemeral-cluster-password' not in str(args) for args,_ in calls))
                self.assertFalse(any('--reload' in args for args,_ in calls))
                config=(root/'sshd_config').read_text()
                self.assertIn('PasswordAuthentication no',config);self.assertIn('PermitRootLogin forced-commands-only',config)
                self.assertEqual(json.loads((root/'ha.json').read_text())['ssh_port'],2223)
                identity=json.loads((root/'ha-deployment-identity.json').read_text());self.assertEqual(identity['host_fingerprint'],helper.fingerprint(KEY))

    def test_authentication_keeps_password_out_of_command_arguments(self):
        group={'node_id':'a','peer_id':'b','local_address':'192.0.2.10','peer_address':'192.0.2.20'}
        with patch.object(helper,'group_settings',return_value=group),patch.object(helper,'run',return_value='') as run:
            helper.execute({'action':'authenticate','cluster_password':'private-cluster-password'})
            self.assertNotIn('private-cluster-password',str(run.call_args.args))
            self.assertEqual(run.call_args.kwargs['input'],'private-cluster-password\n')
        with self.assertRaises(ValueError):helper.password({'cluster_password':'password\ninjected'})

    def test_fencing_credentials_use_stdin_and_existing_resources_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'corosync').touch()
            group={'node_id':'a','peer_id':'b','local_address':'192.0.2.10','peer_address':'192.0.2.20'}
            request={'action':'fence','fence_resource':'fence-a','fence_agent':'fence_ipmilan','fence_parameters':{'pcmk_host_list':'a','passwd':'private-fence-password'}}
            original=Path.is_file
            with patch.object(helper,'ROOT',root),patch.object(helper,'COROSYNC',root/'corosync'),patch.object(helper,'group_settings',return_value=group),patch.object(helper,'agent_metadata',side_effect=lambda name: helper.parse_metadata(name,METADATA) if name!='fence_dummy' else helper.agent_path(name)),patch.object(Path,'is_file',lambda p: True if str(p)=='/usr/sbin/fence_ipmilan' else original(p)),patch.object(helper,'run',return_value='<cib><configuration><resources/></configuration></cib>') as run:
                helper.execute(request)
                create=run.call_args
                self.assertIn('--xml-pipe',create.args)
                self.assertNotIn('private-fence-password',str(create.args))
                self.assertIn('private-fence-password',create.kwargs['input'])
                self.assertEqual(json.loads((root/'ha.group.json').read_text())['fencing_resources'],['fence-a'])
                run.return_value='<cib><configuration><resources><primitive id="fence-a"/></resources></configuration></cib>'
                with self.assertRaisesRegex(ValueError,'already exists'):helper.execute(request)
                request['fence_agent']='fence_dummy'
                with self.assertRaisesRegex(ValueError,'power-fencing'):helper.execute(request)

    def test_catalog_uses_metadata_types_aliases_and_real_available_agents(self):
        metadata=helper.parse_metadata('fence_vmware_rest',METADATA)
        fields={field['name']:field for field in metadata['parameters']}
        self.assertEqual(metadata['platform'],'vmware');self.assertEqual(metadata['target_parameter'],'plug')
        self.assertEqual(fields['ip']['aliases'],['ipaddr']);self.assertTrue(fields['ip']['required'])
        self.assertEqual(fields['password']['type'],'password');self.assertEqual(fields['password']['default'],'')
        self.assertEqual(fields['auth']['choices'],['md5','none']);self.assertEqual(fields['ssl_secure']['type'],'boolean')
        self.assertTrue({'password_script','ssh_path','debug_file','verbose_level','action','ipaddr','passwd'}.isdisjoint(fields))
        self.assertIn('api_path',fields)
        with self.assertRaisesRegex(ValueError,'power fencing'):helper.parse_metadata('fence_bad','<resource-agent><actions><action name="monitor"/></actions></resource-agent>')
        with self.assertRaises(ValueError):helper.parse_metadata('fence_bad','<!DOCTYPE resource-agent [<!ENTITY bad "x">]><resource-agent/>')
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'fence_vmware_rest';path.touch();path.chmod(0o755)
            with patch.object(helper,'AGENTS',Path(temp)),patch.object(helper,'agent_metadata',return_value=metadata):
                catalog=helper.fencing_catalog()
                platforms={entry['id']:entry for entry in catalog['platforms']}
                self.assertTrue(platforms['vmware']['available']);self.assertFalse(platforms['hyperv']['available'])
                self.assertEqual(platforms['vmware']['agents'],['fence_vmware_rest'])

    def test_probe_is_read_only_keeps_secrets_off_argv_and_uses_explicit_mapping(self):
        group={'node_id':'a','peer_id':'b'}
        metadata=helper.parse_metadata('fence_vmware_rest',METADATA)
        request={'fence_agent':'fence_vmware_rest','fence_parameters':{'password':'private-password','ip':'192.0.2.5','pcmk_host_map':'a:vm-a;b:vm-b'}}
        with patch.object(helper,'agent_metadata',return_value=metadata),patch.object(helper,'agent_path',return_value=Path('/usr/sbin/fence_vmware_rest')),patch.object(helper.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'vm-a,First appliance\nvm-b,Second appliance\n','')) as run:
            result=helper.fence_probe(request,group)
            self.assertEqual(result['targets'],[{'id':'vm-a','label':'First appliance'},{'id':'vm-b','label':'Second appliance'}])
            self.assertEqual(run.call_args.args[0],['/usr/sbin/fence_vmware_rest'])
            self.assertIn('password=private-password\n',run.call_args.kwargs['input']);self.assertIn('action=list\n',run.call_args.kwargs['input'])
            self.assertNotIn('pcmk_',run.call_args.kwargs['input'])
            request.update(fence_probe_action='status',fence_target='b')
            run.return_value=subprocess.CompletedProcess([],2,'Status: OFF','')
            result=helper.fence_probe(request,group)
            self.assertEqual(result['power'],'off');self.assertEqual(result['target'],'b')
            self.assertIn('plug=vm-b\n',run.call_args.kwargs['input']);self.assertIn('action=status\n',run.call_args.kwargs['input'])
            for operation in ('off','on','reboot','monitor','metadata'):
                request['fence_probe_action']=operation
                with self.assertRaisesRegex(ValueError,'read-only'):helper.fence_probe(request,group)
            request['fence_probe_action']='list';run.return_value=subprocess.CompletedProcess([],1,'password=private-password','private-password')
            with self.assertRaises(ValueError) as error:helper.fence_probe(request,group)
            self.assertNotIn('private-password',str(error.exception))

    def test_advanced_parameters_cannot_execute_local_commands_or_inject_actions(self):
        metadata=helper.parse_metadata('fence_vmware_rest',METADATA)
        with patch.object(helper,'agent_metadata',return_value=metadata):
            for key,value in [('password_script','id'),('ssh_path','/bin/sh'),('debug_file','/etc/passwd'),('verbose_level','99'),('action','off'),('password','private\naction=off'),('unknown','value'),('pcmk_host_check','none'),('plug','override-mapping'),('uuid','override-mapping'),('skip_race_check','1'),('disable_timeout','1'),('network_fencing','1')]:
                with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{key:value}})
            helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'passwd':'private','api_path':'/api','pcmk_host_check':'static-list'}})
        group={'node_id':'a','peer_id':'b'}
        for mapping in ('a:same;b:same','a:vm-a;a:vm-b','outside:vm-x','a:','a:vm-a;bad'):
            with self.assertRaises(ValueError):helper.fence_mapping({'pcmk_host_map':mapping},group)

    def test_credential_file_parameters_reject_unowned_or_public_files(self):
        metadata=helper.parse_metadata('fence_vmware_rest',METADATA)
        metadata['parameters'].append({'name':'identity_file','aliases':[],'type':'string'})
        with tempfile.TemporaryDirectory() as temp,patch.object(helper,'agent_metadata',return_value=metadata),patch.object(helper,'ROOT',Path(temp)):
            path=Path(temp)/'identity';path.write_text('secret');path.chmod(0o644)
            with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'identity_file':str(path)}})
            with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'identity_file':'/etc/passwd'}})

    def test_fixed_controller_cannot_claim_to_protect_two_appliances(self):
        document=METADATA.replace('</parameters>','<parameter name="port_as_ip"><content type="boolean"/></parameter></parameters>')
        metadata=helper.parse_metadata('fence_ipmilan',document)
        self.assertIsNone(metadata['target_parameter'])
        fields={field['name']:field for field in metadata['parameters']}
        self.assertTrue(fields['plug']['hidden']);self.assertNotIn('port_as_ip',fields)
        group={'node_id':'a','peer_id':'b'}
        with self.assertRaisesRegex(ValueError,'one appliance'):
            helper.validate_fence_mapping(metadata,{'pcmk_host_list':'a b'},group)
        self.assertEqual(helper.validate_fence_mapping(metadata,{'pcmk_host_list':'a'},group)[0],{'a'})

    def test_false_flags_cannot_enable_insecure_tls_and_aliases_are_canonical(self):
        document=METADATA.replace('</parameters>','<parameter name="ssl_insecure"><content type="boolean"/></parameter></parameters>')
        metadata=helper.parse_metadata('fence_vmware_rest',document)
        with patch.object(helper,'agent_metadata',return_value=metadata):
            _,parameters=helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'ipaddr':'192.0.2.5','passwd':'private','ssl_secure':'true','ssl_insecure':'0'}})
            self.assertEqual(parameters,{'ip':'192.0.2.5','password':'private','ssl_secure':'1','pcmk_host_argument':'plug'})
            with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'passwd':'first','password':'second'}})
            with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_vmware_rest','fence_parameters':{'ssl_insecure':'sometimes'}})

    def test_alternate_target_field_cannot_override_cluster_mapping(self):
        document=METADATA.replace('</parameters>','<parameter name="uuid"><content type="string"/></parameter></parameters>')
        metadata=helper.parse_metadata('fence_riverlb_openstack',document)
        fields={field['name']:field for field in metadata['parameters']}
        self.assertEqual(metadata['target_parameter'],'plug');self.assertTrue(fields['uuid']['hidden'])
        with patch.object(helper,'agent_metadata',return_value=metadata):
            with self.assertRaises(ValueError):helper.fence_parameters({'fence_agent':'fence_riverlb_openstack','fence_parameters':{'uuid':'a-different-machine','pcmk_host_map':'a:vm-a;b:vm-b'}})

    def test_failed_commands_do_not_echo_credentials(self):
        with patch.object(helper.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'secret','password=secret')):
            with self.assertRaises(ValueError) as error:helper.run('/usr/sbin/chpasswd',input='secret')
            self.assertNotIn('secret',str(error.exception))


if __name__=='__main__':unittest.main()
