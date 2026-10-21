"""OCF, ownership authority and platform-neutral cluster contracts."""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def load(name):
    loader=importlib.machinery.SourceFileLoader(name,str(ROOT/'deploy/ha'/name))
    spec=importlib.util.spec_from_loader(name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module


class Agents(unittest.TestCase):
    def test_pcs_authentication_and_cluster_actions_share_the_pcsd_state_directory(self):
        cluster=load('riverlb-cluster');deployment=load('riverlb-ha-deploy')
        inherited={'STATE_DIRECTORY':'/var/lib/riverlb', 'LOGS_DIRECTORY':'/var/log/riverlb',
                   'PATH':'/usr/sbin:/usr/bin', 'LANG':'C.UTF-8'}
        with patch.dict(os.environ,inherited,clear=True):
            with patch.object(cluster.subprocess,'check_output',return_value=b'') as command:
                cluster.run('cluster','setup','pair')
                cluster_environment=command.call_args.kwargs['env']
            with patch.object(deployment.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as command:
                deployment.run('/usr/sbin/pcs','host','auth','a','b',input='private-password\n')
                authentication_environment=command.call_args.kwargs['env']
                self.assertEqual(command.call_args.kwargs['input'],'private-password\n')
            for environment in (cluster_environment,authentication_environment):
                # PCS 0.12 reads STATE_DIRECTORY for its known-hosts location.
                # Without the RiverLB override it uses the vendor pcsd path.
                self.assertEqual(environment.get('STATE_DIRECTORY','/var/lib/pcsd'),'/var/lib/pcsd')
                self.assertEqual(environment.get('LOGS_DIRECTORY','/var/log/pcsd'),'/var/log/pcsd')
                self.assertEqual(environment['LANG'],'C.UTF-8')
            self.assertEqual(dict(os.environ),inherited)
            with patch.object(deployment.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as command:
                deployment.run('/usr/bin/systemctl','start','pcsd.service')
                self.assertEqual(command.call_args.kwargs['env'],inherited)

    def test_authority_requires_quorum_fencing_and_single_owner(self):
        module=load('riverlb-authority')
        def cib(fence='fence_ipmilan',enabled='true',policy='stop'):
            return ET.fromstring(f'<cib><configuration><crm_config><cluster_property_set><nvpair name="stonith-enabled" value="{enabled}"/><nvpair name="no-quorum-policy" value="{policy}"/></cluster_property_set></crm_config><resources><primitive class="stonith" type="{fence}"/></resources></configuration></cib>')
        def status(quorum='true',nodes=('riverlb-a',)):
            return ET.fromstring('<pacemaker-result><summary><current_dc with_quorum="'+quorum+'"/></summary><resources><resource id="riverlb-traffic" active="true" role="Started">'+''.join('<node name="'+n+'"/>'for n in nodes)+'</resource></resources></pacemaker-result>')
        result=module.authority(cib(),status(),'riverlb-traffic');self.assertEqual(result,dict(quorate=True,fencing=True,owner='riverlb-a'))
        self.assertFalse(module.authority(cib(),status('false'),'riverlb-traffic')['quorate'])
        for options in [dict(fence='fence_dummy'),dict(enabled='false'),dict(policy='ignore')]:
            self.assertFalse(module.authority(cib(**options),status(),'riverlb-traffic')['fencing'])
        for agent in module.NON_POWER_AGENTS:
            self.assertFalse(module.authority(cib(fence=agent),status(),'riverlb-traffic')['fencing'],agent)
        with self.assertRaises(ValueError):module.authority(cib(),status(nodes=('riverlb-a','riverlb-b')),'riverlb-traffic')
        with self.assertRaises(ValueError):module.authority(cib(),status(nodes=()),'riverlb-traffic')

    def test_starting_resource_retains_its_single_identified_owner(self):
        module=load('riverlb-authority')
        cib=ET.fromstring('<cib><configuration><crm_config><cluster_property_set><nvpair name="no-quorum-policy" value="stop"/></cluster_property_set></crm_config><resources><primitive class="stonith" type="fence_riverlb_hyperv"/></resources></configuration></cib>')
        def status(role='Starting',names=('riverlb-a',),active='true'):
            nodes=''.join('<node name="'+name+'"/>' for name in names)
            return ET.fromstring('<pacemaker-result><summary><current_dc with_quorum="true"/></summary><resources><resource id="riverlb-traffic" active="'+active+'" role="'+role+'">'+nodes+'</resource></resources></pacemaker-result>')
        for name in ('riverlb-a','riverlb-b'):
            self.assertEqual(module.authority(cib,status(names=(name,)),'riverlb-traffic')['owner'],name)
        for names in ((),('riverlb-a','riverlb-b')):
            with self.assertRaises(ValueError):module.authority(cib,status(names=names),'riverlb-traffic')
        with self.assertRaises(ValueError):
            module.authority(cib,ET.fromstring('<pacemaker-result><resources><resource id="riverlb-traffic" active="true" role="Starting"><node/></resource></resources></pacemaker-result>'),'riverlb-traffic')
        with self.assertRaises(ValueError):module.authority(cib,status(role='Unknown'),'riverlb-traffic')
        self.assertIsNone(module.authority(cib,status(active='false'),'riverlb-traffic')['owner'])

    def test_two_node_mode_requires_wait_for_all_and_complete_fencing(self):
        module=load('riverlb-authority')
        values="quorum.two_node (u8) = 1\nquorum.wait_for_all (u8) = 1\nnodelist.node.0.name (str) = a\nnodelist.node.1.name (str) = b"
        cib=ET.fromstring('<cib><configuration><resources><primitive class="stonith"><instance_attributes><nvpair name="pcmk_host_list" value="a b"/></instance_attributes></primitive></resources></configuration></cib>')
        module.validate_two_node(values,cib)
        for bad in [values.replace('two_node (u8) = 1','two_node (u8) = 0'),values.replace('wait_for_all (u8) = 1','wait_for_all (u8) = 0'),values+'\nnodelist.node.2.name (str) = c']:
            with self.assertRaises(ValueError):module.validate_two_node(bad,cib)
        cib.find('.//nvpair').set('value','a')
        with self.assertRaises(ValueError):module.validate_two_node(values,cib)

    def test_cluster_moves_and_setup_use_fixed_commands_without_force(self):
        module=load('riverlb-cluster')
        group=dict(cluster_id='lb',node_id='a',peer_id='b',local_address='192.0.2.10',peer_address='192.0.2.20',fencing_resources=['fence-platform'])
        cmap=b'quorum.two_node (u8) = 1\nquorum.wait_for_all (u8) = 1\nnodelist.node.0.name (str) = a\nnodelist.node.1.name (str) = b'
        with patch.object(module.subprocess,'check_output',return_value=cmap),patch.object(module,'run',return_value='')as mock:
            module.execute(dict(action='setup',group=group))
            calls=[c.args for c in mock.call_args_list]
            self.assertIn(('quorum','update','wait_for_all=1'),calls)
            self.assertLess(calls.index(('quorum','update','wait_for_all=1')),
                            calls.index(('cluster','start','--all')))
            self.assertLess(calls.index(('cluster','start','--all')),
                            calls.index(('cluster','enable','--all')))
            self.assertNotIn('two_node=1',[arg for c in calls for arg in c])
            self.assertNotIn('--force',[arg for c in calls for arg in c])
            self.assertTrue(any(call[:2]==('property','set') and 'stonith-timeout=180s' in call for call in calls),
                            'Fresh clusters need the qualified fencing timeout, including transport and fencing delay')
            self.assertTrue(any('--disabled' in call for call in calls))
            mock.reset_mock();module.execute(dict(action='failover',group=group,target='b'))
            mock.assert_called_once_with('resource','move','riverlb-traffic','b','--wait=120')
        with self.assertRaises(ValueError):module.execute(dict(action='failover',group=group,target='third-node'))

    def test_cluster_setup_checks_effective_two_node_quorum_before_creating_resources(self):
        module=load('riverlb-cluster')
        group=dict(cluster_id='lb',node_id='a',peer_id='b',local_address='192.0.2.10',peer_address='192.0.2.20')
        values='quorum.two_node (u8) = 1\nquorum.wait_for_all (u8) = 1\nnodelist.node.0.name (str) = a\nnodelist.node.1.name (str) = b'
        for bad in (values.replace('two_node (u8) = 1','two_node (u8) = 0'),
                    values.replace('wait_for_all (u8) = 1','wait_for_all (u8) = 0'),
                    values.replace('quorum.wait_for_all (u8) = 1\n',''),
                    values.replace('name (str) = b','name (str) = c'),
                    values+'\nnodelist.node.2.name (str) = c'):
            with self.subTest(cmap=bad),patch.object(module.subprocess,'check_output',return_value=bad.encode()),patch.object(module,'run',return_value='') as command:
                with self.assertRaisesRegex(ValueError,'two-node quorum'):
                    module.execute(dict(action='setup',group=group))
                self.assertFalse(any(call.args[:2]==('resource','create') for call in command.call_args_list))

    def test_ocf_never_reports_unreachable_daemon_as_stopped(self):
        module=load('riverlb-traffic')
        ET.fromstring(module.METADATA)
        with patch.object(module,'call',return_value=dict(role='standby')):
            self.assertEqual(module.main('monitor'),7);self.assertEqual(module.main('stop'),0)
        with patch.object(module,'call',return_value=dict(role='active',data_ready=True)):
            self.assertEqual(module.main('monitor'),0);self.assertEqual(module.main('start'),0)
        with patch.object(module,'call',return_value=dict(role='active',data_ready=False)):
            self.assertEqual(module.main('monitor'),1);self.assertEqual(module.main('start'),1)
        with patch.object(module,'call',side_effect=OSError('unreachable')):
            with self.assertRaises(OSError):module.main('stop')
        self.assertEqual(module.main('unknown'),3)

    def test_enable_requires_real_fencing_for_both_nodes(self):
        module=load('riverlb-cluster')
        group=dict(node_id='a',peer_id='b',fencing_resources=['fence-platform'])
        cib=b'<cib><configuration><resources><primitive id="fence-platform" class="stonith" type="fence_ipmilan"><instance_attributes><nvpair name="pcmk_host_list" value="a b"/></instance_attributes></primitive></resources></configuration></cib>'
        with patch.object(module.subprocess,'check_output',return_value=cib):module.verify_fencing(group)
        self.assertEqual(module.NON_POWER_AGENTS,load('riverlb-authority').NON_POWER_AGENTS)
        for bad in [cib.replace(b'a b',b'a'),*(cib.replace(b'fence_ipmilan',agent.encode()) for agent in module.NON_POWER_AGENTS)]:
            with patch.object(module.subprocess,'check_output',return_value=bad):
                with self.assertRaises(ValueError):module.verify_fencing(group)
        with self.assertRaises(ValueError):module.verify_fencing(dict(group,fencing_resources=[]))


if __name__=='__main__':unittest.main()
