"""Inventory completeness, original-byte validation and provenance rejection tests.

Synthetic packages test the contracts; they are never guest/signature evidence.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import software_inventory as inv
import software_provenance as prov
from artifact_inventory import rpm_payload, verify_application_archive, verify_embedded_packages, os_catalog
from package_inventory import FIELDS, parse_rpm_query, validate_inventory
spec = importlib.util.spec_from_file_location('application_packager', ROOT / 'scripts/package-application.py')
packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
spec = importlib.util.spec_from_file_location('qualification_contract', ROOT / 'scripts/qualify-appliance.py')
qualification = importlib.util.module_from_spec(spec); spec.loader.exec_module(qualification)


class InventoryTests(unittest.TestCase):
    def test_rpm_cpio_hardlinks_resolve_actual_content_and_retained_alias(self):
        def member(name, data, inode=7):
            name = name.encode() + b'\0'
            fields = [inode, 0o100644, 0, 0, 2, 0, len(data), 0, 1, 0, 0, len(name), 0]
            header = b'070701' + ''.join(f'{v:08x}' for v in fields).encode()
            return header + name + b'\0' * (-(110 + len(name)) % 4) + data + b'\0' * (-len(data) % 4)
        path = self.root / 'payload.cpio'
        original_popen = subprocess.Popen
        def decode(*args, **kwargs):
            return original_popen(['cat', str(path)], **kwargs)
        payload = b'original linked bytes'
        path.write_bytes(member('./first', b'') + member('./last', payload) + member('TRAILER!!!', b'', 99))
        with patch('artifact_inventory.subprocess.Popen', side_effect=decode):
            files, kept = rpm_payload('synthetic.rpm', lambda name: name == 'first')
        for entry in files.values():
            self.assertEqual(entry['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(entry['size'], len(payload))
        self.assertEqual(kept, {'first': payload})
        path.write_bytes(member('./first', b'conflict') + member('./last', payload) + member('TRAILER!!!', b'', 99))
        with patch('artifact_inventory.subprocess.Popen', side_effect=decode), self.assertRaisesRegex(ValueError, 'Conflicting RPM hardlink'):
            rpm_payload('synthetic.rpm')

    def test_ubuntu_legacy_schema_resolver_is_offline(self):
        from types import SimpleNamespace
        with patch('inspect.signature', return_value=SimpleNamespace(parameters={})):
            # Exercise the older Ubuntu system-jsonschema API as well.
            minimal = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                       'components': [{'type': 'library', 'name': 'fixture',
                                       'licenses': [{'license': {'id': 'MIT'}}]}]}
            prov.validate_schema(ROOT, minimal)
            with self.assertRaises(Exception):
                prov.validate_schema(ROOT, {**minimal, 'bomFormat': 'invalid'})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.inputs = Path(self.temp.name) / 'inputs'
        self.output = Path(self.temp.name) / 'software'
        for name in ('packaging/third-party/cargo', 'deploy/ha/vendor'):
            (self.root / name).mkdir(parents=True)
        for name in ('cargo-vendor/foo-1.0', 'wheels'):
            (self.inputs / name).mkdir(parents=True)
        shutil.copytree(ROOT / 'deploy/ha/vendor/fence-agents', self.root / 'deploy/ha/vendor/fence-agents')
        for helper in ('riverlb-authority', 'riverlb-cluster', 'riverlb-traffic', 'riverlb-ha.service'):
            (self.root / 'deploy/ha' / helper).write_text('public helper\n')
        (self.root / 'Cargo.toml').write_text('[package]\nname="riverlb"\nversion="1.0.1"\nlicense="MIT"\n')
        (self.root / 'LICENSE').write_text('public first-party license\n')
        (self.root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="riverlb"\nversion="1.0.1"\n[[package]]\nname="foo"\nversion="1.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+'1'*64+'"\n')
        crate = self.inputs / 'cargo-vendor/foo-1.0'
        (crate / 'Cargo.toml').write_text('[package]\nname="foo"\nversion="1.0"\nlicense="MIT"\n')
        (crate / 'LICENSE').write_text('public dependency copyright and license\n')
        (crate / '.cargo-checksum.json').write_text(json.dumps({'package':'1'*64,'files':{}}))
        (self.root / 'packaging/third-party/cargo/index.json').write_text('{"schema":1,"crates":[]}')
        wheel = self.inputs / 'wheels/example_sdk-1.0-py3-none-any.whl'
        root_metadata = 'example_sdk-1.0.dist-info/METADATA'
        nested_metadata = 'example_sdk/_vendor/tool-2.0.dist-info/METADATA'
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr(root_metadata, 'Name: example-sdk\nVersion: 1.0\nLicense: MIT\n')
            archive.writestr('example_sdk-1.0.dist-info/LICENSE', 'SDK copyright/license\n')
            archive.writestr(nested_metadata, 'Name: vendored-tool\nVersion: 2.0\nLicense: Apache-2.0\n')
            archive.writestr('example_sdk/_vendor/tool-2.0.dist-info/licenses/LICENSE', 'embedded tool license\n')
            archive.writestr('example_sdk/_vendor/tool-2.0.dist-info/RECORD', 'tool-2.0.dist-info/METADATA,,\ntool/__init__.py,,\n')
            archive.writestr('example_sdk/_vendor/tool/__init__.py', 'public embedded code\n')
        digest = inv.sha256(wheel)
        (self.root / 'deploy/ha/vendor/openstack-requirements.txt').write_text('example-sdk==1.0 --hash=sha256:'+digest+'\n')
        packages = {}
        for name, version, path in [('example-sdk','1.0',root_metadata),('vendored-tool','2.0',nested_metadata)]:
            packages[name+'=='+version]={'name':name,'version':version,'source_url':'https://files.pythonhosted.org/'+name+'.tar.gz',
                'source_sha256':'2'*64,'origins':[{'wheel':wheel.name,'wheel_sha256':digest,'metadata_path':path}]}
        (self.root / 'packaging/third-party/python-sources.lock.json').write_bytes(inv.canonical({'schema':1,'packages':packages}))
        self.metadata={'packages':[{'id':'app','name':'riverlb','version':'1.0.1'},{'id':'foo','name':'foo','version':'1.0'}],
            'resolve':{'root':'app','nodes':[{'id':'app','deps':[{'pkg':'foo'}]},{'id':'foo','deps':[]}]}}
        inventory={'files':{str(p.relative_to(self.inputs)):{'sha256':inv.sha256(p)} for p in self.inputs.rglob('*') if p.is_file()}}
        (self.inputs / 'inventory.json').write_bytes(inv.canonical(inventory))
        self.lock={'schema':1,'sha256':'3'*64,'inventory_sha256':inv.sha256(self.inputs/'inventory.json'),
                   'url':'https://example.test/retained-inputs.tar.gz','images':{'builder':{'id':'sha256:'+'4'*64},'tools':{'id':'sha256:'+'5'*64}}}
        (self.root / 'packaging/build-inputs.lock.json').write_bytes(inv.canonical(self.lock))
        self.manifest={'version':'1.0.1','commit':'a'*40,'dirty':False,'source_date_epoch':1,'rust':'1.92.0',
                       'build_inputs':self.lock,'cargo_lock_sha256':inv.sha256(self.root/'Cargo.lock')}
        self.compiler='rustc 1.92.0 (fixture 2026-01-01)\nhost: x86_64-unknown-linux-gnu\n'
        self.binary=self.root/'riverlb'; self.binary.write_bytes(b'public compiled binary fixture')

    def generate(self):
        return inv.source_inventory(self.root,self.inputs,self.metadata,self.binary,self.manifest)

    def test_original_locks_include_embedded_distributions_and_schema_validates(self):
        inventory,document=self.generate()
        self.assertEqual(len(inventory.components),5)
        self.assertTrue(any(c['name']=='vendored-tool' for c in inventory.components.values()))
        self.assertTrue(any(c['name']=='foo' for c in inventory.components.values()))
        prov.validate_schema(ROOT,document)
        self.assertEqual(set(inventory.license_records),set(inventory.components))
        self.assertTrue(all(c['notices'] for c in inventory.license_records.values()))

    def test_generation_is_byte_reproducible(self):
        a,doc=self.generate();a.write(self.output,doc)
        original={p.name: p.read_bytes() for p in self.output.iterdir()}
        b,doc=self.generate();b.write(self.output,doc)
        self.assertEqual(original,{p.name:p.read_bytes() for p in self.output.iterdir()})

    def test_retained_license_tampering_is_rejected_against_input_hashes(self):
        (self.inputs/'cargo-vendor/foo-1.0/LICENSE').write_text('altered')
        with self.assertRaisesRegex(ValueError,'Retained source bytes changed'):
            self.generate()

    def test_missing_locked_crate_is_rejected(self):
        inventory=inv.Inventory()
        with patch.object(inv.Inventory,'notice'):
            shutil.rmtree(self.inputs/'cargo-vendor/foo-1.0')
            with self.assertRaisesRegex(ValueError,'Cargo.lock'):
                inventory.cargo(self.root,self.inputs,self.metadata,'root')

    def test_missing_embedded_distribution_source_is_rejected(self):
        path=self.root/'packaging/third-party/python-sources.lock.json'
        value=json.loads(path.read_text());del value['packages']['vendored-tool==2.0'];path.write_bytes(inv.canonical(value))
        with self.assertRaisesRegex(ValueError,'embedded-distribution'):
            self.generate()

    def test_missing_vendor_license_is_rejected(self):
        (self.root/'deploy/ha/vendor/fence-agents/COPYING.applications').unlink()
        with self.assertRaisesRegex(ValueError,'license absent'):
            self.generate()

    def test_unknown_license_does_not_become_an_asserted_license(self):
        with self.assertRaises(ValueError):
            inv.component('pypi','foo','1','0'*64,'UNKNOWN','https://example.test/foo')

    def test_unsafe_notice_paths_are_rejected(self):
        for path in ('../key','/etc/key','a/../../key','a\\key','a\nkey'):
            with self.subTest(path=path),self.assertRaises(ValueError):
                inv.relative(path)

    def test_application_archive_matches_original_binary_sources_and_inventory(self):
        inventory,document=self.generate();inventory.write(self.output,document)
        (self.root/'private.key').write_text('must never ship')
        path=packager.package(self.root,self.binary,self.output,self.manifest,self.compiler,self.root/'archives')
        members=verify_application_archive(path,self.root,self.output,self.manifest,self.compiler,inv.sha256(self.binary))
        self.assertNotIn('private.key',members)
        self.assertIn('software/notices.tar.gz',members)
        self.binary.write_bytes(b'altered executable')
        with self.assertRaisesRegex(ValueError,'differs'):
            verify_application_archive(path,self.root,self.output,self.manifest,self.compiler,inv.sha256(self.binary))

    def test_failed_archive_compression_preserves_previous_candidate(self):
        inventory,document=self.generate();inventory.write(self.output,document)
        path=packager.package(self.root,self.binary,self.output,self.manifest,self.compiler,self.root/'archives')
        before=path.read_bytes()
        with patch.object(packager.gzip,'GzipFile',side_effect=OSError('compression failure')):
            with self.assertRaises(OSError):
                packager.package(self.root,self.binary,self.output,self.manifest,self.compiler,self.root/'archives')
        self.assertEqual(path.read_bytes(),before)
        self.assertFalse(list(path.parent.glob('*.partial')))

    def test_iso_package_set_rejects_missing_extra_and_changed_bytes(self):
        packages=self.root/'rpms';packages.mkdir();(packages/'ha-dependencies').mkdir()
        (packages/'riverlb.rpm').write_bytes(b'candidate')
        def tar(entries):
            path=self.root/'payload.tar'
            with tarfile.open(path,'w') as archive:
                for name,data in entries.items():
                    info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
            return path
        verify_embedded_packages(tar({'./riverlb.rpm':b'candidate'}),packages)
        for entries in ({},{'./riverlb.rpm':b'altered'},{'./riverlb.rpm':b'candidate','./rogue.rpm':b'x'}):
            with self.assertRaises(ValueError):verify_embedded_packages(tar(entries),packages)

    def rpm_inventory(self):
        rows=[]
        for n in range(10):
            row={'name':'pkg'+str(n),'epochnum':'0','version':'1','release':'1.el10','arch':'x86_64','license':'MIT','sourcerpm':'pkg.src.rpm','url':'https://example.test'}
            rows.append('\t'.join(row[f] for f in FIELDS))
        rows.append('\t'.join(['gpg-pubkey','0','c2a1e572','12345678','(none)','pubkey','(none)','(none)']))
        return parse_rpm_query('\n'.join(rows),'bios')

    def test_installed_metadata_exports_only_package_and_public_key_identity(self):
        value=self.rpm_inventory();self.assertEqual(len(validate_inventory(value,'bios')),10)
        self.assertEqual(value['rpm_keys'],['gpg-pubkey-c2a1e572-12345678'])
        altered=copy.deepcopy(value);altered['packages'][0]['password']='private'
        with self.assertRaises(ValueError):validate_inventory(altered,'bios')
        with self.assertRaises(ValueError):validate_inventory(value,'uefi')
        altered=copy.deepcopy(value);altered['packages'].append(altered['packages'][0])
        with self.assertRaises(ValueError):validate_inventory(altered,'bios')

    def evidence(self):
        inventory,document=self.generate();inventory.write(self.output,document)
        for name,data in {'payloads.json.gz':b'public payload inventory','compiler.txt':self.compiler.encode(),
                          'build-manifest.json':inv.canonical(self.manifest),'build-inputs.json':b'{}',
                          'cargo-graph.json':inv.canonical(self.metadata),'runtime-packages.lock.json':b'{}'}.items():
            (self.output/name).write_bytes(data)
        names=['riverlb-image.iso','riverlb-installer.iso','riverlb.qcow2','riverlb.raw',
               'riverlb-1.0.1-1.el10.x86_64.rpm','riverlb-ha-1.0.1-1.el10.x86_64.rpm','riverlb-appliance-1.0.1-1.el10.x86_64.rpm',
               'riverlb-1.0.1-x86_64-unknown-linux-gnu-aaaaaaaaaaaa.tar.gz']
        artifacts={name:hashlib.sha256(name.encode()).hexdigest() for name in names}
        identity={'schema':1,'source':'a'*40,'firmware':'bios','artifacts':artifacts,'components':5,'installed_packages':10,
                  'files':{name:inv.sha256(self.output/name) for name in prov.FILES}}
        (self.output/'inventory-identity.json').write_bytes(inv.canonical(identity))
        report={'schema':1,'status':'passed','stage':'complete','stages':{name:'passed' for name in prov.STAGES},'cleanup':'passed',
                'source':'a'*40,'firmware':'bios','run_id':'123','run_attempt':'1','platform':{},'resources':{},'commands':{},
                'inputs':{'lock_sha256':inv.sha256(self.root/'packaging/build-inputs.lock.json'),'snapshot_sha256':self.lock['sha256'],
                          'rpm_manifest_sha256':inv.sha256(self.output/'build-manifest.json'),'tools_image':self.lock['images']['tools']['id']},
                'artifacts':{n:artifacts[n] for n in names[:4]},'software':{name:inv.sha256(self.output/name) for name in ('sbom.cdx.json','licenses.json','notices.tar.gz','payloads.json.gz','inventory-identity.json')},
                'boot':{'status':'passed','firmware':'bios','tests':sorted(qualification.BOOT_TESTS)},
                'installer':{'status':'passed','firmware':'bios','tests':sorted(qualification.INSTALLER_TESTS)},'finished_at_utc':'2026-10-23T00:00:00Z'}
        path=self.root/'report.json';path.write_bytes(inv.canonical(report))
        shutil.copytree(ROOT/'packaging/schemas',self.root/'packaging/schemas')
        return path,report

    def test_provenance_binds_exact_subjects_compiler_builder_and_tests(self):
        path,report=self.evidence();predicate=prov.prepare(self.root,self.output,path,'a'*40,'bios')
        self.assertEqual(predicate['buildDefinition']['externalParameters']['commit'],'a'*40)
        self.assertIn('compiler',predicate['buildDefinition']['internalParameters'])
        self.assertEqual(predicate['runDetails']['metadata']['invocationId'],'https://github.com/codyasmith8118/RiverLB/actions/runs/123/attempts/1')
        self.assertEqual(json.loads((self.output/'qualification.json').read_text()),report)

    def test_incomplete_cleanup_source_or_guest_tests_cannot_be_attested(self):
        path,original=self.evidence()
        for changes in ({'cleanup':'failed'},{'status':'failed'},{'source':'b'*40},{'password':'private'}):
            report={**original,**changes};path.write_bytes(inv.canonical(report))
            with self.subTest(changes=changes),self.assertRaises(ValueError):prov.prepare(self.root,self.output,path,'a'*40,'bios')
        report=copy.deepcopy(original);report['installer']['tests'].pop();path.write_bytes(inv.canonical(report))
        with self.assertRaises(ValueError):prov.prepare(self.root,self.output,path,'a'*40,'bios')

    def test_changed_inventory_is_rejected_before_signing(self):
        path,_=self.evidence();(self.output/'sbom.cdx.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'changed'):prov.prepare(self.root,self.output,path,'a'*40,'bios')

    def test_altered_artifact_wrong_subject_set_and_platform_are_rejected(self):
        path,_=self.evidence();predicate=prov.prepare(self.root,self.output,path,'a'*40,'bios')
        subjects=predicate['buildDefinition']['externalParameters']['subjects']
        value={'_type':'https://in-toto.io/Statement/v1','predicateType':prov.PREDICATE_TYPE,'predicate':predicate,
               'subject':[{'name':name,'digest':{'sha256':digest}} for name,digest in subjects.items()]}
        artifact=self.output/'sbom.cdx.json'
        prov.check_statement(value,predicate,artifact,'a'*40,'bios')
        with self.assertRaises(ValueError):prov.check_statement(value,predicate,artifact,'b'*40,'bios')
        with self.assertRaises(ValueError):prov.check_statement(value,predicate,artifact,'a'*40,'uefi')
        modified=copy.deepcopy(value);modified['subject'].pop()
        with self.assertRaises(ValueError):prov.check_statement(modified,predicate,artifact,'a'*40,'bios')
        artifact.write_bytes(artifact.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'Artifact altered'):prov.check_statement(value,predicate,artifact,'a'*40,'bios')

    def test_bundle_parser_rejects_wrong_statement_and_free_form_json(self):
        path=self.root/'bundle.json';path.write_text('{}')
        with self.assertRaises(ValueError):prov.statement(path)
        path.write_bytes(inv.canonical({'dsseEnvelope':{'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(b'{}').decode()}}))
        with self.assertRaises(ValueError):prov.statement(path)

    def test_os_catalog_checks_original_notices_and_iso_identity(self):
        catalog,packages,notices=os_catalog(ROOT)
        self.assertEqual(sum(p['installer_runtime'] for p in packages.values()),826)
        self.assertEqual(len(packages),1322)
        self.assertTrue(notices)
        self.assertTrue(all(p['source_url'].startswith('https://') for p in packages.values()))


if __name__=='__main__':unittest.main()
