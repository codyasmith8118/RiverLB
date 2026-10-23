"""Build a complete aggregate SBOM for qualified RPM/media/appliance artifacts."""
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import zipfile
from artifact_inventory import (add_os_package, installed_packages, inspect_iso, os_catalog,
                                rpm_metadata, rpm_payload, runtime_manifest, verify_embedded_packages, verify_application_archive)
from software_inventory import canonical, sha256, source_inventory


def build(root, inputs, packages, media, disks, installed, report_path, output, firmware):
    root, packages, media, disks, output = map(Path, (root, packages, media, disks, output))
    manifest = json.loads((packages / 'build-manifest.json').read_text())
    report = json.loads(Path(report_path).read_text())
    if (manifest['dirty'] or manifest['commit'] != report['source'] or report['firmware'] != firmware
            or report.get('boot', {}).get('status') != 'passed' or report.get('installer', {}).get('status') != 'passed'):
        raise ValueError('Source/qualification identity mismatch')
    artifacts = {p.name: p for p in packages.glob('*.rpm')}
    artifacts.update({name: media / name for name in ('riverlb-image.iso', 'riverlb-installer.iso')})
    artifacts.update({name: disks / name for name in ('riverlb.qcow2', 'riverlb.raw')})
    applications = list(packages.glob('riverlb-*.tar.gz'))
    if len(applications) != 1:
        raise ValueError('Expected exactly one application archive')
    artifacts[applications[0].name] = applications[0]
    actual = {name: sha256(path) for name, path in artifacts.items()}
    if any(actual.get(name) != digest for name, digest in report['artifacts'].items()) or len(report['artifacts']) != 4:
        raise ValueError('Artifacts differ from qualification results')
    candidate_rpms = sorted(packages.glob('*.rpm'))
    if len(candidate_rpms) != 3:
        raise ValueError('Expected exactly three candidate RPMs')
    metadata = {rpm_metadata(p)['name']: (p, rpm_metadata(p)) for p in candidate_rpms}
    if set(metadata) != {'riverlb', 'riverlb-ha', 'riverlb-appliance'}:
        raise ValueError('Expected exact RiverLB RPM set')
    keep = lambda n: n == 'usr/lib/riverlb/base/riverlb' or n.endswith('/sbom.cdx.json') or n.endswith('/licenses.json') or n == 'usr/sbin/fence_pve' or (n.startswith('usr/lib/riverlb/fencing/openstack/') and n.endswith('.dist-info/METADATA'))
    payloads, retained = {}, {}
    for name, (path, _) in metadata.items():
        files, data = rpm_payload(path, keep)
        payloads[actual[path.name]] = files
        retained.update(data)
    if 'usr/lib/riverlb/base/riverlb' not in retained or 'usr/sbin/fence_pve' not in retained:
        raise ValueError('Application/agent absent from package payload')
    # Verify the SDK actually installed in the RPM, including every embedded dist.
    expected_python = {}
    for wheel in (Path(inputs) / 'wheels').glob('*.whl'):
        with zipfile.ZipFile(wheel) as source:
            for name in source.namelist():
                if name.endswith('.dist-info/METADATA'):
                    expected_python['usr/lib/riverlb/fencing/openstack/' + name] = hashlib.sha256(source.read(name)).hexdigest()
    actual_python = {name: hashlib.sha256(data).hexdigest() for name, data in retained.items() if name.startswith('usr/lib/riverlb/fencing/openstack/')}
    if actual_python != expected_python:
        raise ValueError('Packaged SDK distributions differ from locked wheels')
    with tempfile.TemporaryDirectory(prefix='riverlb-public-inventory-') as scratch:
        scratch = Path(scratch)
        binary, agent = scratch / 'riverlb', scratch / 'fence_pve'
        binary.write_bytes(retained['usr/lib/riverlb/base/riverlb']); agent.write_bytes(retained['usr/sbin/fence_pve'])
        inv, source_bom = source_inventory(root, Path(inputs), json.loads((packages / 'cargo-graph.json').read_text()), binary, manifest, agent)
        embedded = [data for name, data in retained.items() if name.endswith('/sbom.cdx.json')]
        licenses = [data for name, data in retained.items() if name.endswith('/licenses.json')]
        if embedded != [canonical(source_bom)] or licenses != [canonical({'schema': 1, 'components': inv.license_records})]:
            raise ValueError('Packaged source SBOM/notices inventory differs from retained inputs')
        expected_source = scratch / 'source-check'
        inv.write(expected_source, source_bom)
        for name in ('sbom.cdx.json', 'licenses.json', 'notices.tar.gz'):
            if sha256(packages / 'software' / name) != sha256(expected_source / name):
                raise ValueError('Source inventory sidecar mismatch')
        application_files = verify_application_archive(applications[0], root, expected_source, manifest,
                                                       (packages / 'compiler.txt').read_text(), sha256(binary))
        base_files = payloads[actual[metadata['riverlb'][0].name]]
        for name, expected in [('notices.tar.gz', sha256(expected_source / 'notices.tar.gz')),
                               ('runtime-notices.tar.gz', sha256(root / 'packaging/third-party/runtime-notices.tar.gz'))]:
            matches = [v['sha256'] for p, v in base_files.items() if p.startswith('usr/share/licenses/riverlb/') and p.endswith('/' + name)]
            if matches != [expected]:
                raise ValueError('Required notices absent/changed in RPM payload')
        catalog, os_packages, os_notices = os_catalog(root)
        occurrences = {name: set() for name in os_packages}
        all_rpms = {sha256(p): p for p in (packages / 'ha-dependencies').rglob('*.rpm')}
        iso_payloads = {}
        for mode in ('image', 'installer'):
            folder = scratch / mode
            entries = inspect_iso(media / f'riverlb-{mode}.iso', folder)
            iso_payloads[mode] = entries
            for name in runtime_manifest(folder / 'images/install.img', catalog):
                occurrences[name].add('installer-runtime:' + mode)
            verify_embedded_packages(folder / 'riverlb-packages.tar', packages)
            for path in folder.rglob('*.rpm'):
                all_rpms.setdefault(sha256(path), path)
        for digest, path in sorted(all_rpms.items()):
            entry = rpm_metadata(path)
            original = os_packages.get(entry['nevra'])
            if not original or any(entry[k] != original[k] for k in entry):
                raise ValueError('RPM bytes/metadata absent from reviewed OS catalog: ' + entry['nevra'])
            occurrences[entry['nevra']].add('distributed RPM/media payload')
            if digest not in payloads:
                payloads[digest] = rpm_payload(path)[0]
        installed_rows = installed_packages(installed, firmware)
        local = {entry['nevra']: entry for _, entry in metadata.values()}
        for nevra, entry in installed_rows.items():
            original = local.get(nevra) or os_packages.get(nevra)
            if not original or any(entry[k] != original[k] for k in entry):
                raise ValueError('Installed package absent/mismatched in distribution inventory: ' + nevra)
            if nevra in occurrences:
                occurrences[nevra].add('installed appliance:' + firmware)
        root_ref = source_bom['metadata']['component']['bom-ref']
        for name, entry in sorted(os_packages.items()):
            ref = add_os_package(inv, entry, os_notices, occurrences[name])
            if occurrences[name]:
                inv.dependencies[root_ref].add(ref)
        for name, (path, entry) in sorted(metadata.items()):
            from software_inventory import component
            ref = inv.add(component('rpm/riverlb', name, entry['version'] + '-' + entry['release'], actual[path.name], entry['license'],
                                    'https://github.com/codyasmith8118/RiverLB/archive/' + manifest['commit'] + '.tar.gz',
                                    qualifier='?arch=' + entry['arch'] + '&epoch=' + entry['epochnum'],
                                    properties={'riverlb:occurrences': 'RPM/media and installed appliance', 'riverlb:hash-scope': 'built RPM archive'}))
            inv.dependencies[root_ref].add(ref)
            inv.notice(ref, 'riverlb/LICENSE', (root / 'LICENSE').read_bytes(),
                       'https://github.com/codyasmith8118/RiverLB/blob/' + manifest['commit'] + '/LICENSE')
        properties = {p['name']: p['value'] for p in source_bom['metadata']['properties']}
        properties.update({'riverlb:scope': 'aggregate inventory: RPM candidates, both ISO payloads and installed appliance; per-component occurrences distinguish usage',
                           'riverlb:firmware': firmware, 'riverlb:os-catalog-sha256': sha256(root / 'packaging/third-party/runtime-packages.lock.json'),
                           'riverlb:artifact-digests': json.dumps(actual, sort_keys=True)})
        document = inv.document(source_bom['metadata']['component'], properties)
        inv.write(output, document)
        raw_payloads = canonical({'schema': 1, 'rpm_payloads_by_archive_sha256': payloads, 'iso_payloads': iso_payloads,
                                  'application_payload': application_files, 'installed_packages': installed_rows,
                                  'installed_rpm_keys': json.loads(Path(installed).read_text())['rpm_keys']})
        with (output / 'payloads.json.gz').open('wb') as stream:
            with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, filename='') as compressed:
                compressed.write(raw_payloads)
    for name in ('compiler.txt', 'build-manifest.json', 'build-inputs.json', 'cargo-graph.json'):
        shutil.copyfile(packages / name, output / name)
    shutil.copyfile(root / 'packaging/third-party/runtime-packages.lock.json', output / 'runtime-packages.lock.json')
    identity = {'schema': 1, 'source': manifest['commit'], 'firmware': firmware,
                'artifacts': actual, 'components': len(inv.components), 'installed_packages': len(installed_rows),
                'files': {p.name: sha256(p) for p in sorted(output.iterdir()) if p.is_file() and p.name != 'inventory-identity.json'}}
    (output / 'inventory-identity.json').write_bytes(canonical(identity))
    print('Verified aggregate inventory:', len(inv.components), 'components;', len(installed_rows), 'installed RPMs')
    return identity
