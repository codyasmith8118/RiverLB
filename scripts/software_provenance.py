"""Fail-closed binding of public build inventories to qualified artifact digests."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
from software_inventory import canonical, sha256

REPOSITORY = 'codyasmith8118/RiverLB'
WORKFLOW = REPOSITORY + '/.github/workflows/appliance-image.yml'
BUILD_TYPE = 'https://github.com/' + REPOSITORY + '/buildtypes/appliance/v1'
PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'
STAGES = {'resource-controls', 'base-media', 'image-media', 'image-structure', 'disk-build',
          'boot-suite', 'installer-media', 'installer-structure', 'installer-suite', 'software-inventory'}
FILES = {'sbom.cdx.json', 'licenses.json', 'notices.tar.gz', 'payloads.json.gz', 'compiler.txt',
         'build-manifest.json', 'build-inputs.json', 'cargo-graph.json', 'runtime-packages.lock.json'}
REPORT_FIELDS = {'schema', 'status', 'stage', 'stages', 'cleanup', 'source', 'firmware', 'run_id', 'run_attempt',
                 'platform', 'resources', 'commands', 'inputs', 'artifacts', 'boot', 'installer', 'software', 'finished_at_utc'}


def load(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('Unsafe or oversized evidence file')
    return json.loads(path.read_text())


def validate_report(report, source, firmware):
    if (set(report) != REPORT_FIELDS or report['schema'] != 1 or report['source'] != source or report['firmware'] != firmware
            or report['status'] != 'passed' or report['stage'] != 'complete' or report['cleanup'] != 'passed'
            or set(report['stages']) != STAGES or set(report['stages'].values()) != {'passed'}):
        raise ValueError('Provenance requires complete matching qualification and cleanup')
    for field in ('run_id', 'run_attempt'):
        if not re.fullmatch('[0-9]+', report[field]):
            raise ValueError('Invalid run identity')
    # Share the fixture assertion contract with the qualification controller.
    spec = importlib.util.spec_from_file_location('riverlb_qualification_contract', Path(__file__).with_name('qualify-appliance.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    for key, expected in [('boot', module.BOOT_TESTS), ('installer', module.INSTALLER_TESTS)]:
        value = report[key]
        if (set(value) != {'status', 'firmware', 'tests'} or value['status'] != 'passed' or value['firmware'] != firmware
                or len(value['tests']) != len(expected) or set(value['tests']) != expected):
            raise ValueError('Incomplete guest assertion evidence')
    if set(report['artifacts']) != {'riverlb-image.iso', 'riverlb-installer.iso', 'riverlb.qcow2', 'riverlb.raw'}:
        raise ValueError('Unexpected qualification artifact inventory')


def prepare(root, evidence, report_path, source, firmware):
    root, evidence = Path(root), Path(evidence)
    if not re.fullmatch('[a-f0-9]{40}', source) or firmware not in ('bios', 'uefi'):
        raise ValueError('Invalid requested source/platform')
    report = load(report_path, 1024 * 1024)
    validate_report(report, source, firmware)
    identity = load(evidence / 'inventory-identity.json')
    if (set(identity) != {'schema', 'source', 'firmware', 'artifacts', 'components', 'installed_packages', 'files'}
            or identity['schema'] != 1 or identity['source'] != source or identity['firmware'] != firmware or set(identity['files']) != FILES):
        raise ValueError('Inventory identity/coverage mismatch')
    for name, digest in identity['files'].items():
        if not re.fullmatch('[a-f0-9]{64}', digest) or sha256(evidence / name) != digest or (evidence / name).is_symlink():
            raise ValueError('Inventory artifact changed: ' + name)
    for name, digest in report['software'].items():
        if name not in FILES | {'inventory-identity.json'} or sha256(evidence / name) != digest:
            raise ValueError('Inventory differs from qualification results')
    if set(report['software']) != {'sbom.cdx.json', 'licenses.json', 'notices.tar.gz', 'payloads.json.gz', 'inventory-identity.json'}:
        raise ValueError('Missing qualified software inventory')
    artifacts = identity['artifacts']
    if len(artifacts) != 8 or any(artifacts.get(k) != v for k, v in report['artifacts'].items()):
        raise ValueError('Artifact/test identity mismatch')
    applications = [n for n in artifacts if n.endswith('.tar.gz')]
    if len(applications) != 1 or not re.fullmatch(r'riverlb-[0-9][A-Za-z0-9.+_-]*\.tar\.gz', applications[0]):
        raise ValueError('Unexpected application archive subject')
    rpms = set(artifacts) - set(report['artifacts']) - set(applications)
    if len(rpms) != 3 or any(not re.fullmatch(r'riverlb(?:-ha|-appliance)?-[0-9][A-Za-z0-9.+_-]*\.rpm', n) for n in rpms):
        raise ValueError('Unexpected RPM subjects')
    if any(not re.fullmatch('[a-f0-9]{64}', v) for v in artifacts.values()):
        raise ValueError('Invalid subject digest')
    manifest = load(evidence / 'build-manifest.json')
    lock = load(root / 'packaging/build-inputs.lock.json')
    if manifest['dirty'] or manifest['commit'] != source or manifest['build_inputs'] != lock:
        raise ValueError('Dirty/wrong source or builder inputs')
    expected_inputs = {'lock_sha256': sha256(root / 'packaging/build-inputs.lock.json'), 'snapshot_sha256': lock['sha256'],
                       'rpm_manifest_sha256': sha256(evidence / 'build-manifest.json'), 'tools_image': lock['images']['tools']['id']}
    if report['inputs'] != expected_inputs:
        raise ValueError('Qualification/build input identity mismatch')
    compiler = (evidence / 'compiler.txt').read_text()
    if not compiler.startswith('rustc ' + manifest['rust'] + ' ') or len(compiler) > 16384:
        raise ValueError('Compiler identity differs from build manifest')
    sbom = load(evidence / 'sbom.cdx.json')
    validate_schema(root, sbom)
    components = [sbom['metadata']['component']] + sbom['components']
    refs = [c['bom-ref'] for c in components]
    if len(set(refs)) != len(refs) or len(components) != identity['components']:
        raise ValueError('SBOM component coverage/identity mismatch')
    licenses = load(evidence / 'licenses.json')
    if set(licenses) != {'schema', 'components'} or set(licenses['components']) != set(refs):
        raise ValueError('License inventory coverage differs from SBOM')
    shutil.copyfile(report_path, evidence / 'qualification.json')
    subjects = dict(artifacts)
    subjects.update({name: sha256(evidence / name) for name in FILES | {'inventory-identity.json', 'qualification.json'}})
    (evidence / 'subjects.sha256').write_text(''.join(d + '  ' + n + '\n' for n, d in sorted(subjects.items())))
    invocation = f'https://github.com/{REPOSITORY}/actions/runs/{report["run_id"]}/attempts/{report["run_attempt"]}'
    predicate = {'buildDefinition': {'buildType': BUILD_TYPE,
        'externalParameters': {'repository': 'https://github.com/' + REPOSITORY, 'commit': source, 'firmware': firmware,
                               'subjects': subjects},
        'internalParameters': {'compiler': compiler, 'platform': report['platform'], 'resources': report['resources'],
                               'commands': report['commands'], 'builderImage': lock['images']['builder']['id'],
                               'toolsImage': lock['images']['tools']['id']},
        'resolvedDependencies': [
            {'uri': 'git+https://github.com/' + REPOSITORY, 'digest': {'gitCommit': source}},
            {'uri': lock['url'], 'digest': {'sha256': lock['sha256']}},
            {'uri': 'Cargo.lock', 'digest': {'sha256': manifest['cargo_lock_sha256']}},
            {'uri': 'runtime-packages.lock.json', 'digest': {'sha256': identity['files']['runtime-packages.lock.json']}}]},
        'runDetails': {'builder': {'id': 'https://github.com/' + WORKFLOW + '@refs/heads/release-2.0'},
                       'metadata': {'invocationId': invocation},
                       'byproducts': [{'name': 'qualification.json', 'digest': {'sha256': subjects['qualification.json']}},
                                      {'name': 'sbom.cdx.json', 'digest': {'sha256': subjects['sbom.cdx.json']}}]}}
    (evidence / 'provenance.json').write_bytes(canonical(predicate))
    return predicate


def validate_schema(root, sbom):
    import jsonschema
    from referencing import Registry, Resource
    folder = Path(root) / 'packaging/schemas'
    origins = load(folder / 'SOURCES.json')
    resources = []
    for name in ('bom-1.6.schema.json', 'spdx.schema.json'):
        if sha256(folder / name) != origins[name]['sha256']:
            raise ValueError('SBOM schema bytes changed')
        value = load(folder / name)
        resources.append((value['$id'], Resource.from_contents(value)))
    registry = Registry().with_resources(resources)
    validator = jsonschema.Draft7Validator(load(folder / 'bom-1.6.schema.json'), registry=registry)
    validator.validate(sbom)


def statement(bundle_path):
    bundle = load(bundle_path, 32 * 1024 * 1024)
    envelope = bundle.get('dsseEnvelope')
    if not isinstance(envelope, dict) or envelope.get('payloadType') != 'application/vnd.in-toto+json':
        raise ValueError('Expected a Sigstore DSSE in-toto bundle')
    payload = base64.b64decode(envelope['payload'], validate=True)
    result = json.loads(payload)
    if result.get('_type') != 'https://in-toto.io/Statement/v1':
        raise ValueError('Unsupported attestation statement')
    return result


def check_statement(value, predicate, artifact, source, firmware, subject_name=None):
    if (value.get('predicateType') != PREDICATE_TYPE or value.get('predicate') != predicate
            or predicate['buildDefinition']['buildType'] != BUILD_TYPE):
        raise ValueError('Wrong/altered provenance predicate')
    parameters = predicate['buildDefinition']['externalParameters']
    if parameters['commit'] != source or parameters['firmware'] != firmware or parameters['repository'] != 'https://github.com/' + REPOSITORY:
        raise ValueError('Wrong source/platform')
    subjects = {}
    for item in value['subject']:
        if set(item) != {'name', 'digest'} or set(item['digest']) != {'sha256'} or item['name'] in subjects:
            raise ValueError('Unexpected/duplicate attestation subject')
        subjects[item['name']] = item['digest']['sha256']
    if subjects != parameters['subjects']:
        raise ValueError('Attested subjects differ from qualified artifact inventory')
    name = subject_name or Path(artifact).name
    if subjects.get(name) != sha256(artifact):
        raise ValueError('Artifact altered or absent from signed provenance')
    return subjects
