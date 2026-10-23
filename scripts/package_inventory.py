"""Allowlisted, non-secret RPM metadata exported by disposable appliance tests."""
import re

FIELDS = ('name', 'epochnum', 'version', 'release', 'arch', 'license', 'sourcerpm', 'url')
RPM_QUERY_FORMAT = '\t'.join('%{' + field.upper() + '}' for field in FIELDS) + '\n'


def parse_rpm_query(text, firmware):
    packages, keys = [], []
    if firmware not in ('bios', 'uefi') or not isinstance(text, str) or len(text) > 2 * 1024 * 1024:
        raise ValueError('Invalid installed package inventory')
    for line in text.splitlines():
        values = line.split('\t')
        if len(values) != len(FIELDS) or any(not v or len(v) > 4096 for v in values):
            raise ValueError('Unexpected RPM query row')
        entry = dict(zip(FIELDS, values))
        if entry['name'] == 'gpg-pubkey':
            key = 'gpg-pubkey-' + entry['version'] + '-' + entry['release']
            if not re.fullmatch('gpg-pubkey-[a-f0-9]{8}-[a-f0-9]{8}', key):
                raise ValueError('Invalid RPM public-key identity')
            keys.append(key)
        else:
            packages.append(entry)
    result = {'schema': 1, 'firmware': firmware, 'packages': sorted(packages, key=lambda p: tuple(p.values())), 'rpm_keys': sorted(keys)}
    validate_inventory(result, firmware)
    return result


def validate_inventory(value, firmware):
    if set(value) != {'schema', 'firmware', 'packages', 'rpm_keys'} or value['schema'] != 1 or value['firmware'] != firmware:
        raise ValueError('Installed package inventory identity mismatch')
    if not isinstance(value['rpm_keys'], list) or len(value['rpm_keys']) != len(set(value['rpm_keys'])) or any(not re.fullmatch('gpg-pubkey-[a-f0-9]{8}-[a-f0-9]{8}', k) for k in value['rpm_keys']):
        raise ValueError('Unexpected RPM public-key metadata')
    result = {}
    for package in value['packages']:
        if set(package) != set(FIELDS) or any(not isinstance(v, str) or not v or '\n' in v or '\r' in v or '\t' in v or len(v) > 4096 for v in package.values()):
            raise ValueError('Unexpected installed RPM metadata')
        key = '{name}-{version}-{release}.{arch}'.format(**package)
        if key in result or package['name'] == 'gpg-pubkey':
            raise ValueError('Duplicate/non-software installed package')
        result[key] = package
    if len(result) < 10:
        raise ValueError('Installed inventory is incomplete')
    return result
