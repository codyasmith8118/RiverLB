#!/usr/bin/env python3
"""Verify qualified artifact bytes and GitHub/Sigstore signer/source identity."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from software_inventory import sha256
from software_provenance import (PREDICATE_TYPE, REPOSITORY, WORKFLOW, check_statement,
                                 load, statement)

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--artifact', type=Path, required=True)
p.add_argument('--subject-name')
p.add_argument('--bundle', type=Path, required=True)
p.add_argument('--predicate', type=Path, required=True)
p.add_argument('--source', required=True)
p.add_argument('--firmware', choices=['bios', 'uefi'], required=True)
p.add_argument('--sbom', type=Path)
p.add_argument('--sbom-bundle', type=Path)
a = p.parse_args()
if bool(a.sbom) != bool(a.sbom_bundle):
    p.error('SBOM and SBOM bundle must be supplied together')
with tempfile.TemporaryDirectory(prefix='riverlb-attestation-verify-') as folder:
    # Verify the same bundle bytes we parse; do not race a replaced input file.
    bundle = Path(folder) / 'bundle.json'
    if a.bundle.is_symlink() or a.bundle.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Unsafe/oversized attestation bundle')
    bundle.write_bytes(a.bundle.read_bytes())
    predicate = load(a.predicate)
    subjects = check_statement(statement(bundle), predicate, a.artifact, a.source, a.firmware, a.subject_name)
    before = sha256(a.artifact)
    def cryptographic_verification(artifact, bundle_path, predicate_type):
        subprocess.run(['gh', 'attestation', 'verify', str(artifact), '--bundle', str(bundle_path), '--repo', REPOSITORY,
                        '--signer-workflow', WORKFLOW, '--signer-digest', a.source, '--source-digest', a.source,
                        '--source-ref', 'refs/heads/release-2.0', '--deny-self-hosted-runners',
                        '--predicate-type', predicate_type], check=True, stdout=subprocess.DEVNULL)
    cryptographic_verification(a.artifact, bundle, PREDICATE_TYPE)
    if a.sbom:
        sbom_bundle = Path(folder) / 'sbom-bundle.json'
        if a.sbom_bundle.is_symlink() or a.sbom_bundle.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('Unsafe/oversized SBOM bundle')
        sbom_bundle.write_bytes(a.sbom_bundle.read_bytes())
        value = statement(sbom_bundle)
        if value.get('predicateType') != 'https://cyclonedx.org/bom' or value.get('predicate') != load(a.sbom):
            raise ValueError('Signed SBOM differs from the supplied inventory')
        if {s['name']: s['digest']['sha256'] for s in value['subject']} != subjects:
            raise ValueError('SBOM/provenance subjects differ')
        if subjects.get(a.sbom.name) != sha256(a.sbom):
            raise ValueError('SBOM differs from signed provenance')
        cryptographic_verification(a.sbom, sbom_bundle, 'https://cyclonedx.org/bom')
    if sha256(a.artifact) != before:
        raise ValueError('Artifact changed during verification')
print(json.dumps({'status': 'verified', 'source': a.source, 'firmware': a.firmware,
                  'artifact': a.subject_name or a.artifact.name, 'sha256': before,
                  'attested_subjects': len(subjects)}, sort_keys=True))
