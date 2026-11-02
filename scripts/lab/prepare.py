#!/usr/bin/env python3
"""Prepare an exact-commit, CI-gated RPM bundle for the private development lab."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

REPO = 'codyasmith8118/RiverLB'
BRANCH = 'release-2.0'
REQUIRED = {'ci.yml', 'security.yml', 'rpm.yml'}


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def qualified_runs(runs, sha):
    latest = {}
    for run in runs:
        if run['head_sha'] != sha or run['head_branch'] != BRANCH:
            continue
        path = run['path'].split('@')[0]
        if path not in latest or run['id'] > latest[path]['id']:
            latest[path] = run
    missing = REQUIRED - {Path(p).name for p in latest}
    if missing:
        raise ValueError('Missing exact-commit workflows: ' + ', '.join(sorted(missing)))
    for run in latest.values():
        if run['status'] != 'completed' or run['conclusion'] != 'success':
            raise ValueError('Workflow is not successful: ' + run['html_url'])
    return list(latest.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.sha):
        parser.error('--sha must be the complete commit SHA')
    if args.output.exists():
        parser.error('Output already exists')
    head = json.loads(gh('api', f'repos/{REPO}/branches/{BRANCH}'))['commit']['sha']
    if head != args.sha:
        raise ValueError('Deploy only the current release-2.0 head')
    pages = json.loads(gh('api', '--paginate', '--slurp',
                         f'repos/{REPO}/actions/runs?head_sha={args.sha}&per_page=100'))
    runs = qualified_runs([r for p in pages for r in p['workflow_runs']], args.sha)
    rpm = next(r for r in runs if Path(r['path']).name == 'rpm.yml')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gh('run', 'download', str(rpm['id']), '--repo', REPO,
           '--name', f"rpm-{rpm['id']}", '--dir', str(root))
        manifest = json.loads((root / 'build-manifest.json').read_text())
        if manifest['commit'] != args.sha or manifest['dirty']:
            raise ValueError('Artifact source does not match the clean accepted commit')
        sums = {}
        for line in (root / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            sums[name.removeprefix('*').removeprefix('./')] = digest
        packages = sorted(root.glob('*.rpm'))
        if not packages or not any(p.name.startswith('riverlb-appliance-') for p in packages):
            raise ValueError('Incomplete appliance RPM artifact')
        digests = {}
        for package in packages:
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            if sums.get(package.name) != digest:
                raise ValueError('RPM checksum mismatch: ' + package.name)
            digests[package.name] = digest
        receipt = dict(schema=1, repository=REPO, branch=BRANCH, commit=args.sha,
                       created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       workflows=[dict(id=r['id'], path=r['path'], url=r['html_url'],
                                       conclusion=r['conclusion']) for r in runs], packages=digests)
        (root / 'deployment.json').write_text(json.dumps(receipt, indent=2) + '\n')
        # Recheck the branch immediately before handing off an update candidate.
        if json.loads(gh('api', f'repos/{REPO}/branches/{BRANCH}'))['commit']['sha'] != args.sha:
            raise ValueError('Release branch advanced; prepare its tested head instead')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.output, 'x') as archive:
            for package in [*packages, root / 'deployment.json', root / 'build-manifest.json']:
                archive.add(package, arcname=package.name)
    print(json.dumps({'bundle': str(args.output), 'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      'commit': args.sha}, indent=2))


if __name__ == '__main__':
    main()
