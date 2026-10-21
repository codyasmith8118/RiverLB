#!/usr/bin/env python3
"""Named, bounded HTTP/HTTPS lab runs using http_load.py; no admin rights needed."""
import argparse
import datetime
import fcntl
import json
import math
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


PROFILES = {
    'check': [('http', 10, 10, 4), ('https', 10, 10, 4)],
    'http': [('http', 30, 50, 16)],
    'https': [('https', 30, 50, 16)],
    'ramp': [('http', 15, rate, 32) for rate in (10, 25, 50, 100, 200)],
    'soak': [('http', 600, 10, 8)],
    'payload': [('http', 30, 50, 16)],
    'failover': [('http', 120, 10, 8)],
}


def phases(args, config):
    nodes = config['expected_nodes']
    if not isinstance(nodes, list) or not nodes or any(not isinstance(n, str) or not n or ',' in n for n in nodes):
        raise ValueError('expected_nodes must be a nonempty list of node names without commas')
    planned = []
    for scheme, duration, rate, workers in PROFILES[args.profile]:
        duration = args.duration if args.duration is not None else duration
        rate = args.rate if args.rate is not None else rate
        workers = args.workers if args.workers is not None else workers
        if not (math.isfinite(duration) and math.isfinite(rate) and math.isfinite(args.timeout)
                and 0 < duration <= 86400 and 0 < rate <= 1000 and 1 <= workers <= 64
                and 0 < args.timeout <= 60 and duration * rate <= 200000):
            raise ValueError('each phase: duration 0..86400 s; rate 0..1000 rps; workers 1..64; timeout 0..60 s; at most 200000 requests')
        url = config[scheme + '_url']
        parsed = urlsplit(url)
        if parsed.scheme != scheme or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('configured URLs must use their matching scheme and contain no credentials or fragment')
        extra = []
        if scheme == 'https':
            ca = Path(config['ca_certificate'])
            if not ca.is_file():
                raise ValueError('HTTPS trust file does not exist: ' + str(ca))
            extra.extend(['--ca', str(ca)])
        if args.profile == 'payload':
            url = urlunsplit((parsed.scheme, parsed.netloc, '/payload', 'bytes=16384', ''))
            extra.extend(['--expect-bytes', '16384'])
        planned.append(dict(scheme=scheme, url=url, duration=duration, rate=rate, workers=workers, extra=extra))
    return planned


def run(args):
    config = json.loads(args.config.read_text())
    planned = phases(args, config)  # Validate every phase before any traffic.
    runner = Path(__file__).resolve().with_name('http_load.py')
    if not runner.is_file():
        raise ValueError('http_load.py must be installed beside loadgen.py')
    base = args.results.expanduser()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = base / '.load.lock'
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another load run is active in this results directory; stop it before starting another') from None
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        directory = base / (stamp + '-' + args.profile + '-' + uuid.uuid4().hex[:8])
        directory.mkdir(mode=0o700)
        report = dict(profile=args.profile, hostname=platform.node(), kernel=platform.release(),
                      cpu_count=os.cpu_count(), planned=planned, phases=[], passed=False)
        if Path('/proc/meminfo').is_file():
            report['generator_memory_before'] = Path('/proc/meminfo').read_text()
        print('Results: ' + str(directory), flush=True)
        result = 0
        try:
            for index, phase in enumerate(planned, 1):
                output = directory / f'{index:02d}-{phase["scheme"]}-{phase["rate"]:g}rps.json'
                command = [sys.executable, str(runner), phase['url'], '--duration', str(phase['duration']),
                           '--rate', str(phase['rate']), '--workers', str(phase['workers']),
                           '--timeout', str(args.timeout), '--expect-nodes', ','.join(config['expected_nodes']),
                           '--output', str(output), *phase['extra']]
                print(f'{phase["scheme"]}: {phase["rate"]:g} requests/s for {phase["duration"]:g}s, {phase["workers"]} workers', flush=True)
                with output.with_suffix('.console.log').open('x') as console:
                    with subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT, start_new_session=True) as process:
                        try:
                            process.wait()
                        except KeyboardInterrupt:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
                            raise
                entry = dict(summary=str(output), exit_code=process.returncode)
                if output.is_file() and output.stat().st_size:
                    entry['result'] = json.loads(output.read_text())
                    summary = entry['result']
                    print(f'  {summary["successes"]}/{summary["scheduled"]} succeeded; failures={summary["failures"]}; '
                          f'scheduler dropped={summary["scheduler_dropped"]}; p95={summary["successful_latency_ms"]["p95"]} ms; '
                          f'backends={summary["backend_counts"]}', flush=True)
                report['phases'].append(entry)
                if process.returncode:
                    result = process.returncode if process.returncode > 0 else 1
                    print('Stopped after an unsuccessful phase; inspect its summary and console log.', flush=True)
                    break
            report['passed'] = result == 0
        except KeyboardInterrupt:
            report['interrupted'] = True
            result = 130
        finally:
            (directory / 'run.json').write_text(json.dumps(report, indent=2) + '\n')
            print('Run report: ' + str(directory / 'run.json'), flush=True)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', choices=PROFILES)
    parser.add_argument('--config', type=Path, default=Path('/opt/riverlb-loadgen/config.json'))
    parser.add_argument('--results', type=Path, default=Path.home() / 'riverlb-loadgen' / 'results')
    parser.add_argument('--duration', type=float, help='override seconds per phase')
    parser.add_argument('--rate', type=float, help='override offered requests/s per phase')
    parser.add_argument('--workers', type=int, help='override concurrent worker limit')
    parser.add_argument('--timeout', type=float, default=3)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
