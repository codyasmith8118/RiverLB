#!/usr/bin/env python3
"""Bounded HTTP/1 functional/low-rate load. One new connection per request, no retries/cookies."""
import argparse
import collections
import concurrent.futures
import http.client
import json
import math
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)] if ordered else None


def run(args):
    url = urlsplit(args.url)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.fragment:
        raise ValueError('use an http(s) URL without credentials or fragment')
    if args.host and ('\r' in args.host or '\n' in args.host):
        raise ValueError('invalid Host header')
    if not (0 < args.duration <= 86400 and 0 < args.rate <= 10000 and
            1 <= args.workers <= 256 and 0 < args.timeout <= 60):
        raise ValueError('duration 0..86400, rate 0..10000, workers 1..256, timeout 0..60')
    if args.duration * args.rate > 2000000:
        raise ValueError('at most 2 million scheduled requests per run; split longer runs')
    context = ssl.create_default_context(cafile=args.ca) if url.scheme == 'https' else None
    path = url.path or '/'
    if url.query:
        path += '?' + url.query
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows_path = output.with_suffix('.requests.jsonl')
    if rows_path == output:
        raise ValueError('summary filename must not end in .requests.jsonl')
    # Refuse overwrites; each run is independent evidence.
    with output.open('x') as summary_file, rows_path.open('x') as row_file:
        start = time.monotonic()
        epoch = time.time()
        duration = args.duration
        count = math.ceil(duration * args.rate)
        pending = set()
        lock = threading.Lock()
        rows = []
        dropped = 0

        def request(index, due):
            began = time.monotonic()
            connection = None
            row = {'sequence': index, 'scheduled_at_unix': epoch + due - start,
                   'started_at_unix': time.time(), 'schedule_lag_ms': (began - due) * 1000,
                   'status': None, 'node': None, 'bytes': 0, 'error': None}
            try:
                cls = http.client.HTTPSConnection if context else http.client.HTTPConnection
                options = {'timeout': args.timeout}
                if context:
                    options['context'] = context
                # URL hostname controls DNS, SNI and certificate verification. --host changes only HTTP Host.
                connection = cls(url.hostname, url.port, **options)
                headers = {'Connection': 'close', 'User-Agent': 'RiverLB-lab/1'}
                if args.host:
                    headers['Host'] = args.host
                connection.request('GET', path, headers=headers)
                response = connection.getresponse()
                row['status'] = response.status
                row['node'] = response.getheader('X-Backend-Node')
                while chunk := response.read(65536):
                    row['bytes'] += len(chunk)
                    if row['bytes'] > 16 * 1024 * 1024:
                        raise ValueError('response exceeds 16 MiB safety bound')
            except (OSError, ValueError, http.client.HTTPException) as error:
                row['error'] = f'{type(error).__name__}: {error}'
            finally:
                if connection:
                    connection.close()
            ended = time.monotonic()
            row['completed_at_unix'] = time.time()
            row['latency_ms'] = (ended - began) * 1000
            row['scheduled_latency_ms'] = (ended - due) * 1000
            if row['error'] is None and args.expect_bytes is not None and row['bytes'] != args.expect_bytes:
                row['error'] = f'body length {row["bytes"]} != expected {args.expect_bytes}'
            if row['error'] is None and args.expect_nodes and row['node'] not in args.expect_nodes.split(','):
                row['error'] = f'unexpected backend identity: {row["node"]!r}'
            row['success'] = row['error'] is None and row['status'] == args.expect_status
            with lock:
                row_file.write(json.dumps(row) + '\n')
                rows.append(row)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            for index in range(count):
                due = start + index / args.rate
                remaining = due - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
                done = {future for future in pending if future.done()}
                for future in done:
                    future.result()
                pending -= done
                if time.monotonic() >= start + duration or len(pending) >= args.workers:
                    dropped += 1
                    continue
                pending.add(executor.submit(request, index, due))
            # Observe unexpected worker failures instead of silently discarding them.
            for future in pending:
                future.result()
        elapsed = time.monotonic() - start
        successful = [row for row in rows if row['success']]
        failures = len(rows) - len(successful)
        summary = {'url': args.url, 'started_at_unix': epoch, 'offered_rate_rps': args.rate,
                   'offer_duration_secs': duration, 'elapsed_including_drain_secs': elapsed,
                   'scheduled': count, 'started': len(rows), 'scheduler_dropped': dropped,
                   'successes': len(successful), 'failures': failures,
                   'success_rps_including_drain': len(successful) / elapsed,
                   'status_counts': dict(collections.Counter(str(row['status']) for row in rows)),
                   'error_counts': dict(collections.Counter(row['error'] for row in rows if row['error'])),
                   'backend_counts': dict(collections.Counter(row['node'] or '<missing>' for row in successful)),
                   'successful_latency_ms': {f'p{p}': percentile([r['latency_ms'] for r in successful], p/100)
                                             for p in (50, 95, 99)},
                   'max_schedule_lag_ms': max((r['schedule_lag_ms'] for r in rows), default=0),
                   'request_log': str(rows_path),
                   'passed': failures == 0 and dropped == 0 and len(rows) == count}
        json.dump(summary, summary_file, indent=2)
        summary_file.write('\n')
    print(json.dumps(summary, indent=2))
    return 0 if summary['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--duration', type=float, default=30)
    parser.add_argument('--rate', type=float, default=10)
    parser.add_argument('--workers', type=int, default=32)
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--expect-status', type=int, default=200)
    parser.add_argument('--expect-bytes', type=int, help='require an exact response body length')
    parser.add_argument('--expect-nodes', help='comma-separated allowed X-Backend-Node values')
    parser.add_argument('--host', help='HTTP Host only; use the URL hostname for HTTPS SNI')
    parser.add_argument('--ca', help='PEM trust bundle for HTTPS; verification stays enabled')
    parser.add_argument('--output', required=True, help='new summary JSON filename')
    args = parser.parse_args()
    if not all(math.isfinite(value) for value in (args.duration, args.rate, args.timeout)):
        parser.error('numeric settings must be finite')
    try:
        raise SystemExit(run(args))
    except (ValueError, OSError) as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
