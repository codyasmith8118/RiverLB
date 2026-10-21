#!/usr/bin/env python3
"""Run on a dedicated TRex lab generator; requires its bundled Python client API."""
import argparse
import json
import math
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='127.0.0.1')
    parser.add_argument('--cps', type=float, default=100)
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--response-bytes', type=int, default=1024)
    parser.add_argument('--vip', default='198.18.10.100')
    parser.add_argument('--output', required=True)
    parser.add_argument('--confirm-isolated-lab', action='store_true')
    args = parser.parse_args()
    if not args.confirm_isolated_lab:
        parser.error('--confirm-isolated-lab is required; this acquires the generator ports')
    if not (math.isfinite(args.cps) and math.isfinite(args.duration) and
            0 < args.cps <= 1000000 and 0 < args.duration <= 3600):
        parser.error('cps 0..1000000; duration 0..3600; finite values required')
    from trex.astf.api import ASTFClient
    from trex_tcp_profile import register
    profile = register().get_profile(vip=args.vip, response_bytes=args.response_bytes)
    client = ASTFClient(server=args.server)
    connected = acquired = loaded = started = False
    # Reserve evidence path before modifying generator state.
    with Path(args.output).open('x') as output:
        report = {'started_at_unix': time.time(), 'arguments': vars(args),
                  'profile': '64-byte request; raw TCP response; one transaction per connection'}
        try:
            client.connect()
            connected = True
            client.acquire(force=False)
            acquired = True
            if client.is_traffic_active():
                raise RuntimeError('generator has active traffic; refusing to interrupt it')
            client.load_profile(profile)
            loaded = True
            # Dedicated lab only. Never force acquisition or call reset().
            client.clear_stats()
            client.start(mult=args.cps, duration=args.duration, nc=False,
                         latency_pps=0, client_mask=1, t_duration=15)
            started = True
            print(f'ASTF profile active for {args.duration}s; requested multiplier {args.cps} CPS.', flush=True)
            client.wait_on_traffic(timeout=args.duration + 45)
            started = False
            report['stats'] = client.get_stats(skip_zero=False)
            report['warnings'] = client.get_warnings()
            report['completed_at_unix'] = time.time()
        except Exception as error:
            report['error'] = f'{type(error).__name__}: {error}'
            raise
        finally:
            try:
                if started:
                    client.stop()
                if loaded:
                    client.clear_profile()
            finally:
                try:
                    if acquired:
                        client.release()
                finally:
                    if connected:
                        client.disconnect()
                    json.dump(report, output, indent=2, default=str)
                    output.write('\n')
    print(f'Raw counters saved to {args.output}; evaluate both client and server errors before passing.')


if __name__ == '__main__':
    main()
