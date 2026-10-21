#!/usr/bin/env python3
"""Create an offline RiverLB bundle with an operator-owned Ed25519 signing key."""
import argparse, base64, hashlib, json, os, subprocess, tempfile, time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=Path,required=True);p.add_argument('--key',type=Path,required=True)
p.add_argument('--version',required=True);p.add_argument('--sequence',type=int,required=True)
p.add_argument('--output',type=Path,required=True);p.add_argument('--valid-days',type=int,default=30)
a=p.parse_args();os.umask(0o077)
if a.sequence<=0 or not 1<=a.valid_days<=366:p.error('sequence must be positive; validity is 1–366 days')
if a.output.exists():p.error('output already exists')
data=a.binary.read_bytes()
if len(data)>128*1024*1024 or data[:6]!=b'\x7fELF\x02\x01' or data[18:20]!=b'\x3e\x00':p.error('binary must be an x86-64 ELF executable under 128 MiB')
public=subprocess.run(['openssl','pkey','-in',str(a.key),'-pubout','-outform','DER'],check=True,stdout=subprocess.PIPE).stdout
if public[:12]!=bytes.fromhex('302a300506032b6570032100') or len(public)!=44:p.error('key must be Ed25519')
key_id=hashlib.sha256(public[12:]).hexdigest();now=int(time.time())
manifest=json.dumps(dict(format=1,product='RiverLB',version=a.version,sequence=a.sequence,architecture='x86_64',platform='almalinux-10',minimum_schema=6,maximum_schema=6,created=now,expires=now+a.valid_days*86400,payload_length=len(data),payload_sha256=hashlib.sha256(data).hexdigest(),key_id=key_id),sort_keys=True,separators=(',',':'))
with tempfile.TemporaryDirectory(prefix='riverlb-sign-') as directory:
    source=Path(directory)/'manifest';source.write_text(manifest)
    signature=subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(a.key),'-in',str(source)],check=True,stdout=subprocess.PIPE).stdout
with a.output.open('x') as f:json.dump(dict(manifest=manifest,signature=base64.b64encode(signature).decode(),payload=base64.b64encode(data).decode()),f,separators=(',',':'));f.flush();os.fsync(f.fileno())
trust=a.output.with_suffix('.trust.json')
with trust.open('x') as f:json.dump(dict(format=1,keys=[dict(id=key_id,public_key=base64.b64encode(public[12:]).decode())]),f,indent=2)
print('Created signed bundle:',a.output)
print('Public trust export:',trust,'— verify and install separately; never ship the private key.')
