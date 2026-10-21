"""OpenSSL signer/Rust verifier interoperability and hostile offline bundle rejection."""
import json, os, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];BINARY=Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'debug/riverlb'
with tempfile.TemporaryDirectory(prefix='riverlb-updates-') as directory:
    root=Path(directory);key=root/'publisher.key';bundle=root/'fixture.rlbupdate'
    subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',key],check=True,capture_output=True);os.chmod(key,0o600)
    subprocess.run(['python3',ROOT/'scripts/sign-update.py','--binary','/bin/true','--key',key,'--version','0.1.0','--sequence','41','--output',bundle],check=True,capture_output=True)
    trust=bundle.with_suffix('.trust.json')
    def verify(path=bundle,sequence=40,valid=True):
        result=subprocess.run([BINARY,'update-verify','--bundle',path,'--trust',trust,'--sequence',str(sequence)],capture_output=True,text=True)
        assert (result.returncode==0)==valid,(result.returncode,result.stderr)
        if valid:return json.loads(result.stdout)
    assert verify()['sequence']==41;verify(sequence=41,valid=False)
    modified=json.loads(bundle.read_text());modified['payload']=modified['payload'][:-4]+'AAAA';bad=root/'tampered.rlbupdate';bad.write_text(json.dumps(modified));verify(bad,valid=False)
    modified=json.loads(bundle.read_text());modified['manifest']+=' ';bad.write_text(json.dumps(modified));verify(bad,valid=False)
    linked=root/'linked.rlbupdate';linked.symlink_to(bundle);verify(linked,valid=False)
    os.chmod(trust,0o666);verify(valid=False)
    print('PASS signed offline bundles: OpenSSL/Rust Ed25519, payload/signature tampering, sequence, symlink and trust permissions')
