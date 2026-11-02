from pathlib import Path
import subprocess as S,json,time,datetime,shlex
P=Path('/root/riverlb-eve-lab');run_id=time.time_ns();evidence={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':{}}
def ssh(last,cmd,timeout=45,stdin=None):
 r=S.run(['ssh','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(P/'guest-known-hosts'),'-i',str(P/'id_ed25519'),f'root@10.77.0.{last}',cmd],input=stdin,text=True,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(str(last)+': '+r.stderr[-1000:]+r.stdout[-1000:])
 return r.stdout
code='''import urllib.request,json,collections
for vip in [100,101]:
 c=collections.Counter()
 for _ in range(30):
  with urllib.request.urlopen(f'http://10.77.10.{vip}:8080/',timeout=5) as r:
   assert r.status==200;c[json.load(r)['node']]+=1
 print(json.dumps({'vip':vip,'nodes':dict(c)}))
'''
def sample():return [json.loads(s) for s in ssh(50,'python3 -',stdin=code).splitlines()]
def save(): (P/'validation.json').write_text(json.dumps(evidence,indent=2))
ssh(101,'test ! -e /run/riverlb-lab/unhealthy')
injected=False
try:
 normal=sample();assert all(set(x['nodes'])=={'backend1','backend2','backend3'} for x in normal);evidence['checks']['round_robin']=normal;save()
 injected=True
 ssh(101,'touch /run/riverlb-lab/unhealthy');time.sleep(8)
 failed=sample();assert all(set(x['nodes'])=={'backend2','backend3'} for x in failed);evidence['checks']['health_failure']=failed;save()
finally:
 if injected:ssh(101,'rm -f /run/riverlb-lab/unhealthy')
time.sleep(8)
recovered=sample();assert all(set(x['nodes'])=={'backend1','backend2','backend3'} for x in recovered);evidence['checks']['health_recovery']=recovered;save()
for vip in [100,101]:
 out=ssh(50,f'python3 /opt/riverlb-lab/http_load.py http://10.77.10.{vip}:8080/ --duration 15 --rate 20 --workers 8 --expect-nodes backend1,backend2,backend3 --output /opt/riverlb-lab/vip-{vip}-load-{run_id}.json',timeout=45)
 result=json.loads(ssh(50,f'cat /opt/riverlb-lab/vip-{vip}-load-{run_id}.json'));evidence['checks'][f'load_{vip}']=result;save()
print(json.dumps(evidence,indent=2))
