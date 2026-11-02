from pathlib import Path
import subprocess as S,json,time,shlex
P=Path('/root/riverlb-eve-lab');credentials=json.loads((P/'credentials.json').read_text());access=json.loads((P/'access.json').read_text())
def args(last):return ['ssh','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(P/'guest-known-hosts'),'-i',str(P/'id_ed25519'),f'root@10.77.0.{last}']
def ssh(last,command,stdin=None):return S.check_output(args(last)+[command],input=stdin,text=True,timeout=35)
evidence={}
for node,last,vip in [('a',11,100),('b',12,101)]:
 base='riverlb manage --url '+shlex.quote(access[node]['management_url'])+' --ca /etc/riverlb/device.crt '
 session='/root/riverlb-live-check.session'
 ssh(last,base+'login --output '+session,stdin=json.dumps({'username':'admin','password':credentials['admin_password']}))
 code=f'''import urllib.request,concurrent.futures
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as e:
 list(e.map(lambda _: urllib.request.urlopen('http://10.77.10.{vip}:8080/?delay_ms=8000',timeout=15).read(),range(6)))
'''
 process=S.Popen(args(50)+['python3 -'],stdin=S.PIPE,stdout=S.PIPE,stderr=S.PIPE,text=True);process.stdin.write(code);process.stdin.close()
 try:
  time.sleep(2)
  result=json.loads(ssh(last,base+'--session-file '+session+' connections --limit 20 --virtual-server lab-http'))
  assert len(result['result']['rows'])==6,result
  evidence[node]=result
  print(node,json.dumps(result),flush=True)
  process.wait(timeout=20);assert process.returncode==0
 finally:
  ssh(last,base+'--session-file '+session+' logout && rm -f '+session)
(P/'live-flow-check.json').write_text(json.dumps(evidence,indent=2))
