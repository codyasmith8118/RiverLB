from pathlib import Path
import subprocess as S,json,shlex,time
P=Path('/root/riverlb-eve-lab');creds=json.loads((P/'credentials.json').read_text());evidence={};access={}
def ssh(last,command,stdin=None):
 r=S.run(['ssh','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(P/'guest-known-hosts'),'-i',str(P/'id_ed25519'),f'root@10.77.0.{last}',command],input=stdin,text=True,capture_output=True,timeout=35)
 if r.returncode:raise RuntimeError(str(last)+': '+r.stdout[-500:]+r.stderr[-500:])
 return r.stdout
for node,last,vip in [('a',11,100),('b',12,101)]:
 details=json.loads(ssh(last,'cat /var/lib/riverlb/.firstboot.complete'));url='https://'+details['address']+':18090';access[node]={'management_url':url,'private_ip':f'10.77.0.{last}','vip':f'http://10.77.10.{vip}:8080/','username':'admin'}
 base='riverlb manage --url '+shlex.quote(url)+' --ca /etc/riverlb/device.crt '
 session='/root/riverlb-lab-check.session'
 ssh(last,'test ! -e '+session+' && '+base+'login --output '+session,stdin=json.dumps({'username':'admin','password':creds['admin_password']}))
 try:
  evidence[node]={'packages':ssh(last,'rpm -q riverlb riverlb-appliance'),'security':ssh(last,'getenforce; systemctl is-active firewalld riverlb; ip -br -4 addr'),'source':json.loads(ssh(last,'cat /usr/share/doc/riverlb/build-manifest.json'))}
  auth=base+'--session-file '+session+' '
  for cmd in ['get','status','connections --limit 10']:
   evidence[node][cmd]=json.loads(ssh(last,auth+cmd))
 finally:
  ssh(last,base+'--session-file '+session+' logout && rm -f '+session)
(P/'access.json').write_text(json.dumps(access,indent=2));(P/'management-check.json').write_text(json.dumps(evidence,indent=2))
print(json.dumps({'access':access,'checks':{n:{'packages':d['packages'],'security':d['security'],'source_commit':d['source']['commit'],'management_cli':['get','status','connections']} for n,d in evidence.items()}},indent=2))
