import subprocess as S,json,time,pathlib
P=pathlib.Path('/root/riverlb-eve-lab');result={}
for last in [101,102,103,50]:
 a=['ssh','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(P/'guest-known-hosts'),'-i',str(P/'id_ed25519'),f'root@10.77.0.{last}']
 cmd='hostname; systemctl is-active ssh; ip -br -4 addr'
 if last!=50:cmd+='; systemctl is-active riverlb-lab-backend; curl -fsS http://10.77.20.'+str(last)+':8080/'
 r=S.run(a+[cmd],text=True,capture_output=True,timeout=15);result[str(last)]={'code':r.returncode,'out':r.stdout,'err':r.stderr}
print(json.dumps(result,indent=2));(P/'support-check.json').write_text(json.dumps(result,indent=2))
