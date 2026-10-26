"""Manual same-host admission benchmark; requires an explicitly retained baseline binary."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import resource
import signal
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from auth_release import PASSWORD, free_port
from flow_inspection import Backends


def measure(binary, backend, polling, idle, rounds, count):
    process=None;sockets=[];stop=threading.Event();worker=None;polls=[]
    with tempfile.TemporaryDirectory(prefix='riverlb-inspection-perf-') as folder:
        config=Path(folder)/'config.toml';admin,vip=free_port(),free_port()
        config.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=300
health_interval_secs=1
max_connections=20000
[[virtual_servers]]
name="benchmark"
listen="127.0.0.1:{vip}"
members=["127.0.0.1:{backend.ports[0]}"]
''')
        subprocess.run([binary,'admin','--database',config.with_suffix('.db')],input=PASSWORD+'\n',text=True,check=True,capture_output=True)
        token=None
        def api(path,body=None):
            c=http.client.HTTPConnection('127.0.0.1',admin,timeout=10)
            headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'}
            if token:headers['Cookie']='riverlb_session='+token
            try:
                c.request('POST' if body else 'GET',path,None if body is None else json.dumps(body),headers)
                r=c.getresponse();raw=r.read();return r.status,dict(r.getheaders()),json.loads(raw) if raw.startswith((b'{',b'[')) else raw.decode()
            finally:c.close()
        try:
            process=subprocess.Popen([binary,'serve','-c',config,'--external-network'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+20
            while True:
                try:
                    _,headers,_=api('/api/v1/auth/login',{'username':'admin','password':PASSWORD})
                    token=headers['set-cookie'].split(';')[0].split('=',1)[1];break
                except (OSError,http.client.HTTPException):
                    if time.monotonic()>deadline:raise
                    time.sleep(.05)
            while not api('/api/v1/status')[2]['virtual_servers'][0]['members'][0]['healthy']:time.sleep(.05)
            for _ in range(idle):sockets.append(socket.create_connection(('127.0.0.1',vip),timeout=5))
            def poll():
                while not stop.is_set():
                    started=time.perf_counter()
                    try:status,_,_=api('/api/v1/connections?limit=200');polls.append({'status':status,'seconds':time.perf_counter()-started})
                    except (OSError,http.client.HTTPException):pass
                    stop.wait(.05)
            if polling:worker=threading.Thread(target=poll);worker.start()
            def memory():
                values={}
                for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                    if line.startswith(('VmRSS:','VmHWM:')):
                        key,value=line.split(':');values[key+'_bytes']=int(value.split()[0])*1024
                return values
            memory_before=memory()
            samples=[]
            for _ in range(rounds):
                started=time.perf_counter()
                for _ in range(count):
                    with socket.create_connection(('127.0.0.1',vip),timeout=5) as client:
                        client.sendall(b'bounded-metadata-benchmark');assert client.recv(64)==b'bounded-metadata-benchmark'
                samples.append(count/(time.perf_counter()-started))
            stop.set()
            if worker:worker.join(15)
            if polling:time.sleep(1.1)
            coverage=api('/api/v1/connections')[2] if polling else None
            return {'connections_per_second':samples,'median_connections_per_second':statistics.median(samples),
                    'memory_before':memory_before,'memory_after':memory(),'polls':len(polls),'poll_statuses':{str(s):sum(p['status']==s for p in polls) for s in {p['status'] for p in polls}},
                    'max_poll_seconds':max((p['seconds'] for p in polls),default=None),
                    'coverage':None if coverage is None else coverage.get('admission_and_coverage')}
        finally:
            stop.set()
            if worker:worker.join(15)
            for client in sockets:client.close()
            if process is not None and process.poll() is None:process.send_signal(signal.SIGTERM);process.wait(timeout=20)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--baseline',type=Path,required=True);parser.add_argument('--candidate',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--idle',type=int,default=3000);parser.add_argument('--rounds',type=int,default=5);parser.add_argument('--count',type=int,default=1000);args=parser.parse_args()
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft<16384:resource.setrlimit(resource.RLIMIT_NOFILE,(min(hard,16384),hard))
    if not (0<=args.idle<=6000 and 1<=args.rounds<=10 and 1<=args.count<=10000):parser.error('Use idle 0..6000, rounds 1..10 and count 1..10000')
    backend=Backends()
    try:
        result={'schema':1,'idle_tcp_connections':args.idle,'rounds':args.rounds,'connections_per_round':args.count,
                'binaries':{name:{'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in [('baseline',args.baseline),('candidate',args.candidate)]}}
        result['baseline']=measure(args.baseline,backend,False,args.idle,args.rounds,args.count)
        result['candidate']=measure(args.candidate,backend,False,args.idle,args.rounds,args.count)
        result['candidate_with_polling']=measure(args.candidate,backend,True,args.idle,args.rounds,args.count)
        for name in ('candidate','candidate_with_polling'):result[name]['median_relative_to_baseline']=result[name]['median_connections_per_second']/result['baseline']['median_connections_per_second']
        args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v['median_connections_per_second'] for k,v in result.items() if isinstance(v,dict) and 'median_connections_per_second'in v}))
    finally:backend.close()


if __name__=='__main__':main()
