"""Real NetworkManager checkpoint/persistence tests in an isolated container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

if os.environ.get('RIVERLB_PACKAGE_TEST')!='disposable-container':
    raise SystemExit('Run scripts/test-network-manager.sh; this fixture changes its container networking')


def run(*args):
    return subprocess.check_output(args,stderr=subprocess.STDOUT,text=True,timeout=25).strip()


def nm(*args):
    return run('nmcli','--wait','15','--escape','no',*args)


def call(method,*args):
    text=run('busctl','--system','--json=short','call','org.freedesktop.NetworkManager','/org/freedesktop/NetworkManager','org.freedesktop.NetworkManager',method,*args)
    return json.loads(text) if text else None


def wait(function):
    end=time.monotonic()+15
    while time.monotonic()<end:
        try:
            if function():return
        except subprocess.CalledProcessError:
            pass
        time.sleep(0.2)
    raise AssertionError('Timed out waiting for NetworkManager fixture')


def checkpoint(device,seconds=30):
    path=call('GetDeviceByIpIface','s',device)['data'][0]
    return call('CheckpointCreate','aouu','1',path,str(seconds),'2')['data'][0]


Path('/run/dbus').mkdir(parents=True,exist_ok=True)
Path('/etc/NetworkManager/conf.d').mkdir(parents=True,exist_ok=True)
Path('/etc/NetworkManager/conf.d/no-auto.conf').write_text('[main]\nno-auto-default=*\n')
run('dbus-uuidgen','--ensure')
with tempfile.TemporaryFile(mode='w+') as log:
    bus=subprocess.Popen(['dbus-daemon','--system','--nofork','--nopidfile'],stdout=log,stderr=log)
    manager=None
    try:
        wait(lambda:Path('/run/dbus/system_bus_socket').exists())
        manager=subprocess.Popen(['NetworkManager','--no-daemon'],stdout=log,stderr=log)
        wait(lambda:nm('-g','STATE','general')!='')
        run('ip','link','add','nmtest','type','dummy')
        nm('connection','add','type','dummy','ifname','nmtest','con-name','baseline','ipv4.method','manual','ipv4.addresses','192.0.2.10/24','ipv4.never-default','yes','ipv6.method','disabled')
        nm('connection','up','id','baseline')
        uuid=nm('-g','connection.uuid','connection','show','id','baseline')
        # Verify fields used by the portal on the appliance's actual NM version.
        assert nm('-g','connection.controller','connection','show','uuid',uuid)==''
        profile=next(p for p in Path('/etc/NetworkManager/system-connections').glob('*') if uuid in p.read_text())
        def addresses():return nm('-g','ipv4.addresses','connection','show','uuid',uuid)
        def trial(address):
            nm('connection','modify','--temporary','uuid',uuid,'ipv4.addresses',address)
            nm('connection','up','uuid',uuid,'ifname','nmtest')
        cp=checkpoint('nmtest')
        checkpoints=json.loads(run('busctl','--system','--json=short','get-property','org.freedesktop.NetworkManager','/org/freedesktop/NetworkManager','org.freedesktop.NetworkManager','Checkpoints'))
        assert cp in checkpoints['data'],checkpoints
        trial('192.0.2.20/24')
        assert '192.0.2.10/24' in profile.read_text(),'Trials must not overwrite the persistent profile'
        rollback=call('CheckpointRollback','o',cp)['data'][0]
        assert isinstance(rollback,dict) and all(value==0 for value in rollback.values()),rollback
        wait(lambda:addresses()=='192.0.2.10/24')
        checkpoint('nmtest',3)
        trial('192.0.2.30/24')
        wait(lambda:addresses()=='192.0.2.10/24')
        cp=checkpoint('nmtest')
        trial('192.0.2.40/24')
        nm('connection','modify','uuid',uuid,'connection.autoconnect','yes')
        call('CheckpointDestroy','o',cp)
        assert '192.0.2.40/24' in profile.read_text(),'Confirmation must save the trial to disk'
        def disable_trial():
            nm('connection','modify','--temporary','uuid',uuid,'connection.autoconnect','no')
            nm('device','disconnect','nmtest')
            run('ip','link','set','dev','nmtest','down')
            assert 'UP' not in json.loads(run('ip','-j','link','show','nmtest'))[0]['flags']
        cp=checkpoint('nmtest')
        disable_trial()
        assert 'autoconnect=false' not in profile.read_text(),'Disabling must remain temporary until confirmed'
        call('CheckpointRollback','o',cp)
        wait(lambda:nm('-g','GENERAL.CON-UUID','device','show','nmtest')==uuid)
        assert 'UP' in json.loads(run('ip','-j','link','show','nmtest'))[0]['flags']
        checkpoint('nmtest',3)
        disable_trial()
        wait(lambda:nm('-g','GENERAL.CON-UUID','device','show','nmtest')==uuid)
        cp=checkpoint('nmtest')
        disable_trial()
        nm('connection','modify','uuid',uuid,'connection.autoconnect','no')
        call('CheckpointDestroy','o',cp)
        assert 'autoconnect=false' in profile.read_text(),'Confirmed disabling must persist'
        cp=checkpoint('nmtest')
        nm('connection','modify','--temporary','uuid',uuid,'connection.autoconnect','yes')
        nm('connection','up','uuid',uuid)
        nm('connection','modify','uuid',uuid,'connection.autoconnect','yes')
        call('CheckpointDestroy','o',cp)
        assert 'autoconnect=false' not in profile.read_text(),'Re-enabling must restore boot reconnection'
        run('ip','link','add','nmtest2','type','dummy')
        wait(lambda:'nmtest2' in nm('-g','DEVICE','device'))
        cp=checkpoint('nmtest2')
        nm('connection','add','save','no','type','dummy','ifname','nmtest2','con-name','trial-new','ipv4.method','manual','ipv4.addresses','198.51.100.10/24','ipv4.never-default','yes','ipv6.method','disabled')
        trial_uuid=nm('-g','connection.uuid','connection','show','id','trial-new')
        nm('connection','up','uuid',trial_uuid)
        assert not any(trial_uuid in p.read_text() for p in Path('/etc/NetworkManager/system-connections').glob('*'))
        call('CheckpointRollback','o',cp)
        assert trial_uuid not in nm('-g','UUID','connection','show'),'Rollback must remove newly created trial profiles'
        # Simulate reboot's loss of /run after an unconfirmed temporary update.
        checkpoint('nmtest')
        trial('192.0.2.50/24')
        manager.terminate();manager.wait(timeout=10)
        for path in Path('/run/NetworkManager/system-connections').glob('*'):
            path.unlink()
        manager=subprocess.Popen(['NetworkManager','--no-daemon'],stdout=log,stderr=log)
        wait(lambda:addresses()=='192.0.2.40/24')
        print('PASS real NetworkManager: temporary profiles, disable/enable, explicit and timeout rollback, confirmed persistence, new-profile cleanup and disk-profile recovery after clearing runtime state')
    except Exception:
        log.seek(0)
        print(log.read()[-12000:])
        raise
    finally:
        if manager and manager.poll() is None:manager.terminate();manager.wait(timeout=10)
        bus.terminate();bus.wait(timeout=10)
