// Independent appliance pages: meaningful save/restore/navigation behavior.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..');
const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'http://localhost:18090',runScripts:'outside-only'});
const w=dom.window, d=w.document;
const settings={alerts:{enabled:true,cpu_percent:90,memory_percent:90,disk_free_percent:10,certificate_days:30,pool_unavailable:true,ha_errors:true,time_unsynchronized:true,pending_configuration:true,webhook_url:'',webhook_ca:'system',syslog_address:'',forward_audit:false},backups:{enabled:false,destination:'',interval_hours:24,retain:14},audit_retention_days:365,audit_max_records:100000};
const publicState={settings,backup_key_configured:false,backup_status:{last_success:null,last_error:null,next_attempt:null,running:false},alerts:[],last_delivery:null,delivery_error:null,queued_notifications:0,next_delivery_attempt:0};
let calls=[], fail=false;
w.confirm=()=>true;w.URL.createObjectURL=()=> 'blob:fixture';w.URL.revokeObjectURL=()=>{};w.HTMLAnchorElement.prototype.click=()=>{};
w.fetch=async(url,options={})=>{
    calls.push({url,options});const endpoint=url.replace('/api/v1/operations/','');let data;
    if(fail)return {ok:false,json:async()=>({error:'Fixture service unavailable'})};
    if(endpoint==='settings'){
        if(options.method==='PUT'){
            const body=JSON.parse(options.body);assert.equal(options.headers['X-RiverLB-Request'],'configure');publicState.settings=body.settings;
            if(body.backup_passphrase)publicState.backup_key_configured=true;
        }data=publicState;
    }else if(endpoint==='health')data={version:'fixture',revision:1,cpu_percent:null,system:{memory:{used_percent:12.5},disk:null,uptime_seconds:7200,time_synchronized:null,interfaces:[{name:'eth0',state:'up',mtu:1500}]},ha:{role:'standalone',configuration_sync:'standalone'}};
    else if(endpoint.startsWith('audit?'))data={total:51,entries:[{id:1,created:100,actor:'fixture',action:'Configuration applied'}]};
    else if(endpoint==='backup/restore')data={valid:true,staged:JSON.parse(options.body).stage,summary:{created:100,administrators:1,configuration_revisions:3,device_certificates:2,virtual_server_certificates:1},message:'Backup staged. Activate from the console.'};
    else if(endpoint==='backup/download')data={format:'fixture-encrypted-backup'};
    else if(endpoint==='alerts/refresh')data=publicState;
    else throw Error('Unexpected operations request '+url);
    return {ok:true,json:async()=>JSON.parse(JSON.stringify(data))};
};
w.eval(fs.readFileSync(path.join(root,'web/operations.js'),'utf8'));
const settle=()=>new Promise(resolve=>setTimeout(resolve,10));
async function navigate(page){for(const element of d.querySelectorAll('[data-page]'))element.hidden=element.dataset.page!==page;w.dispatchEvent(new w.CustomEvent('riverlb:page',{detail:{page}}));await settle();}
const button=(parent,text)=>[...parent.querySelectorAll('button')].find(element=>element.textContent===text);
const input=(parent,label)=>[...parent.querySelectorAll('label')].find(element=>element.querySelector('span')?.textContent===label)?.querySelector('input');
function snapshot(page){
    if(!process.env.UI_SNAPSHOT_DIR)return;
    const clone=d.documentElement.cloneNode(true);for(const script of clone.querySelectorAll('script'))script.remove();
    clone.querySelector('link[rel=stylesheet]').href='file://'+path.join(root,'web/style.css');
    const title=clone.querySelector('#page-title');title.textContent={'system-health':'System Health',alerts:'Alerts',backups:'Backups & Recovery','audit-events':'Audit Events'}[page];
    clone.querySelector('#breadcrumb').textContent='RiverLB / System / '+title.textContent;
    clone.querySelector('.apply-bar').hidden=true;
    clone.querySelector('#appliance-hostname').textContent='riverlb-fixture';clone.querySelector('#appliance-role').textContent='Standalone';clone.querySelector('#appliance-sync').textContent='Local configuration';clone.querySelector('#appliance-pending').hidden=false;clone.querySelector('#appliance-pending').textContent='Configuration applied';
    for(const field of clone.querySelectorAll('input')){const real=d.getElementById(field.id)||[...d.querySelectorAll('input')][[...clone.querySelectorAll('input')].indexOf(field)];if(field.type==='password'||field.type==='file')field.setAttribute('value','');else if(real){field.setAttribute('value',real.value);if(real.checked)field.setAttribute('checked','');else field.removeAttribute('checked');}}
    fs.mkdirSync(process.env.UI_SNAPSHOT_DIR,{recursive:true});fs.writeFileSync(path.join(process.env.UI_SNAPSHOT_DIR,page+'.html'),'<!doctype html>\n'+clone.outerHTML);
}
(async()=>{
    await navigate('system-health');const health=d.getElementById('operations-health');
    assert.match(health.textContent,/Collecting/);assert.match(health.textContent,/Unavailable/);assert.match(health.textContent,/Unknown/);assert.doesNotMatch(health.textContent,/undefined/);
    assert.equal(health.querySelector('.table-scroll').tabIndex,0);snapshot('system-health');
    await navigate('alerts');const alerts=d.getElementById('operations-alerts');assert.match(alerts.textContent,/No active alerts/);
    const memory=input(alerts,'Memory threshold (%)');memory.value='85';await button(alerts,'Save alert settings').onclick();
    assert.equal(publicState.settings.alerts.memory_percent,85);assert.match(alerts.textContent,/Alert settings saved/);assert.match(alerts.textContent,/unconfirmed configuration/);snapshot('alerts');
    await navigate('audit-events');const audit=d.getElementById('operations-audit');
    assert.equal(button(audit,'Previous').disabled,true);assert.equal(button(audit,'Next').disabled,false);
    input(audit,'Search text').value='configuration';await button(audit,'Search').onclick();
    assert.match(calls.at(-1).url,/query=configuration/);await button(audit,'Next').onclick();assert.match(calls.at(-1).url,/offset=50/);snapshot('audit-events');
    await navigate('backups');const backups=d.getElementById('operations-backups');
    assert.match(backups.textContent,/Schedule disabled/);const pass=input(backups,'Encryption passphrase (12+ bytes)');pass.value='fixture-password-123';await button(backups,'Save backup settings').onclick();assert.equal(publicState.backup_key_configured,true);assert.equal(pass.value,'');
    const restore=[...backups.querySelectorAll('section')].find(section=>section.querySelector('h3')?.textContent==='Restore backup');
    const file=input(restore,'Encrypted backup file'),restorePass=input(restore,'Backup passphrase');
    Object.defineProperty(file,'files',{configurable:true,value:[{size:10,text:async()=>JSON.stringify({format:'fixture'})}]});
    restorePass.value='restore-fixture-password';await button(backups,'Validate backup').onclick();
    const stage=button(backups,'Stage restore');assert.equal(stage.disabled,false);assert.match(backups.textContent,/Local accounts/);assert.match(backups.textContent,/Configuration revisions/);
    await stage.onclick();assert.match(backups.textContent,/Activate from the console/);assert.equal(stage.disabled,true);
    restorePass.value='restore-fixture-password';await button(backups,'Validate backup').onclick();const before=calls.length;
    await navigate('overview');await stage.onclick();assert.equal(calls.length,before);assert.equal(restorePass.value,'');
    await navigate('backups');snapshot('backups');
    fail=true;await navigate('alerts');assert.equal(d.getElementById('operations-alerts').querySelector('[role=alert]').textContent,'Fixture service unavailable');assert.equal(d.getElementById('operations-alerts').hasAttribute('aria-busy'),false);
    dom.window.close();console.log('PASS operations GUI: unknown metrics, accessible tables, independent settings, audit pagination, restore review/staging, credential cleanup, errors and snapshots');
})().catch(error=>{console.error(error);process.exitCode=1;dom.window.close();});
