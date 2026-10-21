// DOM behavior tests. Socket/kernel effects are covered by Python integration tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '..');
const builtinRiverRules = JSON.parse(fs.readFileSync(path.join(root, 'src/river_rules.json'), 'utf8'));
const dom = new JSDOM(fs.readFileSync(path.join(root, 'web/index.html'), 'utf8'), {
    url: 'http://localhost:9090', runScripts: 'outside-only', pretendToBeVisual: true
});
const window = dom.window;
let current = {
    management: '127.0.0.1:9090', connect_timeout_ms: 200, session_timeout_secs: 10,
    health_interval_secs: 1, max_connections: 64,
    virtual_servers: [{ name: 'existing', listen: '127.0.0.1:8080', algorithm: 'round_robin', members: ['127.0.0.1:8001'] }]
};
let revision = 1, saved;
let adapterTrial={pending:false},adapterRequest;
const adapterSettings={ifname:'eth1',uuid:null,mtu:1500,route_metric:600,autoconnect:true,ipv4:{method:'disabled',addresses:[],gateway:null,dns:[],default_route:false},ipv6:{method:'disabled',addresses:[],gateway:null,dns:[],default_route:false}};
let eth1Available = true;
let liveState = 'up', statusFailure = false;
let overviewMembers=[],overviewTraffic;
let haStatus = {role:'standalone',hostname:'lb-test',configuration_sync:'standalone'};
let haGroup=null,haAction=null;
let haDeployRequest=null;
let localAdministrators=['admin'],adminChange;
let importedCertificate, clearedPersistence = false, builtinCatalogReads=0;
let renewalJobs=[], stagedBackup;
window.confirm = () => true;
window.setInterval = () => 1;
window.clearInterval = () => {};
window.Element.prototype.scrollIntoView = () => {};
window.scrollTo = () => {};
let generatedCertificate=null,deviceGenerated=null,csrGenerated=null,csrCompleted=null;
const pendingRequests={device:[],virtual_server:[]},completedCertificates={device:[],virtual_server:[]};
const certFixture=(name,names)=>({name,dns_names:names??[],ip_addresses:[],subject:'CN='+name,issuer:'CN=Fixture',serial:'01',fingerprint_sha256:'123',not_before:1,not_after:2000000000,valid_now:true,days_remaining:30,chain_length:1,used_by:[]});
window.eval(fs.readFileSync(path.join(root,'web/fencing.js'),'utf8'));
const fenceCatalog={platforms:[{id:'physical',label:'Physical server',available:true,agents:['fence_ipmilan']}],agents:[{name:'fence_ipmilan',label:'IPMI',description:'Remote power control',platform:'physical',target_parameter:null,can_list:false,can_status:true,parameters:[{name:'ipaddr',label:'Management address',type:'string',required:true},{name:'passwd',label:'Password',type:'string',secret:true}]}]};
window.fetch = async (url, options = {}) => {
    if(url==='/api/v1/ha/deployment/fencing')return {ok:true,text:async()=>JSON.stringify(fenceCatalog)};
    if(url==='/api/v1/ha/deployment') {
        if(options.method==='POST'){haDeployRequest=JSON.parse(options.body);return {ok:true,text:async()=>JSON.stringify({job:'123',message:'HA deployment operation queued'})};}
        return {ok:true,text:async()=>JSON.stringify({installed:true,identity:{sync_public_key:'ssh-ed25519 SYNC',host_public_key:'ssh-ed25519 HOST',host_fingerprint:'SHA256:verified',fence_agents:['fence_ipmilan']},job:null})};
    }
    if(url==='/api/v1/network/adapter-change')return {ok:true,text:async()=>JSON.stringify(adapterTrial)};
    if(url.startsWith('/api/v1/network/adapter-change/')){assert.equal(JSON.parse(options.body).token,adapterTrial.token);adapterTrial={pending:false};return {ok:true,text:async()=>JSON.stringify({pending:false,message:'Interface configuration applied'})};}
    if(url.startsWith('/api/v1/network/adapters/'))return {ok:true,text:async()=>JSON.stringify({settings:adapterSettings,editing_supported:true,active:false})};
    if(url==='/api/v1/network/adapters'){adapterRequest=JSON.parse(options.body);adapterTrial={pending:true,token:'fixture-token',ifname:adapterRequest.ifname,seconds_remaining:90};return {ok:true,text:async()=>JSON.stringify(adapterTrial)};}
    if(url==='/api/v1/river-rules/builtins'){builtinCatalogReads++;return {ok:true,text:async()=>JSON.stringify({rule_sets:builtinRiverRules})};}
    if(url==='/api/v1/appliance')return {ok:true,text:async()=>JSON.stringify(haStatus)};
    if(url.split('?')[0]==='/api/v1/administrators'){
        let data={current_user:'admin',administrators:localAdministrators};
        if(options.method==='POST'){adminChange=JSON.parse(options.body);if(adminChange.action==='create')localAdministrators.push(adminChange.username);if(adminChange.action==='delete')localAdministrators=localAdministrators.filter(n=>n!==adminChange.username);data={message:'Local administrator updated'};}
        return {ok:true,text:async()=>JSON.stringify(data)};
    }
    if(url==='/api/v1/ha'){
        if(options.method==='PUT')haGroup=JSON.parse(options.body);
        const data=options.method==='PUT'?{message:'HA group saved',restart_required:true}:{group:haGroup,settings:{},status:haStatus,restart_required:false};
        return {ok:true,text:async()=>JSON.stringify(data)};
    }
    if(url==='/api/v1/ha/action'){
        haAction=JSON.parse(options.body).action;
        assert.equal(options.headers['X-RiverLB-Request'],'configure');
        return {ok:true,text:async()=>JSON.stringify({message:'HA '+haAction+' requested'})};
    }
    if (url === '/metrics') return { ok: true, text: async () => '# TYPE riverlb_member_healthy gauge\nriverlb_member_healthy 1\n' };
    const body = options.body ? JSON.parse(options.body) : null;
    let data;
    const scope=url.startsWith('/api/v1/device-certificates')?'device':'virtual_server';
    if(url.endsWith('/requests')){
        if(options.method==='POST'){csrGenerated={scope,...body};const request={name:body.name,names:body.names,csr:'-----BEGIN CERTIFICATE REQUEST-----\nfixture\n-----END CERTIFICATE REQUEST-----'};pendingRequests[scope].push(request);data=request;}
        else data=pendingRequests[scope];
    }else if(url.includes('/requests/')&&url.endsWith('/complete')){
        const name=decodeURIComponent(url.split('/').at(-2));csrCompleted={scope,name,...body};const request=pendingRequests[scope].find(r=>r.name===name);completedCertificates[scope].push(certFixture(name,request.names));pendingRequests[scope]=pendingRequests[scope].filter(r=>r.name!==name);data={name};
    }else if(url==='/api/v1/device-certificates/self-signed'){
        deviceGenerated=body;completedCertificates.device.push(certFixture(body.name,body.names));data={name:body.name};
    }else if(url==='/api/v1/device-certificates')data=completedCertificates.device;
    else if(url === '/api/v1/certificates/self-signed') {
        assert.equal(options.headers['X-RiverLB-Request'],'configure');generatedCertificate=body;data={name:body.name};
    } else if(url === '/api/v1/renewals' && options.method === 'POST') {
        assert.equal(options.headers['X-RiverLB-Request'],'configure');renewalJobs=[{settings:body,next_attempt:0,last_success:null,last_error:null}];data={message:'Schedule saved'};
    } else if(url === '/api/v1/renewals') {data=renewalJobs;
    } else if(url === '/api/v1/restore/stage') {stagedBackup=body;data={message:'Validated and staged; activate offline'};
    } else if (url === '/api/v1/certificates' && options.method === 'POST') {
        assert.equal(options.headers['X-RiverLB-Request'], 'configure'); importedCertificate = body; data = { name: body.name };
    } else if (url === '/api/v1/certificates') {
        data = [{ name: 'home', subject: 'CN=app.home', issuer: 'CN=Home CA', serial: '01', dns_names: ['app.home'], fingerprint_sha256: 'abc123', not_before: 100, not_after: 2000000000, valid_now: true, days_remaining: 12, chain_length: 2, used_by: ['renamed'] }];
        data.push(...completedCertificates.virtual_server);
        if(generatedCertificate)data.push({...data[0],name:generatedCertificate.name,dns_names:[generatedCertificate.hostname],used_by:[]});
    } else if (url === '/api/v1/persistence') {
        data = { revision, virtual_servers: [{ virtual_server: 'renamed', profile: 'home-affinity', total_records: clearedPersistence ? 0 : 1, records: clearedPersistence ? [] : [{ source: '192.0.2.0', member: '192.0.2.12:80', expires_in_secs: 60 }] }] };
    } else if (url === '/api/v1/persistence/renamed/clear') {
        assert.equal(options.headers['X-RiverLB-Request'], 'configure'); clearedPersistence = true; data = { cleared: 1 };
    } else if (url === '/api/v1/config' && options.method === 'PUT') {
        assert.equal(body.revision, revision);
        assert.equal(options.headers['X-RiverLB-Request'], 'configure');
        saved = body.config; current = JSON.parse(JSON.stringify(saved)); revision++;
        for(const route of current.domain_routes??[])if(route.enabled&&route.certificate){
            const parent=current.virtual_servers.find(v=>v.name===route.virtual_server);
            const name=parent.name+'-https-'+route.https_port;
            if(!current.virtual_servers.some(v=>v.name===name))current.virtual_servers.push({...JSON.parse(JSON.stringify(parent)),name,listen:parent.listen.replace(/:[0-9]+$/,':'+route.https_port),domain_tls_parent:parent.name,certificate:route.certificate,sni_certificates:{[route.hostname]:route.certificate},members:[],node_members:[]});
        }
        data = { revision, management_url: (current.management_protocol==='https'?'https://':'http://') + current.management, message: 'Saved' };
    } else if (url === '/api/v1/config/history') {
        data = [{ revision: 1, created: 100, actor: 'admin' }];
    } else if (url === '/api/v1/config/history/1') {
        data = { ...current, virtual_servers: current.virtual_servers.map(v => ({ ...v, description: 'Restored draft' })) };
    } else if (url === '/api/v1/config') {
        data = { revision, config: current, network_mode: 'external' };
    } else if (url === '/api/v1/status') {
        if (statusFailure) throw Error('Status unavailable');
        data = { pools:(current.pools ?? []).map(p=>({name:p.name,state:liveState})),virtual_servers: current.virtual_servers.map(v => ({ ...v, state:v.enabled === false ? 'disabled' : liveState, enabled: v.enabled !== false, members: overviewMembers, traffic:overviewTraffic })) };
        data.ha = haStatus;
    } else if (url === '/api/v1/nodes') {
        data = (current.nodes ?? []).map(n => ({...n,state:n.enabled === false ? 'Disabled' : ({up:'Up',down:'Down',unknown:'Unused',unavailable:'Unavailable'})[liveState],active:0,completed:0,failures:0,instances:[]}));
    } else if (url === '/api/v1/network/interfaces') {
        data = [{ ifname: 'eth0', operstate: 'UP', addr_info: [{ local: '192.0.2.2', prefixlen: 24 }] },
            ...(eth1Available ? [{ ifname:'eth1',operstate:'UP',addr_info:[{local:'198.51.100.2',prefixlen:24}] }] : [])];
    } else if (url === '/api/v1/network/plan') {
        data = { mode: 'external', steps: [{ command: ['link', 'add', 'rlb100'] }] };
    } else if (url === '/api/v1/config/validate') {
        data = { valid: true };
    } else if (url === '/api/v1/statistics') {
        data = { revision, virtual_servers: [{ name: 'renamed', members: [], traffic: { current: 2, peak: 3, accepted: 4, rejected: 0, completed: 1, failures: 0, bytes_in: 1000, bytes_out: 2000 } }], pools: [] };
    } else if (url === '/api/v1/statistics/history') {
        data = [{ created: 100, revision, virtual_servers: [{ name: 'renamed', traffic: { bytes_in: 0, bytes_out: 0 } }] }, { created: 105, revision, virtual_servers: [{ name: 'renamed', traffic: { bytes_in: 1000, bytes_out: 2000 } }] }];
    } else throw Error('Unexpected request: ' + url);
    return { ok: true, text: async () => JSON.stringify(data), json: async () => data };
};
window.eval(fs.readFileSync(path.join(root, 'web/appearance.js'), 'utf8'));
window.eval(fs.readFileSync(path.join(root, 'web/app.js'), 'utf8'));
window.eval(fs.readFileSync(path.join(root, 'web/statistics.js'), 'utf8'));
const document = window.document;
const id = name => document.getElementById(name);
function change(container, name, value) {
    const input = container.querySelector('[name=' + name + ']');
    assert.ok(input, name); input.value = value;
    input.dispatchEvent(new window.Event('input', { bubbles: true }));
}
function members(container,addresses) {
    for(const row of [...container.querySelectorAll('.member-row')])row.querySelector('button').click();
    for(const address of addresses){
        container.querySelector('.add-member').click();const row=container.querySelector('.member-rows').lastElementChild;
        const parts=address.match(/^\[([^\]]+)\]:(\d+)$/)||address.match(/^([^:]+):(\d+)$/);
        change(row,'member_name','test-'+address.replace(/[^a-zA-Z0-9]/g,'-'));
        change(row,'member_ip',parts[1]);change(row,'member_port',parts[2]);
    }
}
async function ready() {
    for (let i = 0; i < 100; i++) {
        await new Promise(resolve => setImmediate(resolve));
        if (!id('apply').disabled) return;
    }
    throw Error('UI stayed busy');
}
(async () => {
    await ready();
    assert.equal(builtinCatalogReads,1,'built-in catalog loads once alongside configuration');
    assert.ok(builtinRiverRules.length>=20,'the built-in catalog covers useful common HTTP operations');
    assert.equal([...id('river-rule-configs').children].filter(c=>c.dataset.builtin==='true').length,builtinRiverRules.length);
    assert.equal(document.querySelectorAll('[data-page]:not([hidden])').length, 1);
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page, 'overview');
    assert.match(id('network-mode').textContent, /OS-provisioned mode/);
    assert.match(id('interfaces').textContent, /eth0.*192.0.2.2/);
    const dirtyBeforeAdapter=id('appliance-pending').textContent;
    document.querySelector('[aria-label="Configure eth1"]').click();await ready();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'interface-editor');
    const adapterEditor=id('interface-editor');
    assert.equal([...document.querySelectorAll('[data-page=interface-editor] button')].filter(b=>b.textContent==='Done').length,1,'Interface editor has one bottom Done action');
    assert.equal(id('interface-apply').textContent,'Enable and apply interface settings');
    assert.equal(adapterEditor.querySelector('[name=adapter_ipv4_method]').value,'disabled');
    assert.equal(adapterEditor.querySelector('[name=adapter_ipv4_default_route]').value,'false');
    change(adapterEditor,'adapter_ipv4_method','manual');
    adapterEditor.querySelector('[name=adapter_ipv4_method]').dispatchEvent(new window.Event('change',{bubbles:true}));
    change(adapterEditor,'adapter_ipv4_addresses','198.51.100.10/24');
    assert.equal(id('appliance-pending').textContent,dirtyBeforeAdapter,'Local interface edits must not change the traffic draft state');
    id('interface-apply').click();await ready();
    assert.equal(adapterRequest.ipv4.method,'manual');
    assert.deepEqual(adapterRequest.ipv4.addresses,['198.51.100.10/24']);
    assert.equal(adapterRequest.ipv4.default_route,false);
    assert.equal(adapterRequest.ipv6.method,'disabled');
    assert.equal(adapterRequest.route_metric,600);
    assert.match(id('appliance-pending').textContent,/Interface change awaiting confirmation/);
    assert.equal(id('interface-apply').disabled,true);
    [...adapterEditor.querySelectorAll('button')].find(b=>b.textContent==='Done').click();await ready();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'interfaces');
    assert.equal(id('interface-change').hidden,false);
    id('interface-change').querySelector('[data-interface-action=confirm]').click();await ready();
    assert.equal(adapterTrial.pending,false);
    assert.equal(id('interface-change').hidden,true);
    adapterSettings.uuid='11111111-1111-4111-8111-111111111111';
    document.querySelector('[aria-label="Configure eth1"]').click();await ready();
    assert.equal(id('interface-apply').textContent,'Enable interface');
    assert.equal(id('interface-editor').querySelector('fieldset').disabled,true,'Saved inactive settings must be activated before editing');
    id('interface-apply').click();await ready();
    assert.equal(adapterRequest.activate_only,true,'Enable must use the saved profile without replacing its settings');
    assert.equal(adapterRequest.uuid,adapterSettings.uuid);
    id('interface-editor-confirmation').querySelector('[data-interface-action=confirm]').click();await ready();
    document.querySelector('[aria-label="Configure eth1"]').click();await ready();
    id('interface-disable').click();await ready();
    assert.equal(adapterRequest.disable,true);
    assert.equal(adapterRequest.activate_only,false);
    assert.equal(id('interface-disable').disabled,true);
    id('interface-editor-confirmation').querySelector('[data-interface-action=confirm]').click();await ready();
    adapterSettings.uuid=null;
    document.querySelector('[aria-label="Configure eth1"]').click();await ready();
    id('interface-apply').click();await ready();
    assert.equal(adapterRequest.activate_only,false);
    assert.equal(adapterRequest.ipv4.method,'disabled','Enabling a new link must not enable DHCP');
    assert.equal(adapterRequest.ipv6.method,'disabled');
    assert.equal(adapterRequest.ipv4.default_route,false);
    id('interface-editor-confirmation').querySelector('[data-interface-action=confirm]').click();await ready();
    assert.equal(saved,undefined,'Interface configuration must not replace the traffic configuration');
    document.querySelector('[data-route=overview]').click();await ready();
    const overviewCard=id('pools').firstElementChild;
    document.querySelector('[data-route=settings]').click();
    await id('refresh').onclick();
    assert.equal(id('pools').firstElementChild,overviewCard,'hidden overview must not rebuild on refresh');
    const beforeStatus=haStatus;haStatus={role:'standalone',hostname:'poll-test',configuration_sync:'standalone'};
    await window.eval('refresh(true)');
    assert.equal(id('appliance-hostname').textContent,'poll-test');
    assert.equal(id('pools').firstElementChild,overviewCard);
    const originalFetch=window.fetch;let completeStatus,statusCalls=0;
    window.fetch=(url,options)=>{
        if(url==='/api/v1/appliance'){statusCalls++;return new Promise(resolve=>{completeStatus=()=>resolve({ok:true,text:async()=>JSON.stringify(haStatus)});});}
        return originalFetch(url,options);
    };
    const firstPoll=window.eval('refresh(true)'),secondPoll=window.eval('refresh(true)');
    assert.equal(firstPoll,secondPoll);assert.equal(statusCalls,1,'slow polling must not queue duplicate requests');
    completeStatus();await firstPoll;window.fetch=originalFetch;
    haStatus=beforeStatus;

    document.querySelector('[data-route=administrators]').click();await ready();
    assert.equal([...id('admin-account-list').querySelectorAll('button')].find(b=>b.textContent==='Delete').disabled,true);
    id('admin-create').click();id('admin-account-name').value='operator';
    id('admin-account-new-password').value='operator-password-123';id('admin-account-confirm-password').value='operator-password-123';id('admin-account-current-password').value='admin-password-123';
    await id('admin-account-save').onclick();assert.equal(adminChange.action,'create');assert.deepEqual(localAdministrators,['admin','operator']);
    assert.equal(id('admin-account-current-password').value,'');
    [...id('admin-account-list').querySelectorAll('tr')[2].querySelectorAll('button')].find(b=>b.textContent==='Delete').click();
    id('admin-account-current-password').value='admin-password-123';await id('admin-account-save').onclick();
    assert.equal(adminChange.action,'delete');assert.deepEqual(localAdministrators,['admin']);

    document.querySelector('[data-route=profiles]').click();
    assert.equal(id('profile-navigation').hidden, false);
    document.querySelector('[data-profile-route=http-profiles]').click();
    assert.equal(id('http-profiles').firstElementChild.hidden, true);
    id('http-profile-list').querySelector('button').click();
    assert.equal(id('http-profiles').firstElementChild.querySelector('[name=http_profile_name]').disabled, true);
    id('add-http-profile').click();
    const httpProfile = id('http-profiles').lastElementChild;
    assert.equal(httpProfile.hidden, false);
    assert.equal(id('http-profile-list').hidden, true);
    assert.match(window.location.hash, /^#http-profiles\/new-/);
    change(httpProfile, 'http_profile_name', 'home-http');
    change(httpProfile, 'http_max_body', '4096');
    id('configuration').dispatchEvent(new window.Event('submit', {bubbles:true,cancelable:true}));
    await ready();
    assert.equal(saved.http_profiles[0].name, 'home-http');
    assert.equal(saved.http_profiles[0].settings.max_body_bytes, 4096);
    assert.equal(window.location.hash, '#http-profiles');
    assert.equal(id('http-profile-list').hidden,false);
    assert.equal([...id('http-profiles').children].filter(c => !c.hidden).length, 0);
    document.querySelector('[data-route=virtual-servers]').click();
    assert.equal(id('servers').firstElementChild.hidden, true);
    assert.equal(id('server-list').hidden, false);
    assert.deepEqual([...id('server-list').querySelectorAll('thead th')].map(cell=>cell.textContent),['','Name','Destination IP','Port','Backend connect','HTTP headers','Health check']);
    assert.equal(id('server-list').querySelector('.object-row').children.length,7);
    id('server-list').querySelector('button').click();
    assert.equal(id('servers').firstElementChild.hidden, false);
    assert.equal(id('server-list').hidden, true);
    assert.equal(window.location.hash, '#virtual-servers/existing');
    await Promise.resolve();
    const vipInput=id('servers').querySelector('[name=listen_ip]');
    assert.match(vipInput.getAttribute('aria-description'),/virtual IP/);
    vipInput.dispatchEvent(new window.Event('pointerover',{bubbles:true}));
    assert.equal(id('configuration-tooltip').hidden,false);
    assert.match(id('configuration-tooltip').textContent,/virtual IP/);
    assert.equal(vipInput.getAttribute('aria-describedby'),'configuration-tooltip');
    document.dispatchEvent(new window.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
    assert.equal(id('configuration-tooltip').hidden,true);
    assert.equal(vipInput.hasAttribute('aria-describedby'),false);
    vipInput.dispatchEvent(new window.FocusEvent('focusin',{bubbles:true}));
    assert.equal(id('configuration-tooltip').hidden,false);
    vipInput.dispatchEvent(new window.FocusEvent('focusout',{bubbles:true}));
    assert.equal(id('configuration-tooltip').hidden,true);

    [...id('servers').firstElementChild.querySelectorAll('button')].find(b=>b.textContent==='Done').click();
    assert.equal(id('servers').firstElementChild.hidden, true);
    document.querySelector('[data-route=overview]').click();await id('refresh').onclick();
    document.querySelector('#pools button').click();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page, 'virtual-servers');
    assert.equal(document.activeElement, document.querySelector('#servers [name=name]'));
    const server = id('servers').firstElementChild;
    assert.deepEqual([...server.querySelectorAll('legend')].map(x => x.textContent), ['General properties','Domain routing','Listener and capacity','Pool assignment','Inline pool settings','Client TLS','Server TLS','Source address translation','HTTP','RiverRules','Cookie persistence','Source persistence']);
    assert.equal(server.querySelector('[name=listen_ip]').closest('fieldset').querySelector('legend').textContent, 'Listener and capacity');
    change(server, 'name', 'renamed');
    change(server, 'enabled', 'false');
    change(server, 'description', 'maintenance');
    change(server, 'algorithm', 'least_connections');
    members(server,['192.0.2.10:80','192.0.2.11:80']);
    document.querySelector('[data-route=vlans]').click();
    assert.equal(document.querySelectorAll('[data-page]:not([hidden])').length, 1);
    assert.equal(id('servers').firstElementChild.querySelector('[name=name]').value, 'renamed');
    id('add-vlan').click();
    const vlan = id('vlans').lastElementChild;
    assert.equal(vlan.querySelector('[name=interface]').value, '');
    change(vlan, 'vlan_name', 'rlb100'); change(vlan, 'interface', 'eth1'); change(vlan, 'tag', '100');
    change(vlan, 'vlan_role', 'internal');
    change(vlan,'ipv4_gateway','192.0.2.1');change(vlan,'ipv6_gateway','2001:db8::1');
    id('add-self-ip').click();
    const ip = id('self-ips').lastElementChild;
    change(ip, 'self_name', 'inside'); change(ip, 'address', '192.0.2.2/24'); change(ip, 'vlan', 'rlb100');
    change(server, 'source_self_ip', 'inside');
    change(server, 'ingress_vlan', 'rlb100');
    change(server, 'backend_vlan', 'rlb100');
    id('add-route').click();
    const route = id('routes').lastElementChild;
    change(route, 'route_name', 'default'); change(route, 'gateway', '192.0.2.1'); change(route, 'vlan', 'rlb100');
    id('network-plan').click(); await ready();
    assert.match(id('network-preview').textContent, /will not execute/);
    assert.match(id('network-preview').textContent, /ip link add rlb100/);
    id('configuration').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await ready();
    assert.equal(saved.virtual_servers[0].name, 'renamed');
    assert.equal(saved.virtual_servers[0].enabled, false);
    assert.equal(saved.virtual_servers[0].source_self_ip, 'inside');
    assert.deepEqual(saved.virtual_servers[0].members, []);
    assert.deepEqual(saved.virtual_servers[0].node_members,['test-192-0-2-10-80','test-192-0-2-11-80']);
    assert.deepEqual(saved.network.vlans[0], { name: 'rlb100', interface: 'eth1', tag: 100, role: 'internal',ipv4_gateway:'192.0.2.1',ipv6_gateway:'2001:db8::1' });
    assert.equal(saved.virtual_servers[0].ingress_vlan, 'rlb100');
    assert.equal(saved.virtual_servers[0].backend_vlan, 'rlb100');
    id('interfaces-refresh').click(); await ready();
    assert.match(id('interfaces').textContent, /rlb100 \(internal, tag 100\)/);
    assert.deepEqual(saved.network.self_ips[0], { name: 'inside', address: '192.0.2.2/24', vlan: 'rlb100' });
    assert.equal(saved.network.routes[0].metric, 100);
    assert.equal(id('new-address').hidden, true);
    document.querySelector('[data-route=overview]').click();await id('refresh').onclick();
    document.querySelector('#pools button').click();
    assert.equal(document.activeElement, document.querySelector('#servers [name=name]'));
    id('routes').querySelector('.danger').click();
    assert.equal(id('routes').children.length, 0);
    id('reload').click(); await ready();
    assert.equal(id('routes').children.length, 1);
    assert.equal(id('vlans').querySelector('[name=interface]').value, 'eth1');
    assert.equal(id('vlans').querySelector('[name=ipv4_gateway]').value,'192.0.2.1');
    assert.equal(id('vlans').querySelector('[name=ipv6_gateway]').value,'2001:db8::1');
    eth1Available = false;
    id('interfaces-refresh').click(); await ready();
    assert.equal(id('vlans').querySelector('[name=interface]').value, 'eth1');
    assert.equal(id('vlans').querySelector('[name=ipv4_gateway]').value,'192.0.2.1');
    assert.equal(id('vlans').querySelector('[name=ipv6_gateway]').value,'2001:db8::1');
    assert.match(id('vlans').querySelector('[name=interface]').selectedOptions[0].textContent, /unavailable/);
    eth1Available = true;
    assert.equal(id('servers').firstElementChild.dataset.originalName, 'renamed');
    document.querySelector('[data-route=pools]').click(); id('add-pool').click();
    const pool = id('pool-configs').lastElementChild;
    assert.deepEqual([...pool.querySelectorAll('legend')].map(x => x.textContent), ['General properties','Health monitoring','Members','Load balancing','Priority groups','Connection limits']);
    change(pool, 'pool_name', 'shared'); change(pool, 'algorithm', 'weighted_round_robin');
    members(pool,['192.0.2.12:80','192.0.2.13:80']);
    change(pool, 'draining_members', '192.0.2.12:80');
    change(pool, 'member_weights', '192.0.2.13:80=3');
    document.querySelector('[data-route=virtual-servers]').click();
    const namedServer = id('servers').firstElementChild;
    change(namedServer, 'default_pool', 'shared');
    assert.equal(namedServer.querySelector('.inline-pool-settings').hidden, true);
    change(namedServer, 'persistence_mode', 'source');
    change(namedServer, 'persistence_timeout', '120');
    change(namedServer, 'persistence_capacity', '250');
    change(namedServer, 'vs_certificate', '/tmp/server-cert.pem');
    change(namedServer, 'vs_private_key', '/tmp/server-key.pem');
    change(namedServer, 'source_nat_mode', 'snat');
    change(namedServer, 'snat_addresses', '192.0.2.50, 192.0.2.51');
    assert.equal(namedServer.querySelector('[name=member_ip]').disabled, true);
    assert.equal(namedServer.querySelector('[name=algorithm]').disabled, true);
    document.querySelector('[data-route=settings]').click();
    change(document, 'health_rise', '2'); change(document, 'health_fall', '3');
    id('configuration').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await ready();
    assert.equal(saved.virtual_servers[0].default_pool, 'shared');
    assert.deepEqual(saved.virtual_servers[0].tls, { certificate: '/tmp/server-cert.pem', private_key: '/tmp/server-key.pem' });
    assert.deepEqual(saved.virtual_servers[0].source_nat, { mode: 'snat', addresses: ['192.0.2.50', '192.0.2.51'] });
    assert.equal(saved.virtual_servers[0].source_self_ip, null);
    assert.deepEqual(saved.virtual_servers[0].persistence, { timeout_secs: 120, max_entries: 250 });
    assert.deepEqual(saved.virtual_servers[0].members, []);
    assert.deepEqual(saved.pools[0], { name: 'shared', algorithm: 'weighted_round_robin', members: [], node_members:['test-192-0-2-12-80','test-192-0-2-13-80'], draining_members: ['192.0.2.12:80'], member_weights: { '192.0.2.13:80': 3 } });
    assert.equal(saved.health_rise, 2); assert.equal(saved.health_fall, 3);
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page, 'settings');
    // Invalid fields on another page must reveal that page before reporting validation.
    change(id('pool-configs').firstElementChild, 'pool_name', '');
    id('configuration').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await ready();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page, 'pools');
    assert.match(id('message').textContent, /highlighted/);
    document.querySelector('[data-route=statistics]').click();
    await id('metrics-refresh').onclick();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page, 'statistics');
    assert.match(id('metrics-output').textContent, /riverlb_member_healthy/);
    await id('traffic-refresh').onclick();
    assert.match(id('traffic-tables').textContent, /Virtual servers.*renamed/);
    assert.ok(id('traffic-chart').querySelector('svg polyline'));
    assert.equal(id('traffic-object').value, 'renamed');
    // A reusable readiness check is editable and assigned through a named pool.
    change(id('pool-configs').firstElementChild, 'pool_name', 'shared');
    document.querySelector('[data-route=monitors]').click(); id('add-monitor').click();
    const monitor = id('health-monitors').firstElementChild;
    change(monitor, 'monitor_name', 'ready'); change(monitor, 'host', 'app.home');
    change(monitor, 'body_contains', 'ready');
    assert.equal(monitor.querySelector('[name=ca_certificate]').disabled, true);
    assert.equal(id('page-done'),null);
    assert.ok(monitor.querySelector('.editor-actions button'));
    assert.equal(id('appliance-pending').hidden, false);
    assert.match(id('appliance-pending').textContent, /Not yet applied/);
    const beforeCloneRevision = revision;
    [...monitor.querySelectorAll('button')].find(b=>b.textContent==='Clone').click();
    const monitorCopy = id('health-monitors').lastElementChild;
    assert.notEqual(monitorCopy, monitor);
    assert.notEqual(monitorCopy.querySelector('[name=monitor_name]').value, 'ready');
    assert.equal(monitorCopy.querySelector('[name=body_contains]').value, 'ready');
    change(monitorCopy, 'host', 'clone.home');
    assert.equal(monitor.querySelector('[name=host]').value, 'app.home');
    [...monitorCopy.querySelectorAll('button')].find(b=>b.textContent==='Done').click();
    assert.equal(id('monitor-list').hidden, false);
    assert.equal(revision, beforeCloneRevision);
    assert.equal(id('appliance-pending').hidden, false);
    await id('refresh').onclick();
    assert.equal(id('appliance-pending').hidden, false);
    for (const protocol of ['icmp','udp','dns','tls']) {
        change(monitorCopy, 'kind', protocol);
        const result = window.eval('collect()').health_monitors[1];
        assert.equal(result.kind, protocol);
        assert.equal(Object.hasOwn(result,'path'), false);
        if(protocol==='udp') {assert.equal(result.send,'ping');assert.equal(result.receive,'pong');}
        if(protocol==='dns') {assert.equal(result.query,'example.com');assert.equal(result.record_type,'A');}
        if(protocol==='tls') {assert.equal(result.host,'clone.home');assert.equal(Object.hasOwn(result,'ca_certificate'),true);}
    }
    [...monitorCopy.querySelectorAll('button')].find(b=>b.textContent==='Remove').click();
    document.querySelector('[data-route=settings]').click();
    assert.equal(id('page-done'),null);
    assert.equal(document.activeElement,id('page-title'));
    document.querySelector('[data-route=overview]').click();
    assert.equal(revision,beforeCloneRevision);
    change(id('pool-configs').firstElementChild, 'monitor', 'ready');
    change(id('servers').firstElementChild, 'app_url', 'https://app.home/');
    id('configuration').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true })); await ready();
    assert.equal(id('appliance-pending').hidden, false);
    assert.match(id('appliance-pending').textContent,/Configuration applied/);
    assert.ok(id('appliance-pending').querySelector('.health-up'));
    assert.equal(saved.health_monitors[0].kind, 'http');
    assert.equal(saved.health_monitors[0].body_contains, 'ready');
    assert.equal(saved.pools[0].monitor, 'ready');
    assert.equal(saved.virtual_servers[0].app_url, 'https://app.home/');
    document.querySelector('[data-route=overview]').click();await id('refresh').onclick();
    const link = document.querySelector('#pools a');
    assert.equal(link.href, 'https://app.home/'); assert.equal(link.rel, 'noopener noreferrer');
    const before = revision;
    await id('history-refresh').onclick();
    await id('configuration-history').querySelector('button').onclick();
    assert.equal(revision, before); // Loading a revision edits the draft only.
    assert.equal(id('servers').querySelector('[name=description]').value, 'Restored draft');
    assert.match(id('message').textContent, /loaded into draft/);
    assert.match(id('revision').textContent, /Unsaved changes/);
    document.querySelector('[data-route=persistence]').click(); id('add-persistence').click();
    const profile = id('persistence-profiles').lastElementChild;
    change(profile,'profile_name','home-affinity'); change(profile,'ipv4_prefix','24'); change(profile,'ipv6_prefix','64'); change(profile,'refresh_on_use','false');
    const assigned = id('servers').firstElementChild;
    change(assigned,'persistence_profile','home-affinity');
    change(assigned,'vs_object','home');
    assert.equal(assigned.querySelector('[name=persistence_timeout]').disabled,true);
    assert.equal(assigned.querySelector('[name=vs_private_key]').disabled,true);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true})); await ready();
    assert.equal(saved.virtual_servers[0].certificate,'home'); assert.equal(saved.virtual_servers[0].tls,undefined);
    assert.equal(saved.virtual_servers[0].persistence_profile,'home-affinity'); assert.equal(saved.virtual_servers[0].persistence,undefined);
    assert.equal(saved.persistence_profiles[0].settings.ipv4_prefix,24); assert.equal(saved.persistence_profiles[0].settings.ipv6_prefix,64);
    assert.equal(saved.persistence_profiles[0].settings.refresh_on_use,false);
    await id('persistence-refresh').onclick(); assert.match(id('persistence-records').textContent,/192.0.2.0/);
    await id('persistence-records').querySelector('button').onclick(); assert.equal(clearedPersistence,true);
    assert.doesNotMatch(id('persistence-records').textContent,/192.0.2.0/);
    document.querySelector('[data-route=certificates]').click();
    id('certificate-create').click();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'certificate-import');
    id('certificate-import-name').value = 'new'; id('certificate-import-pem').value = 'public PEM'; id('certificate-import-key').value = 'private PEM';
    await id('certificate-import').onclick();
    assert.equal(importedCertificate.private_key,'private PEM'); assert.equal(id('certificate-import-key').value,'');
    id('certificate-list').querySelector('button').click();
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'certificate-detail');
    assert.match(id('certificate-detail').textContent,/app.home.*abc123/);
    assert.match(window.location.hash,/#certificate-detail\/virtual_server\/home$/);
    window.eval('navigate(window.location.hash.slice(1),false)');
    assert.match(id('certificate-detail').textContent,/app.home.*abc123/);
    assert.equal(id('certificate-detail').querySelector('button').disabled,true);
    assert.match(id('certificate-detail').querySelector('a').href,/certificates\/objects\/home\/pem/);
    const hashProfile = id('persistence-profiles').lastElementChild;
    change(hashProfile,'persistence_kind','source_hash'); hashProfile.querySelector('[name=persistence_kind]').dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.equal(hashProfile.querySelector('[name=persistence_timeout]').disabled,true);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true})); await ready();
    assert.equal(saved.persistence_profiles[0].settings.kind,'source_hash');
    assert.equal(saved.persistence_profiles[0].settings.timeout_secs,0); assert.equal(saved.persistence_profiles[0].settings.max_entries,0);
    document.querySelector('[data-route=server-tls]').click(); id('add-server-tls').click();
    const serverTls = id('server-tls-profiles').lastElementChild;
    change(serverTls,'server_tls_name','verified-backend');change(serverTls,'server_name','app.home');change(serverTls,'ca_certificate','/etc/riverlb/home-ca.pem');
    change(id('servers').firstElementChild,'server_tls_profile','verified-backend');
    change(id('pool-configs').firstElementChild,'algorithm','weighted_least_connections');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].server_tls_profile,'verified-backend');
    assert.deepEqual(saved.server_tls_profiles,[{name:'verified-backend',server_name:'app.home',ca_certificate:'/etc/riverlb/home-ca.pem'}]);
    assert.equal(saved.pools[0].algorithm,'weighted_least_connections');
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=server_tls_profile]').value,'verified-backend');
    assert.equal(id('server-tls-profiles').lastElementChild.querySelector('[name=server_name]').value,'app.home');
    const capacityPool = id('pool-configs').firstElementChild;
    change(capacityPool,'member_priorities','192.0.2.12:80=100\n192.0.2.13:80=10');
    change(capacityPool,'member_connection_limits','192.0.2.12:80=5');
    change(capacityPool,'priority_group_min_active','1');
    change(id('servers').firstElementChild,'connection_limit','20');
    assert.equal(id('servers').querySelector('[name=member_priorities]').disabled,true);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.deepEqual(saved.pools[0].member_priorities,{'192.0.2.12:80':100,'192.0.2.13:80':10});
    assert.deepEqual(saved.pools[0].member_connection_limits,{'192.0.2.12:80':5});
    assert.equal(saved.pools[0].priority_group_min_active,1);
    assert.equal(saved.virtual_servers[0].connection_limit,20);
    assert.equal(saved.virtual_servers[0].member_priorities,undefined);
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=connection_limit]').value,'20');
    assert.equal(id('pool-configs').querySelector('[name=priority_group_min_active]').value,'1');
    for (const name of ['default_pool','monitor','persistence_profile','server_tls_profile','vs_object','source_self_ip']) assert.equal(id('servers').querySelector('[name=' + name + ']').tagName,'SELECT');
    assert.equal(id('self-ips').querySelector('[name=vlan]').tagName,'SELECT');
    assert.equal(id('vlans').querySelector('[name=interface]').tagName,'SELECT');
    assert.ok([...id('servers').querySelector('[name=default_pool]').options].some(o => o.value === 'shared'));
    change(id('servers').firstElementChild,'persistence_profile','source_addr');
    change(id('pool-configs').firstElementChild,'monitor','tcp');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].persistence_profile,'source_addr');
    assert.equal(saved.persistence_profiles.some(p => p.name === 'source_addr'),false); // Built-in resolves without a saved duplicate.
    assert.equal(saved.health_monitors.find(m => m.name === 'tcp').kind,'tcp');
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=persistence_profile]').value,'source_addr');
    assert.equal(id('pool-configs').querySelector('[name=monitor]').value,'tcp');
    const httpServer = id('servers').firstElementChild;
    document.querySelector('[data-route=cookie-profiles]').click();
    const builtinCookie = id('cookie-profiles').firstElementChild;
    assert.equal(builtinCookie.querySelector('.danger').disabled,true);
    [...builtinCookie.querySelectorAll('button')].find(b=>b.textContent==='Clone').click();
    const customCookie = id('cookie-profiles').lastElementChild;
    assert.equal(customCookie.querySelector('[name=cookie_profile_name]').value,'cookie-copy');
    change(customCookie,'cookie_profile_name','home-cookie');
    change(customCookie,'cookie_name','HOME'); change(customCookie,'cookie_ttl_secs','120');
    change(customCookie,'cookie_http_only','false'); change(customCookie,'cookie_same_site','strict');
    document.querySelector('[data-route=river-rules]').click(); id('add-river-rule').click();
    const ruleObject = id('river-rule-configs').lastElementChild;
    change(ruleObject,'rule_name','guard');
    change(ruleObject,'rule_json',JSON.stringify([{name:'deny',when:{path_prefix:'/private'},actions:[{kind:'respond',status:403,body:'Denied'}]}]));
    change(httpServer,'http_enabled','true'); change(httpServer,'http_cookie_profile','home-cookie');
    change(httpServer,'http_rule_sets','guard');
    assert.equal(httpServer.querySelector('.source-persistence').hidden,true);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].http.cookie_profile,'home-cookie');
    assert.deepEqual(saved.virtual_servers[0].http.rule_sets,['guard']);
    assert.equal(saved.virtual_servers[0].http.cookie,undefined);
    assert.equal(saved.virtual_servers[0].http.rules,undefined);
    const sniServer=id('servers').firstElementChild;
    change(sniServer,'vs_object','home');sniServer.querySelector('.sni-assignments > button').click();
    const sniRow=sniServer.querySelector('.sni-row');change(sniRow,'sni_host','app.home');change(sniRow,'sni_certificate','home');
    assert.ok([...sniRow.querySelector('select').options].some(o=>o.value==='home'));
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.deepEqual(saved.virtual_servers[0].sni_certificates,{'app.home':'home'});
    change(id('http-profiles').lastElementChild,'http_streaming','true');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.http_profiles[0].settings.streaming,true);
    id('renewal-name').value='home';id('renewal-domains').value='app.home\nfiles.home';id('renewal-email').value='admin@home.test';id('renewal-terms').checked=true;
    await id('renewal-save').onclick();
    assert.deepEqual(renewalJobs[0].settings.domains,['app.home','files.home']);
    assert.match(id('renewal-list').textContent,/home.*Queued/);
    id('renewal-list').querySelector('button').click();assert.equal(id('renewal-name').value,'home');
    Object.defineProperty(id('backup-file'),'files',{value:[{size:100,text:async()=>JSON.stringify({format:1,tables:{},sha256:'fixture'})}]});
    await id('backup-stage').onclick();assert.equal(stagedBackup.format,1);assert.match(id('backup-message').textContent,/offline/);
    assert.equal(saved.cookie_profiles[0].settings.name,'HOME');
    assert.equal(saved.cookie_profiles[0].settings.http_only,false);
    assert.equal(saved.river_rules[0].rules[0].actions[0].status,403);
    assert.equal(saved.virtual_servers[0].persistence_profile,undefined);
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=http_cookie_profile]').value,'home-cookie');
    assert.equal(id('cookie-profiles').lastElementChild.querySelector('[name=cookie_ttl_secs]').value,'120');
    assert.match(id('river-rule-configs').querySelector('[name=rule_json]').value,/Denied/);
    [...id('river-rule-configs').firstElementChild.querySelectorAll('button')].find(b=>b.textContent==='Copy').click();
    assert.equal(id('river-rule-configs').lastElementChild.querySelector('[name=rule_name]').value,'guard-copy');
    assert.match(id('river-rule-configs').lastElementChild.querySelector('[name=rule_json]').value,/Denied/);
    const assignedServer = id('servers').firstElementChild;
    change(assignedServer,'http_rule_sets','guard-copy');
    assert.match(assignedServer.querySelector('.rule-assignments').textContent,/1\. guard.*2\. guard-copy/);
    assignedServer.querySelector('.rule-assignments').lastElementChild.querySelector('button').click();
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.deepEqual(saved.virtual_servers[0].http.rule_sets,['guard-copy','guard']);
    // Old inline settings are converted into draft objects without dropping behavior.
    const legacy = JSON.parse(JSON.stringify(saved));
    legacy.virtual_servers[0].http = {cookie:{name:'LEGACY',ttl_secs:90,max_entries:10},rules:[{name:'legacy',when:{},actions:[{kind:'respond',status:403,body:'Legacy'}]}]};
    id('import-json').value = JSON.stringify(legacy); await id('import').onclick();
    assert.ok([...id('cookie-profiles').children].some(c => c.querySelector('[name=cookie_name]').value === 'LEGACY'));
    assert.match(id('servers').querySelector('[name=http_cookie_profile]').value,/cookie/);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].http.cookie,undefined);
    assert.equal(saved.virtual_servers[0].http.rules,undefined);
    document.querySelector('[data-route=nodes]').click(); id('add-node').click();
    const newNode=id('node-configs').lastElementChild;
    change(newNode,'node_name','home-node'); change(newNode,'node_address','192.0.2.30:8080');
    change(newNode,'node_description','Home application');
    document.querySelector('[data-route=domain-routing]').click(); id('add-domain-route').click();
    const newRoute=id('domain-route-configs').lastElementChild;
    change(newRoute,'domain_route_name','home-route'); change(newRoute,'domain_hostname','app.home');
    change(newRoute,'domain_virtual_server',id('servers').querySelector('[name=name]').value);
    change(newRoute,'domain_node','home-node');
    assert.ok([...newRoute.querySelector('[name=domain_node]').options].some(o=>o.value==='home-node'));
    assert.equal(newRoute.hidden,false);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true})); await ready();
    assert.equal(saved.nodes.find(n=>n.name==='home-node').address,'192.0.2.30:8080');
    assert.equal(saved.domain_routes[0].node,'home-node');
    assert.equal(saved.domain_routes[0].hostname,'app.home');
    id('reload').click(); await ready();
    assert.equal([...id('node-configs').children].find(c=>c.querySelector('[name=node_name]').value==='home-node').querySelector('[name=node_description]').value,'Home application');
    assert.equal(id('domain-route-configs').querySelector('[name=domain_node]').value,'home-node');
    assert.ok([...id('pool-configs').querySelector('[name=existing_member]').options].some(o=>o.value==='home-node'));
    const typedServer=id('servers').firstElementChild;
    change(typedServer,'server_type','domain_routing');
    change(typedServer,'hostname_miss_body','Application not found.');
    assert.equal(typedServer.querySelector('[name=http_enabled]').value,'true');
    assert.equal(typedServer.querySelector('[name=http_enabled]').disabled,true);
    assert.equal(typedServer.querySelector('.inline-pool-settings').hidden,true);
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].server_type,'domain_routing');
    assert.equal(saved.virtual_servers[0].default_pool,null);
    assert.deepEqual(saved.virtual_servers[0].members,[]);
    assert.equal(saved.virtual_servers[0].hostname_miss_body,'Application not found.');
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=server_type]').value,'domain_routing');
    assert.equal(id('servers').querySelector('[name=hostname_miss_body]').value,'Application not found.');
    // Route HTTPS offers existing certificates, local generation, and deliberate ACME issuance.
    let tlsRoute=id('domain-route-configs').firstElementChild;
    change(tlsRoute,'domain_tls_mode','existing');change(tlsRoute,'domain_certificate','home');
    change(tlsRoute,'domain_https_port','8443');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.domain_routes[0].certificate,'home');assert.equal(saved.domain_routes[0].https_port,8443);
    const managedHttps=[...id('servers').children].find(c=>c.dataset.generatedDomainTls);
    assert.ok(managedHttps);assert.equal(managedHttps.querySelector('[name=listen_port]').disabled,true);
    assert.ok(![...id('domain-route-configs').querySelector('[name=domain_virtual_server]').options].some(o=>o.value===managedHttps.querySelector('[name=name]').value));
    tlsRoute=id('domain-route-configs').firstElementChild;
    change(tlsRoute,'domain_tls_mode','self_signed');change(tlsRoute,'domain_certificate_name','home-local');
    change(tlsRoute,'domain_certificate_days','30');await tlsRoute.querySelector('.domain-certificate-action').onclick();
    assert.deepEqual(generatedCertificate,{name:'home-local',hostname:'app.home',days:30});
    assert.equal(tlsRoute.querySelector('[name=domain_certificate]').value,'home-local');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.domain_routes[0].certificate,'home-local');
    tlsRoute=id('domain-route-configs').firstElementChild;
    change(tlsRoute,'domain_tls_mode','lets_encrypt');change(tlsRoute,'domain_certificate_name','home-public');
    change(tlsRoute,'domain_le_email','admin@example.test');
    const previousJobs=renewalJobs;await tlsRoute.querySelector('.domain-certificate-action').onclick();
    assert.equal(renewalJobs,previousJobs); // Agreement must be accepted before issuing.
    tlsRoute.querySelector('[name=domain_le_terms]').checked=true;
    await tlsRoute.querySelector('.domain-certificate-action').onclick();
    assert.equal(renewalJobs[0].settings.name,'home-public');
    assert.deepEqual(renewalJobs[0].settings.domains,['app.home']);
    assert.equal(renewalJobs[0].settings.challenge_listen,saved.virtual_servers[0].listen);
    await tlsRoute.querySelector('.domain-certificate-check').onclick();
    assert.match(tlsRoute.querySelector('.domain-certificate-status').textContent,/not issued yet/);
    change(tlsRoute,'domain_tls_mode','off');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.domain_routes[0].certificate,undefined);
    assert.equal(id('domain-route-configs').querySelector('[name=domain_certificate]').disabled,true);
    // No persistence clears named affinity and HTTP cookie assignment, including on reload.
    change(id('servers').firstElementChild,'persistence_profile','source_hash');
    assert.equal(id('servers').querySelector('[name=persistence_mode]').value,'source');
    change(id('servers').firstElementChild,'persistence_mode','none');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.deepEqual(saved.virtual_servers[0].persistence,{timeout_secs:0,max_entries:0});
    assert.equal(saved.virtual_servers[0].persistence_profile,undefined);
    assert.equal(saved.virtual_servers[0].http.cookie_profile,undefined);
    id('reload').click();await ready();
    assert.equal(id('servers').querySelector('[name=persistence_mode]').value,'none');
    // Live health changes keep the current editor open, and stale status becomes unknown.
    document.querySelector('[data-route=nodes]').click();
    id('node-list').querySelector('button').click();
    const editorHash=window.location.hash;
    current.virtual_servers[0].enabled=true;
    for (const state of ['up','down','unavailable','unknown']) {
        liveState=state;await id('refresh').onclick();
        assert.equal(window.location.hash,editorHash);
        assert.ok(id('node-configs').querySelector('.health-' + state));
        assert.ok(id('server-list').querySelector('.health-' + state));
        assert.ok(id('pool-list').querySelector('.health-' + state));
    }
    current.virtual_servers[0].enabled=false;await id('refresh').onclick();
    assert.ok(id('server-list').querySelector('.health-disabled'));
    statusFailure=true;await id('refresh').onclick();
    assert.ok(id('node-configs').querySelector('.health-unknown'));
    statusFailure=false;
    haStatus={role:'standby',hostname:'lb-b',configuration_sync:'synchronized',local_configuration_acknowledged:true,node_id:'riverlb-b',peer_id:'riverlb-a',last_received:100};
    await id('refresh').onclick();
    assert.equal(id('ha-summary').hidden,false);
    assert.match(id('ha-summary').textContent,/standby/i);
    assert.equal(id('apply').disabled,true);
    haStatus={role:'active',hostname:'lb-a',configuration_sync:'error',node_id:'riverlb-a',peer_id:'riverlb-b',sync_error:'Peer unreachable'};
    await id('refresh').onclick();
    assert.match(id('ha-summary').textContent,/Peer unreachable/);
    assert.equal(id('apply').disabled,false);
    document.querySelector('[data-route=ha]').click();await ready();
    assert.equal(id('ha-deploy-identity').hidden,false);
    assert.equal(id('ha-deploy-host-fingerprint').value,'SHA256:verified');
    await document.querySelector('[data-ha-deploy=prepare]').onclick();
    assert.equal(haDeployRequest,null,'HTTP management must not send deployment passwords');
    dom.reconfigure({url:window.location.href.replace(/^http:/,'https:')});
    id('ha-fence-platform').value='physical';id('ha-fence-platform').onchange();id('ha-fence-coverage').value='local';id('ha-fence-coverage').onchange();
    for(const action of ['prepare','trust','authenticate','start','fence']) {
        id('ha-deploy-password').value='Admin-proof-password';
        id('ha-deploy-cluster-password').value='Cluster-fixture-password';
        id('ha-deploy-peer-sync').value='ssh-ed25519 PEER-SYNC';
        id('ha-deploy-peer-host').value='ssh-ed25519 PEER-HOST';
        id('ha-deploy-peer-fingerprint').value='SHA256:peer';
        id('ha-deploy-fence-agent').value='fence_ipmilan';
        id('ha-deploy-fence-resource').value='fence-a';
        id('ha-deploy-fence-parameters').value='{"pcmk_delay_max":"3s"}';
        id('ha-fence-connection').querySelector('[name=ipaddr]').value='192.0.2.100';id('ha-fence-connection').querySelector('[name=passwd]').value='private-fence-password';
        await document.querySelector('[data-ha-deploy='+action+']').onclick();
        assert.equal(haDeployRequest.action,action);
        assert.equal(haDeployRequest.current_password,'Admin-proof-password');
        assert.equal(id('ha-deploy-password').value,'');
        assert.equal(id('ha-deploy-cluster-password').value,'');
        if(action==='fence'){assert.equal(id('ha-fence-connection').querySelector('[name=passwd]').value,'');assert.equal(haDeployRequest.fence_agent,'fence_ipmilan');assert.equal(haDeployRequest.fence_parameters.passwd,'private-fence-password');assert.equal(id('ha-deploy-fence-parameters').value,'');}
        await id('ha-deploy-refresh').onclick();
    }
    dom.reconfigure({url:window.location.href.replace(/^https:/,'http:')});
    const groupFields=id('ha-group-fields');
    change(groupFields,'cluster_id','test-group');change(groupFields,'node_id','a');change(groupFields,'peer_id','b');
    change(groupFields,'local_address','192.0.2.10');change(groupFields,'peer_address','192.0.2.20');
    change(groupFields,'floating_self_ips','external, internal');change(groupFields,'automatic_sync','false');
    change(groupFields,'fencing_resources','fence-node-a, fence-node-b');
    await id('ha-save').onclick();
    assert.equal(haGroup.automatic_sync,false);assert.deepEqual(haGroup.floating_self_ips,['external','internal']);
    await document.querySelector('[data-ha-action=sync]').onclick();assert.equal(haAction,'sync');
    await document.querySelector('[data-ha-action=failover]').onclick();assert.equal(haAction,'failover');
    haStatus={role:'standby'};await id('ha-refresh').onclick();
    assert.equal(document.querySelector('[data-ha-action=sync]').disabled,true);
    assert.equal(document.querySelector('[data-ha-action=failover]').disabled,false);
    haStatus={role:'active',hostname:'lb-a',configuration_sync:'pending changes',local_configuration_acknowledged:false,automatic_sync:false,last_sent:100};
    await id('refresh').onclick();assert.ok(id('appliance-sync').querySelector('.health-pending'));
    assert.match(id('appliance-sync').textContent,/not pushed/);
    document.querySelector('[data-route=ha-sync]').click();await ready();
    await document.querySelector('[data-page=ha-sync] [data-ha-action=sync]').onclick();
    assert.equal(id('message').hidden,false);
    assert.ok(id('page-content').contains(id('ha-sync-details')));
    assert.match(id('ha-sync-details').textContent,/Manual/);assert.match(id('ha-sync-details').textContent,/pending changes/);
    assert.equal(id('configuration').querySelector('.apply-bar').hidden,true);
    haStatus={...haStatus,configuration_sync:'synchronized',local_configuration_acknowledged:true};
    await id('refresh').onclick();assert.ok(id('appliance-sync').querySelector('.health-up'));
    for(const route of ['overview','virtual-servers','settings','statistics']){
        document.querySelector('[data-route='+route+']').click();assert.equal(id('ha-summary').hidden,false);
        assert.equal(id('appliance-hostname').textContent,'lb-a');
    }
    await id('refresh').onclick();
    statusFailure=true;await id('refresh').onclick();assert.equal(id('appliance-sync').querySelector('.health-up'),null);
    assert.match(id('appliance-sync').textContent,/unknown/i);statusFailure=false;
    haStatus={role:'standalone',hostname:'lb-test',configuration_sync:'standalone'};await id('refresh').onclick();
    assert.equal(id('ha-summary').hidden,false);
    assert.equal(id('appliance-hostname').textContent,'lb-test');
    assert.match(id('appliance-role').textContent,/Standalone/);
    // Each network/monitor section opens one draft and returns to a clickable list.
    for (const [route,create,target,list] of [
        ['vlans','add-vlan','vlans','vlan-list'],
        ['self-ips','add-self-ip','self-ips','self-ip-list'],
        ['routes','add-route','routes','route-list'],
        ['monitors','add-monitor','health-monitors','monitor-list']
    ]) {
        document.querySelector('[data-route=' + route + ']').click();
        const count=id(target).children.length;
        id(create).click();id(create).click();
        assert.equal(id(target).children.length,count+1);
        assert.equal(id(list).hidden,true);
        assert.equal([...id(target).children].filter(c=>!c.hidden).length,1);
        const draft=id(target).lastElementChild;
        [...draft.querySelectorAll('button')].find(b=>b.textContent==='Done').click();
        assert.equal(id(list).hidden,false);
        id(list).querySelectorAll('button')[id(list).querySelectorAll('button').length-1].click();
        assert.equal(draft.hidden,false);
        draft.querySelector('.danger').click();
    }
    // An untouched route draft must not make unrelated VLAN changes require a route.
    const existingRoutes=JSON.parse(JSON.stringify(current.network.routes));
    document.querySelector('[data-route=routes]').click();id('add-route').click();
    const untouchedRoute=id('routes').lastElementChild;
    document.querySelector('[data-route=vlans]').click();
    id('vlan-list').querySelector('button').click();
    change(id('vlans').firstElementChild,'ipv4_gateway','192.0.2.254');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.network.vlans[0].ipv4_gateway,'192.0.2.254');
    assert.deepEqual(saved.network.routes,existingRoutes);
    assert.equal(untouchedRoute.isConnected,false);
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'vlans');
    // A partially configured route remains a draft and must still be validated.
    document.querySelector('[data-route=routes]').click();id('add-route').click();
    const partialRoute=id('routes').lastElementChild;change(partialRoute,'gateway','192.0.2.1');
    document.querySelector('[data-route=vlans]').click();const beforeRevision=revision;
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(revision,beforeRevision);assert.equal(partialRoute.isConnected,true);
    assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,'routes');
    assert.match(id('message').textContent,/required fields/);
    partialRoute.querySelector('.danger').click();
    // Named, split-field pool members create reusable nodes and stay linked across pools.
    document.querySelector('[data-route=pools]').click();id('add-pool').click();
    let structured=id('pool-configs').lastElementChild;change(structured,'pool_name','structured');
    members(structured,['[2001:db8::10]:18081']);
    let row=structured.querySelector('.member-row');change(row,'member_name','ipv6-app');
    let standalone=[...id('node-configs').children].find(c=>c.querySelector('[name=node_name]').value==='ipv6-app');
    assert.ok(standalone);assert.equal(standalone.querySelector('[name=node_address]').value,'[2001:db8::10]:18081');
    id('add-pool').click();const reused=id('pool-configs').lastElementChild;change(reused,'pool_name','reused');
    const existing=reused.querySelector('[name=existing_member]');existing.value='ipv6-app';existing.dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.equal(reused.querySelector('[name=member_ip]').value,'2001:db8::10');
    change(structured,'member_weights','[2001:db8::10]:18081=3');
    change(structured,'draining_members','[2001:db8::10]:18081');
    change(id('domain-route-configs').firstElementChild,'domain_node','ipv6-app');
    change(row,'member_name','ipv6-member-renamed');
    assert.equal(id('domain-route-configs').querySelector('[name=domain_node]').value,'ipv6-member-renamed');
    change(row,'member_port','18083');assert.equal(reused.querySelector('[name=member_port]').value,'18083');
    change(standalone,'node_address','[2001:db8::11]:18084');
    assert.equal(structured.querySelector('[name=member_ip]').value,'2001:db8::11');
    assert.equal(reused.querySelector('[name=member_port]').value,'18084');
    assert.equal(structured.querySelector('[name=member_weights]').value,'[2001:db8::11]:18084=3');
    assert.equal(structured.querySelector('[name=draining_members]').value,'[2001:db8::11]:18084');
    change(standalone,'node_name','ipv6-renamed');
    assert.equal(reused.querySelector('[name=member_name]').value,'ipv6-renamed');
    standalone.querySelector('.danger').click();assert.ok(standalone.isConnected);
    assert.match(id('message').textContent,/Remove this node from its pool/);
    // A destination uses split IP/port fields, with presets and an editable custom port.
    const destination=id('servers').firstElementChild;
    change(destination,'listen_ip','2001:db8::20');
    const presets=destination.querySelector('[name=listen_port]').closest('label').querySelector('.port-presets');
    presets.value='443';presets.dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.equal(destination.querySelector('[name=listen_port]').value,'443');
    change(destination,'listen_port','18082');assert.equal(presets.value,'');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].listen,'[2001:db8::20]:18082');
    assert.deepEqual(saved.pools.find(p=>p.name==='structured').node_members,['ipv6-renamed']);
    assert.deepEqual(saved.pools.find(p=>p.name==='reused').node_members,['ipv6-renamed']);
    assert.equal(saved.nodes.filter(n=>n.name==='ipv6-renamed').length,1);
    id('reload').click();await ready();
    structured=[...id('pool-configs').children].find(c=>c.querySelector('[name=pool_name]').value==='structured');
    assert.equal(structured.querySelector('[name=member_port]').value,'18084');
    assert.equal(id('servers').querySelector('[name=listen_ip]').value,'2001:db8::20');
    const perRequest = id('servers').firstElementChild;
    change(perRequest,'server_type','http'); change(perRequest,'persistence_mode','none');
    assert.equal(perRequest.querySelector('[name=http_enabled]').value,'true');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.virtual_servers[0].server_type,'http');
    assert.ok(saved.virtual_servers[0].http);
    assert.equal(saved.virtual_servers[0].persistence.timeout_secs,0);
    assert.ok(!saved.virtual_servers[0].http.cookie && !saved.virtual_servers[0].http.cookie_profile);
    window.eval("addMonitor({name:'udp-ui-ready',kind:'udp',interval_secs:1,timeout_ms:100,rise:1,fall:1,send:'probe',receive:'alive'});addServer({name:'udp-ui',server_type:'tcp',listen:'127.0.0.1:18086',algorithm:'round_robin',members:['127.0.0.1:18087']});poolSuggestions();");
    const udpServer=id('servers').lastElementChild;
    change(udpServer,'server_type','udp');
    change(udpServer,'monitor','udp-ui-ready');
    change(udpServer,'udp_idle_timeout_secs','45');
    assert.equal(udpServer.querySelector('[name=http_enabled]').value,'false');
    assert.equal(udpServer.querySelector('[name=vs_object]').closest('fieldset').hidden,true);
    assert.equal(udpServer.querySelector('[name=udp_idle_timeout_secs]').closest('label').hidden,false);
    assert.equal(udpServer.querySelector('[name=persistence_mode] option[value=cookie]').disabled,true);
    assert.ok(id('configuration').checkValidity(),[...id('configuration').querySelectorAll(':invalid')].map(i=>i.name).join(','));
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    const udpSaved=saved.virtual_servers.find(v=>v.name==='udp-ui');
    assert.ok(udpSaved,'UDP draft must be saved');
    assert.equal(udpSaved.server_type,'udp');
    assert.equal(udpSaved.udp_idle_timeout_secs,45);
    assert.ok(!udpSaved.http && !udpSaved.tls && !udpSaved.certificate);
    // Switching back must restore editable TLS controls and hide UDP-only fields.
    const restored=[...id('servers').children].find(c=>c.querySelector('[name=name]').value==='udp-ui');
    change(restored,'server_type','tcp');
    assert.equal(restored.querySelector('[name=vs_object]').disabled,false);
    assert.equal(restored.querySelector('[name=vs_object]').closest('fieldset').hidden,false);
    assert.equal(restored.querySelector('[name=udp_idle_timeout_secs]').closest('label').hidden,true);
    // Remove this isolated fixture before the existing single-server overview assertions.
    restored.remove();
    [...id('health-monitors').children].find(c=>c.querySelector('[name=monitor_name]').value==='udp-ui-ready').remove();
    window.eval('poolSuggestions();mark();');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    await id('refresh').onclick();
    for(const badge of document.querySelectorAll('.health-badge')){
        assert.equal(badge.textContent,'');assert.ok(badge.getAttribute('aria-label'));assert.ok(badge.title);
    }
    document.querySelector('[data-route=river-rules]').click();
    const countBeforeView=id('river-rule-configs').children.length;
    const appliedBeforeBrowse=id('appliance-pending').textContent;
    const catalogEntry=builtinRiverRules[0];
    id('river-rule-search').value=catalogEntry.description;id('river-rule-search').dispatchEvent(new window.Event('input',{bubbles:true}));
    assert.ok([...id('river-rule-list').querySelectorAll('[data-rule-name]')].some(row=>row.dataset.ruleName===catalogEntry.name),'search includes descriptions');
    id('river-rule-search').value='no-matching-rule-fixture';id('river-rule-search').dispatchEvent(new window.Event('input',{bubbles:true}));
    assert.match(id('river-rule-list').textContent,/No matching rule sets/);
    id('river-rule-search').value='';id('river-rule-search').dispatchEvent(new window.Event('input',{bubbles:true}));
    id('river-rule-category').value=catalogEntry.category;id('river-rule-category').dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.ok(id('river-rule-list').querySelectorAll('[data-rule-name]').length);
    for(const row of id('river-rule-list').querySelectorAll('[data-rule-name]'))assert.equal(row.children[1].textContent,catalogEntry.category);
    id('river-rule-category').value='';id('river-rule-category').dispatchEvent(new window.Event('change',{bubbles:true}));
    id('river-rule-source').value='custom';id('river-rule-source').dispatchEvent(new window.Event('change',{bubbles:true}));
    for(const row of id('river-rule-list').querySelectorAll('[data-rule-name]'))assert.equal(row.children[1].textContent,'Custom');
    id('river-rule-source').value='';id('river-rule-source').dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.equal(id('appliance-pending').textContent,appliedBeforeBrowse,'catalog filters must not stage configuration changes');
    assert.equal(id('river-rule-configs').children.length,countBeforeView,'catalog filters must not create rule sets');
    for(const entry of builtinRiverRules)assert.ok([...id('servers').querySelector('[name=http_rule_sets]').options].some(option=>option.value===entry.name),'every built-in is available for assignment');
    const openBuiltin = name => {
        document.querySelector('[data-route=river-rules]').click();
        [...id('river-rule-list').querySelectorAll('button')].find(b=>b.textContent===name).click();
        return [...id('river-rule-configs').children].find(c=>c.querySelector('[name=rule_name]').value===name);
    };
    let builtin=openBuiltin('builtin-http-to-https');
    assert.equal(document.activeElement,builtin.querySelector('h4'),'read-only built-in views must start at the usage information, not jump to bottom actions');
    const redirectMetadata=builtinRiverRules.find(entry=>entry.name==='builtin-http-to-https');
    assert.match(builtin.querySelector('.rule-usage').textContent,/Assign this rule set/);
    assert.ok(builtin.querySelector('.rule-usage').textContent.includes(redirectMetadata.usage));
    assert.ok(builtin.querySelector('.rule-usage').textContent.includes(redirectMetadata.category));
    assert.equal(id('river-rule-configs').children.length,countBeforeView);
    openBuiltin('builtin-http-to-https');
    assert.equal(id('river-rule-configs').children.length,countBeforeView);
    assert.ok(builtin.querySelector('[name=rule_json]').disabled);
    assert.ok(builtin.querySelector('.danger').disabled);
    assert.equal(JSON.parse(builtin.querySelector('[name=rule_json]').value)[0].actions[0].kind,'redirect_https');
    [...builtin.querySelectorAll('button')].find(b=>b.textContent==='Copy').click();
    let customCopy=id('river-rule-configs').lastElementChild;
    assert.equal(customCopy.querySelector('[name=rule_name]').value,'builtin-http-to-https-copy');
    assert.equal(customCopy.querySelector('[name=rule_json]').disabled,false);
    change(customCopy,'rule_json',JSON.stringify([{name:'redirect-to-https',when:{},actions:[{kind:'redirect_https',host:'app.example:8443'}]}]));
    builtin=openBuiltin('builtin-x-forwarded-for');
    assert.equal(JSON.parse(builtin.querySelector('[name=rule_json]').value)[0].actions[0].kind,'set_forwarded_for');
    const assignBuiltins=id('servers').firstElementChild;
    change(assignBuiltins,'http_rule_sets','builtin-x-forwarded-for');
    id('configuration').dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.ok(saved.virtual_servers[0].http.rule_sets.includes('builtin-x-forwarded-for'));
    assert.ok(!saved.river_rules.some(r=>r.name==='builtin-http-to-https'||r.name==='builtin-x-forwarded-for'));
    assert.equal(saved.river_rules.find(r=>r.name==='builtin-http-to-https-copy').rules[0].actions[0].host,'app.example:8443');
    assert.deepEqual(Object.keys(saved.river_rules.find(r=>r.name==='builtin-http-to-https-copy')).sort(),['description','name','rules'],'catalog metadata must not enter saved traffic configuration');
    id('reload').click();await ready();
    builtin=openBuiltin('builtin-http-to-https');
    assert.equal(JSON.parse(builtin.querySelector('[name=rule_json]').value)[0].actions[0].host,undefined);
    assert.ok([...id('river-rule-configs').children].some(c=>c.querySelector('[name=rule_name]').value==='builtin-http-to-https-copy'));
    assert.equal(builtinCatalogReads,1,'discard/reload must reuse the built-in catalog');
    // Both stores support generation, private CSR completion, and scoped certificate choices.
    id('device-certificate-generate-create').click();
    assert.equal(id('certificate-generate-store').value,'device');
    id('certificate-generate-name').value='device-home';id('certificate-generate-names').value='portal.home\n192.0.2.2';id('certificate-generate-days').value='90';
    await id('certificate-generate').onclick();
    assert.equal(deviceGenerated.days,90);assert.deepEqual(deviceGenerated.names,['portal.home','192.0.2.2']);
    assert.ok([...id('device-certificate-names').children].some(c=>c.value==='device-home'));
    assert.ok(![...id('certificate-names').children].some(c=>c.value==='device-home'));
    for(const scope of ['device','virtual_server']){
        id(scope==='device'?'device-certificate-generate-create':'certificate-generate-create').click();
        id('certificate-generate-mode').value='csr';id('certificate-generate-mode').onchange();
        assert.equal(id('certificate-generate-days').disabled,true);
        id('certificate-generate-name').value='external-'+scope;id('certificate-generate-names').value='portal.home';id('certificate-subject-country').value='us';
        await id('certificate-generate').onclick();
        assert.equal(csrGenerated.scope,scope);assert.equal(csrGenerated.subject.country,'US');assert.equal(csrGenerated.days,undefined);
        const request=id('certificate-request-detail');assert.match(request.textContent,/Pending CA signature/);
        assert.ok(request.querySelector('a').href.includes(scope==='device'?'device-certificates':'certificates'));
        document.querySelector('[data-page=certificate-request-detail] .page-done-actions button').click();
        assert.equal(document.querySelector('[data-page]:not([hidden])').dataset.page,scope==='device'?'device-certificates':'certificates','Done returns a signing request to its own certificate store');
        id(scope==='device'?'device-certificate-request-list':'certificate-request-list').querySelector('button').click();
        request.querySelector('textarea').value='SIGNED CHAIN';
        await [...request.querySelectorAll('button')].find(b=>b.textContent==='Import signed certificate').onclick();
        assert.equal(csrCompleted.scope,scope);assert.equal(csrCompleted.certificate,'SIGNED CHAIN');assert.equal(pendingRequests[scope].length,0);
    }
    const settings=id('configuration');change(settings,'management_protocol','https');
    assert.equal(settings.querySelector('[name=management_object]').disabled,false);
    assert.ok([...settings.querySelector('[name=management_object]').options].some(o=>o.value==='device-home'));
    assert.ok(![...settings.querySelector('[name=management_object]').options].some(o=>o.value==='external-virtual_server'));
    const savedBeforeHttps=saved;settings.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved,savedBeforeHttps);assert.match(id('message').textContent,/Select a device certificate/);
    change(settings,'management_object','device-home');const managementAddress=saved.management;
    settings.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.management_protocol,'https');assert.equal(saved.management_certificate,'device-home');assert.equal(saved.management,managementAddress);
    assert.equal(id('new-address').hidden,false);assert.match(id('new-address').href,/^https:/);
    change(settings,'management_protocol','http');settings.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(saved.management_protocol,'http');assert.equal(saved.management_certificate,undefined);assert.equal(saved.management_tls,undefined);
    assert.match(id('new-address').href,/^http:/);
    {
    // Native selects emit input before change: refreshing choices must not erase the selection.
    id('add-node').click();let newNode=id('node-configs').lastElementChild;
    change(newNode,'node_name','new-monitored-node');change(newNode,'node_address','192.0.2.99:8080');
    change(newNode,'node_monitor','tcp');
    settings.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(window.location.hash,'#nodes');assert.equal(id('node-list').hidden,false);
    assert.ok([...id('node-configs').children].every(c=>c.hidden));
    assert.equal(saved.nodes.find(n=>n.name==='new-monitored-node').monitor,'tcp');
    id('add-pool').click();const newPool=id('pool-configs').lastElementChild;
    change(newPool,'pool_name','existing-node-pool');
    const existingNode=newPool.querySelector('[name=existing_member]');existingNode.value='new-monitored-node';
    existingNode.dispatchEvent(new window.Event('input',{bubbles:true}));
    existingNode.dispatchEvent(new window.Event('change',{bubbles:true}));
    assert.equal(newPool.querySelectorAll('.member-row').length,1);
    assert.equal(newPool.querySelector('[name=member_ip]').value,'192.0.2.99');
    assert.equal(newPool.querySelector('[name=member_port]').value,'8080');
    settings.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}));await ready();
    assert.equal(window.location.hash,'#pools');assert.equal(id('pool-list').hidden,false);
    assert.deepEqual(saved.pools.find(p=>p.name==='existing-node-pool').node_members,['new-monitored-node']);
    }
    {
        // Hold every response: all five independent reads must already be in flight.
        const originalFetch=window.fetch,started=[];
        let release;const gate=new Promise(resolve=>{release=resolve;});
        window.fetch=async(url,options)=>{
            if(url==='/api/v1/config'||/^\/api\/v1\/(device-)?certificates(\/requests)?$/.test(url)){
                started.push(url);await gate;
            }
            return originalFetch(url,options);
        };
        const discarded=id('node-configs').firstElementChild.querySelector('[name=node_description]');
        change(id('node-configs').firstElementChild,'node_description','discard this edit');
        const reloading=id('reload').onclick();
        try {
            await new Promise(resolve=>setImmediate(resolve));
            assert.equal(started.length,5);
            assert.equal(id('apply').disabled,true);
            assert.match(id('message').textContent,/Loading configuration/);
        } finally {release();await reloading;window.fetch=originalFetch;}
        assert.equal(id('apply').disabled,false);
        assert.notEqual(id('node-configs').firstElementChild.querySelector('[name=node_description]').value,discarded.value);

        // Hundreds of option insertions must not each trigger a help-label scan.
        let scans=0;const query=window.Element.prototype.querySelectorAll;
        window.Element.prototype.querySelectorAll=function(selector){if(selector==='label' && (this===holder || holder.contains(this)))scans++;return query.call(this,selector);};
        const holder=document.createElement('div'),label=document.createElement('label');
        const input=document.createElement('select');input.name='node_monitor';label.append(input);holder.append(label);
        settings.append(holder);
        for(let i=0;i<200;i++){const option=document.createElement('option');option.value=String(i);input.append(option);}
        try {
            await new Promise(resolve=>setImmediate(resolve));
            assert.ok(scans<=1,'Nested additions should receive one help scan, got '+scans);
            assert.match(input.getAttribute('aria-description'),/Checks this node/);
        }finally{window.Element.prototype.querySelectorAll=query;holder.remove();}
    }
    {
        // Saving must unlock while the noncritical health refresh is still pending.
        const originalFetch=window.fetch;
        let release;const gate=new Promise(resolve=>{release=resolve;});
        window.fetch=async(url,options)=>{
            if(url==='/api/v1/status'||url==='/api/v1/nodes')await gate;
            return originalFetch(url,options);
        };
        let complete=false;
        change(id('node-configs').firstElementChild,'node_description','save without awaiting health');
        const saving=settings.onsubmit({preventDefault(){}}).then(()=>{complete=true;});
        try {
            for(let i=0;i<100 && !complete;i++)await new Promise(resolve=>setImmediate(resolve));
            assert.equal(complete,true,'A pending health response must not keep save locked');
            assert.equal(id('apply').disabled,false);
        }finally{release();await saving;await window.eval("refresh()");window.fetch=originalFetch;}
    }
    // Navigation, landmarks and keyboard interaction survive background refresh.
    assert.equal(id('page-done'),null);
    for(const actions of document.querySelectorAll('.editor-actions:has(> .danger)')){
        assert.ok(actions.lastElementChild.classList.contains('danger'),'Destructive actions follow Done and Clone/Copy');
    }
    assert.equal(document.querySelector('.page-header button')?.textContent,'Refresh status');
    assert.ok(id('page-content').contains(document.querySelector('[data-page=administrators]')));
    id('navigation-toggle').click();assert.equal(id('navigation-toggle').getAttribute('aria-expanded'),'true');
    overviewTraffic={current:2,failures:1,session_timeouts:0,transport_errors:0,backend_errors:1,connect_latency:{samples:10,average_ms:1.25,maximum_ms:3.5},response_latency:{samples:10,average_ms:8.5,maximum_ms:17},probe_latency:{samples:10,average_ms:2,maximum_ms:4}};
    overviewMembers=[{address:'192.0.2.12:80',healthy:true,active:2,completed:12,failures:0,bytes_to_backend:1024,bytes_to_client:2048,last_probe:100,probe_latency_ms:2,traffic:overviewTraffic},{address:'192.0.2.13:80',healthy:false,active:0,completed:5,failures:1,bytes_to_backend:128,bytes_to_client:256,last_probe:100,probe_error:'HTTP status 503 (expected 200)',traffic:overviewTraffic}];
    document.querySelector('[data-route=overview]').click();
    assert.equal(id('navigation-toggle').getAttribute('aria-expanded'),'false');
    await id('refresh').onclick();
    const memberSummary=id('pools').querySelector('details summary');
    assert.ok(memberSummary);memberSummary.parentElement.open=true;memberSummary.focus();await id('refresh').onclick();assert.equal(document.activeElement.tagName,'SUMMARY');assert.equal(document.activeElement.parentElement.open,true);
    assert.equal(id('pools').querySelectorAll('.overview-latency > div').length,3);
    assert.equal(id('pools').querySelectorAll('.overview-table thead th').length,7);
    window.eval("say('Fixture validation error',true)");
    assert.equal(document.activeElement,id('message'));assert.equal(id('message').hidden,false);
    window.eval("say('',false)");
    for(const page of document.querySelectorAll('[data-page]'))assert.ok(id('page-content').contains(page));
    for(const badge of document.querySelectorAll('.health-badge'))assert.equal(badge.getAttribute('role'),'img');
    if(process.env.UI_SNAPSHOT_DIR)await require('./ui_snapshots.cjs')(window,path.resolve(process.env.UI_SNAPSHOT_DIR));
    const failedCatalogDom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'http://localhost:9090',runScripts:'outside-only',pretendToBeVisual:true});
    const retryWindow=failedCatalogDom.window,retryId=name=>retryWindow.document.getElementById(name);
    let catalogUnavailable=true,catalogAttempts=0;
    retryWindow.confirm=()=>true;retryWindow.setInterval=()=>1;retryWindow.clearInterval=()=>{};
    retryWindow.scrollTo=()=>{};retryWindow.Element.prototype.scrollIntoView=()=>{};
    retryWindow.fetch=(url,options)=>{
        if(url==='/api/v1/river-rules/builtins'){
            catalogAttempts++;
            return Promise.resolve(catalogUnavailable?{ok:false,status:503,text:async()=>JSON.stringify({error:'Catalog unavailable'})}:{ok:true,text:async()=>JSON.stringify({rule_sets:builtinRiverRules})});
        }
        return window.fetch(url,options);
    };
    const retryReady=async()=>{for(let i=0;i<100;i++){await new Promise(resolve=>setImmediate(resolve));if(!retryId('apply').disabled)return;}throw Error('Retry UI stayed busy');};
    try {
        retryWindow.eval(fs.readFileSync(path.join(root,'web/app.js'),'utf8'));
        await retryReady();
        assert.match(retryId('message').textContent,/Built-in RiverRules catalog could not be loaded: Catalog unavailable/);
        assert.equal(retryId('river-rule-configs').children.length,0,'failed catalog loads must not substitute local hardcoded built-ins');
        catalogUnavailable=false;retryId('reload').click();await retryReady();
        assert.equal(catalogAttempts,2,'a rejected catalog read must be retryable');
        assert.equal([...retryId('river-rule-configs').children].filter(c=>c.dataset.builtin==='true').length,builtinRiverRules.length);
    } finally {retryWindow.close();}
    console.log('PASS portal: pages, profiles, RiverRules catalog and copies, domain routing/node editors and references, persistence, networking, statistics');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => window.close());
