/* Portal state stays local until a validated, revisioned Save and apply. */
const byId = id => document.getElementById(id);
const form = byId('configuration');
const servers = byId('servers');
const vlans = byId('vlans');
const selfIps = byId('self-ips');
const routes = byId('routes');
const poolConfigs = byId('pool-configs');
const monitors = byId('health-monitors');
const profiles = byId('persistence-profiles');
const serverTlsProfiles = byId('server-tls-profiles');
const cookieProfiles = byId('cookie-profiles');
const riverRules = byId('river-rule-configs');
const httpProfiles = byId('http-profiles');
const nodeConfigs=byId('node-configs'), domainRouteConfigs=byId('domain-route-configs');
let baseConfiguration='';
let haRole='standalone';
let revision = 0, dirty = false, busy = false, activeManagement = '', activeManagementIdentity = '';
const objectLatency={nodes:new Map(),pools:new Map(),monitors:new Map(),'virtual-servers':new Map()};
const health = {nodes:new Map(),pools:new Map(),'virtual-servers':new Map()};
const healthLabels = {up:'Up',down:'Down',disabled:'Disabled',unavailable:'Unavailable',unknown:'Unknown'};
const certificateDetails = new Map(), certificateRequestDetails = new Map();
let certificateStore = 'virtual_server';
const certificateBase = store => store==='device'?'/api/v1/device-certificates':'/api/v1/certificates';
const certificateListPage = store => store==='device'?'device-certificates':'certificates';
const managementIdentity = config => JSON.stringify([config.management,config.management_protocol??(config.management_tls||config.management_certificate?'https':'http'),config.management_certificate??null,config.management_tls??null]);
function latencyText(traffic) {
    const metric=(title,data)=>title+': '+(data?.samples?data.average_ms.toFixed(2)+' ms avg · '+data.maximum_ms.toFixed(2)+' ms max':'—');
    return [metric('Backend connect',traffic?.connect_latency),metric('HTTP headers',traffic?.response_latency),metric('Health check',traffic?.probe_latency)].join(' · ');
}
function latencyCellText(data) {return data?.samples?data.average_ms.toFixed(2)+' ms avg\n'+data.maximum_ms.toFixed(2)+' ms max':'—';}
function latencySummary(route,traffic) {
    if(route!=='monitors')return latencyText(traffic);
    const sample=traffic?.probe_latency;return 'Health check: '+(sample?.samples?sample.average_ms.toFixed(2)+' ms avg · '+sample.maximum_ms.toFixed(2)+' ms max':'No samples yet');
}
function objectLatencyBadge(route,name) {
    const summary=node('span',latencySummary(route,objectLatency[route]?.get(name)));summary.dataset.latencyKind=route;summary.dataset.latencyName=name;return summary;
}
function healthBadge(state = 'unknown', route = '', name = '') {
    if (!healthLabels[state]) state = 'unknown';
    const badge = node('span'); badge.className = 'health-badge';
    badge.dataset.state = state; badge.title = healthLabels[state];
    badge.setAttribute('aria-label',healthLabels[state]); badge.setAttribute('role','img');
    if (route) {badge.dataset.healthKind = route; badge.dataset.healthName = name;}
    const dot = node('span'); dot.className = 'health-dot health-' + state; dot.setAttribute('aria-hidden','true');
    badge.append(dot); return badge;
}
function updateHealthBadges() {
    for(const summary of document.querySelectorAll("[data-latency-kind]")) {const traffic=objectLatency[summary.dataset.latencyKind]?.get(summary.dataset.latencyName);summary.textContent=summary.dataset.latencyMetric?latencyCellText(traffic?.[summary.dataset.latencyMetric]):latencySummary(summary.dataset.latencyKind,traffic);}
    for (const badge of document.querySelectorAll('[data-health-kind]')) {
        const state = health[badge.dataset.healthKind].get(badge.dataset.healthName) ?? 'unknown';
        if(badge.dataset.state!==state)badge.replaceWith(healthBadge(state,badge.dataset.healthKind,badge.dataset.healthName));
    }
}
const pages = {
    administrators:['Local Administrators','System'],
    'system-health':['System Health','System'],alerts:['Alerts','System'],backups:['Backups & Recovery','System'],'audit-events':['Audit Events','System'],security:['Security','System'],updates:['Application Updates','System'],
    ha:['HA Configuration','High Availability'],'ha-sync':['Configuration Sync','High Availability'],
    'device-certificates':['Device Certificates','System'],'certificate-generate':['Generate Certificate / CSR','System'],'certificate-request-detail':['Certificate Signing Request','System'],
    'certificate-import':['Import Certificate','System'],'certificate-detail':['Certificate Details','System'],renewals:['Certificate Renewals','System'],'renewal-editor':['Renewal Schedule','System'],
    nodes:['Nodes','Local Traffic'],'domain-routing':['Domain Routing','Local Traffic'],
    overview: ['Overview', 'RiverLB'], 'virtual-servers': ['Virtual Servers', 'Local Traffic'],
    pools: ['Pools', 'Local Traffic'], interfaces: ['Interfaces', 'Network'], 'interface-editor':['Configure Interface','Network'],
    vlans: ['VLANs', 'Network'], 'self-ips': ['Self IPs', 'Network'], routes: ['Static Routes', 'Network'],
    monitors: ['Health Monitors', 'Local Traffic'], settings: ['Settings', 'System'], 'configuration-files': ['Import / Export', 'System'],
    'server-tls': ['Server TLS Profiles', 'Local Traffic'], certificates: ['Certificates', 'System'], persistence: ['Persistence Profiles', 'Local Traffic'], statistics: ['Statistics', 'System'],
    'cookie-profiles':['Cookie Persistence Profiles','Profiles'],'river-rules':['RiverRules','Local Traffic'],
    profiles:['Profiles','Local Traffic'],'http-profiles':['HTTP Profiles','Profiles']
};
pages.persistence = ['Source Persistence Profiles','Profiles']; pages['server-tls'][1] = 'Profiles';
const objectPages = {
    vlans:{target:vlans,key:'vlan_name',list:'vlan-list'},'self-ips':{target:selfIps,key:'self_name',list:'self-ip-list'},routes:{target:routes,key:'route_name',list:'route-list'},monitors:{target:monitors,key:'monitor_name',list:'monitor-list'},
    nodes:{target:nodeConfigs,key:'node_name',list:'node-list'},'domain-routing':{target:domainRouteConfigs,key:'domain_route_name',list:'domain-route-list'},
    'virtual-servers':{target:servers,key:'name',list:'server-list'},pools:{target:poolConfigs,key:'pool_name',list:'pool-list'},
    persistence:{target:profiles,key:'profile_name',list:'persistence-list'},'server-tls':{target:serverTlsProfiles,key:'server_tls_name',list:'server-tls-list'},
    'cookie-profiles':{target:cookieProfiles,key:'cookie_profile_name',list:'cookie-profile-list'},'http-profiles':{target:httpProfiles,key:'http_profile_name',list:'http-profile-list'},
    'river-rules':{target:riverRules,key:'rule_name',list:'river-rule-list'}
};
const profileRoutes = ['http-profiles','server-tls','persistence','cookie-profiles'];
function navigate(route, update = true) {
    const parts = route.split('/');
    route = parts[0];
    if (!pages[route]) route = 'overview';
    if (byId('configuration-tooltip')) hideConfigurationHelp();
    if (objectPages[route]) showObjectList(route);
    byId('profile-navigation').hidden = route !== 'profiles' && !profileRoutes.includes(route);
    for (const page of document.querySelectorAll('[data-page]')) page.hidden = page.dataset.page !== route;
    if(route!=='interface-editor')for(const fieldset of byId('interface-editor').querySelectorAll('fieldset'))fieldset.disabled=true;
    const activeNavigation=['certificate-detail','certificate-request-detail','certificate-import','certificate-generate'].includes(route)?certificateListPage(parts.length>2?parts[1]:certificateStore):route==='renewal-editor'?'renewals':route==='interface-editor'?'interfaces':route;
    for (const link of document.querySelectorAll('[data-route]')) {
        if (link.dataset.route === activeNavigation) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
    }
    byId('page-title').textContent = pages[route][0];
    byId('breadcrumb').textContent = pages[route][1] + ' / ' + pages[route][0];
    document.title = 'RiverLB · ' + pages[route][0];
    if (update && ['certificates','device-certificates'].includes(route)) {certificateStore=route==='device-certificates'?'device':'virtual_server';refreshCertificates();}
    updateApplyBar();
    if (update && route==='overview')refresh();
    if (update && route==='administrators')refreshAdministrators();
    if (update && route==='interfaces')showInterfaces();
    if (route==='interface-editor' && parts[1]) {try {editInterface(decodeURIComponent(parts[1]));}catch(error){say(error.message,true);}}
    if (update && ['ha','ha-sync'].includes(route)) refreshHaGroup();
    if (update && route === 'renewals') refreshRenewals();
    if (update && route === 'persistence') refreshPersistence();
    if (update) window.history.pushState(null, '', '#' + [route,...parts.slice(1)].join('/'));
    if (update) {
        byId('navigation-toggle').setAttribute('aria-expanded','false');
        document.querySelector('.sidebar').dataset.navigationOpen='false';
        window.scrollTo?.({top:0,behavior:'instant'});
        byId('page-title').focus({preventScroll:true});
    }
    if (parts[1] && objectPages[route]) {
        let name;
        try { name = decodeURIComponent(parts[1]); } catch { return; }
        const {target,key} = objectPages[route];
        const editor = [...target.children].find(c => value(c,key) === name || c.dataset.draftRoute === name);
        if (editor) openObject(editor, route, false);
    }
    window.dispatchEvent(new CustomEvent('riverlb:page',{detail:{page:route}}));
    if (['certificate-detail','certificate-request-detail'].includes(route) && parts[1]) {
        const scoped=parts.length>2;certificateStore=scoped?parts[1]:'virtual_server';
        let name;try{name=decodeURIComponent(parts[scoped?2:1]);}catch{return;}
        const details=(route==='certificate-detail'?certificateDetails:certificateRequestDetails).get(certificateStore+'/'+name);
        byId(route).replaceChildren(details??node('p','Certificate or request not found.'));byId('page-title').textContent=name;
    }

}
for(const page of document.querySelectorAll('[data-page]')) {
    const route=page.dataset.page;
    if(objectPages[route] || ['overview','statistics','profiles','interface-editor'].includes(route))continue;
    const actions=node('div');actions.className='actions editor-actions page-done-actions';
    const done=node('button','Done');done.type='button';done.onclick=()=>{
        if(route==='certificate-import')byId('certificate-import-back').click();
        else if(route==='certificate-generate')byId('certificate-generate-back').click();
        else if(route==='certificate-detail')byId('certificate-detail-back').click();
        else if(route==='certificate-request-detail')byId('certificate-request-back').click();
        else if(route==='renewal-editor')byId('renewal-back').click();
        else if(route==='administrators'&&!byId('admin-account-editor').hidden)byId('admin-account-cancel').click();
        else navigate('overview');
        if(dirty)say('Changes staged. Save and apply to activate them.');
    };actions.append(done);page.append(actions);
}
for (const link of document.querySelectorAll('[data-route]')) link.onclick = event => {
    event.preventDefault(); navigate(link.dataset.route);
};
for (const button of document.querySelectorAll('[data-profile-route]')) button.onclick = () => navigate(button.dataset.profileRoute);
window.addEventListener('hashchange', () => navigate(window.location.hash.slice(1), false));
window.addEventListener('popstate', () => navigate(window.location.hash.slice(1), false));

function showObjectList(route) {
    const {target,key,list:listId} = objectPages[route]; const list = byId(listId);
    document.querySelector('[data-page="'+route+'"]').dataset.editing='false';
    if(route==='river-rules'){showRiverRulesList();return;}
    list.replaceChildren(); list.hidden = false;
    list.classList.add('table-scroll');
    const table=node('table');table.className='object-table';table.dataset.objectKind=route;
    const header=node('tr'),body=node('tbody'),head=node('thead');
    const columns=[];
    if(health[route])columns.push('');
    columns.push('Name',route==='virtual-servers'?'Destination IP':'Details');
    if(route==='virtual-servers')columns.push('Port');
    const metrics=route==='monitors'?[['probe_latency','Health check']]:objectLatency[route]?[['connect_latency','Backend connect'],['response_latency','HTTP headers'],['probe_latency','Health check']]:[];
    for(const [,title] of metrics)columns.push(title);
    for(const title of columns){const cell=node('th',title);cell.scope='col';if(!title)cell.setAttribute('aria-label','Health');header.append(cell);}
    head.append(header);table.append(head,body);
    const caption=node('caption',pages[route][0]);caption.className='visually-hidden';table.prepend(caption);
    if(target.children.length)list.append(table);
    list.tabIndex=0;list.setAttribute('role','region');list.setAttribute('aria-label',pages[route][0]+' list. Scroll horizontally to view all columns.');
    for (const editor of target.children) {
        editor.hidden = true;
        const row = node('tr'); row.className = 'object-row';
        const append=content=>{const cell=node('td');cell.append(content);row.append(cell);};
        if (health[route]) append(healthBadge(health[route].get(value(editor,key)),route,value(editor,key)));
        const link = node('button', value(editor,key) || '(New object)');
        link.type = 'button'; link.onclick = () => openObject(editor, route);
        const detail = route === 'vlans' ? value(editor,'interface')+' · '+value(editor,'vlan_role')+' · '+(value(editor,'tag') ? 'Tag '+value(editor,'tag') : 'Untagged') : route === 'self-ips' ? value(editor,'address')+' · '+value(editor,'vlan') : route === 'routes' ? value(editor,'destination')+' via '+value(editor,'gateway') : route === 'monitors' ? value(editor,'kind')+' · '+value(editor,'interval_secs')+' seconds' : route === 'nodes' ? value(editor,'node_address') : route === 'domain-routing' ? value(editor,'domain_hostname')+' → '+value(editor,'domain_node')+' · '+value(editor,'domain_virtual_server') : route === 'pools' ? value(editor,'algorithm') : route === 'virtual-servers' ? value(editor,'listen_ip')+' : '+value(editor,'listen_port') : editor.dataset.builtin === 'true' ? 'Built-in default — clone to customize' : 'Custom';
        append(link);
        append(node('span',route==='virtual-servers'?value(editor,'listen_ip'):detail));
        if(route==='virtual-servers')append(node('span',value(editor,'listen_port')));
        for(const [metric] of metrics){const cell=node('span',latencyCellText(objectLatency[route].get(value(editor,key))?.[metric]));cell.dataset.latencyKind=route;cell.dataset.latencyName=value(editor,key);cell.dataset.latencyMetric=metric;append(cell);}
        body.append(row);
    }
    if (!target.children.length) list.append(emptyState('No '+pages[route][0].toLowerCase()+' yet','Use Create to configure your first item.'));
}
function openObject(editor, route, update = true) {
    navigate(route, false);
    byId(objectPages[route].list).hidden = true;
    editor.hidden = false;
    document.querySelector('[data-page="'+route+'"]').dataset.editing='true';
    const name = value(editor,objectPages[route].key) || 'New object';
    editor.querySelector('.object-health')?.remove();
    editor.querySelector('.object-latency')?.remove();
    if(objectLatency[route]) {const summary=objectLatencyBadge(route,name);summary.className='object-latency';editor.prepend(summary);}
    if (health[route]) {
        const badge = healthBadge(health[route].get(value(editor,objectPages[route].key)),route,value(editor,objectPages[route].key));
        const summary = node('div'); summary.className = 'object-health'; summary.append(badge); editor.prepend(summary);
    }
    byId('page-title').textContent = name;
    byId('breadcrumb').textContent = pages[route][1] + ' / ' + pages[route][0] + ' / ' + name;
    if (update) window.history.pushState(null, '', '#' + route + '/' + encodeURIComponent(value(editor,objectPages[route].key) || editor.dataset.draftRoute));
    if(route==='river-rules'&&editor.dataset.builtin==='true'){
        const heading=editor.querySelector('h4');heading.tabIndex=-1;
        window.scrollTo?.({top:0,behavior:'instant'});heading.focus({preventScroll:true});
    }else editor.querySelector('input:not(:disabled),select:not(:disabled),button:not(:disabled)')?.focus();
}
for(const button of document.querySelectorAll('button'))if(!button.className&&!/^(Done|Save|Create|Generate|Import|Enable|Sync|Sign)/.test(button.textContent))button.classList.add('secondary');
byId('navigation-toggle').onclick = () => {
    const button=byId('navigation-toggle'),open=button.getAttribute('aria-expanded')!=='true';
    button.setAttribute('aria-expanded',String(open));
    document.querySelector('.sidebar').dataset.navigationOpen=String(open);
};
byId('skip-content').onclick = event => {event.preventDefault();byId('page-content').focus();};
function node(tag, text = '') {
    const element = document.createElement(tag);
    element.textContent = text;
    if (tag === 'button' && !/^(Done|Save|Create|Generate|Import|Enable)/.test(text)) element.className='secondary';
    return element;
}
function emptyState(title, detail) {
    const state=node('div');state.className='empty-state';state.append(node('h3',title),node('p',detail));return state;
}
function scrollTable(table, label) {
    const scroll=node('div');scroll.className='table-scroll';scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label',label+'. Scroll horizontally to view all columns.');scroll.append(table);return scroll;
}
function say(text, failed = false) {
    byId('message').textContent = text;
    byId('message').hidden = !text;
    byId('message').className = 'feedback ' + (failed ? 'feedback-error' : 'feedback-success');
    if (failed || form.querySelector('.apply-bar').hidden) {byId('message').focus({preventScroll:true});byId('message').scrollIntoView({block:'center'});}
}
function updateApplyBar() {
    const route=document.querySelector('[data-page]:not([hidden])')?.dataset.page;
    const independent=['ha','ha-sync','administrators','system-health','alerts','backups','audit-events','security','updates','interface-editor'].includes(route);
    const readOnly=['overview','profiles','interfaces','statistics','certificates','device-certificates','certificate-detail','certificate-request-detail','certificate-import','certificate-generate','renewals','renewal-editor'].includes(route);
    form.querySelector('.apply-bar').hidden=independent||(!dirty&&readOnly);
}
let configurationConfirmation={pending:false};
let interfaceChange={pending:false};
window.riverlbSetConfirmation=state=>{configurationConfirmation=state??{pending:false};renderPendingChanges();};
function renderPendingChanges() {
    updateApplyBar();
    const badge = byId('appliance-pending');
    badge.hidden = false;
    badge.replaceChildren(indicator(interfaceChange.pending ? 'Interface change awaiting confirmation' : configurationConfirmation.pending ? 'Awaiting connectivity confirmation' : dirty ? 'Not yet applied' : (revision ? 'Configuration applied' : 'Configuration loading'), interfaceChange.pending || configurationConfirmation.pending || dirty ? 'pending' : (revision ? 'up' : 'unknown')));
}
function mark() {
    dirty = true;
    renderPendingChanges();
    byId('revision').textContent = 'Unsaved changes · based on revision ' + revision;
}
function lock(value) {
    busy = value;
    for (const input of form.querySelectorAll('button,input,textarea,select')) input.disabled = value;
    if (!value) for (const button of form.querySelectorAll('[data-certificate-in-use=true]')) button.disabled = true;
    if (!value && haRole==='standby')byId('apply').disabled=true;
    if (!value) for (const input of form.querySelectorAll('[data-builtin-readonly=true]')) input.disabled = true;
    if (!value) {for (const profile of profiles.children) syncPersistence(profile); syncTls(form,'management');}
    if (!value) syncCertificateGeneration();
    if (!value) for (const route of domainRouteConfigs.children) route.syncDomainTls?.();
    if (!value) for (const monitor of monitors.children) monitor.syncMonitor();
    if (!value) for (const profile of cookieProfiles.children) profile.syncCookie();
    if (!value) for (const server of servers.children) { syncPoolChoice(server); syncSourceNat(server); syncPersistence(server); syncTls(server,'vs'); syncHttp(server); }
    if (!value) for (const input of form.querySelectorAll('[data-builtin-readonly=true]')) input.disabled = true;
}
function syncUdp(container) {
    const udp=value(container,'server_type')==='udp';
    for(const name of ['vs_object','server_tls_profile','http_enabled','http_rule_sets','http_cookie_profile']) {
        const input=container.querySelector('[name='+name+']'),section=input.closest('fieldset');
        section.hidden=udp;
        if(udp||['vs_object','server_tls_profile'].includes(name))for(const control of section.querySelectorAll('input,select,button,textarea'))control.disabled=busy||udp||control.dataset.builtinReadonly==='true';
    }
    if(!udp)syncTls(container,'vs');
    const idle=container.querySelector('[name=udp_idle_timeout_secs]');
    idle.closest('label').hidden=!udp;idle.disabled=busy||!udp;
    const cookie=container.querySelector('[name=persistence_mode] option[value=cookie]');cookie.disabled=udp;
    const monitor=container.querySelector('[name=monitor]');
    monitor.closest('label').querySelector('span').textContent=udp?'Health monitor (required: UDP, DNS or ICMP; named pool owns monitor)':'Health monitor name (blank = default TCP; named pool owns monitor)';
    monitor.required=udp&&!value(container,'default_pool');
    if(monitor.options?.length)monitor.options[0].textContent=udp?'Select UDP, DNS or ICMP monitor':'Default TCP monitor';
    container.querySelector('[name=connection_limit]').closest('label').querySelector('span').textContent=udp?'Virtual server flow limit (0 = unlimited)':'Virtual server connection limit (0 = unlimited)';
    container.querySelector('[name=enabled]').closest('label').querySelector('span').textContent=udp?'Accept new flows':'Accept new connections';
    container.querySelector('.protocol-help').textContent=udp
        ? 'UDP keeps a client IP and port on one backend until the flow is idle. New flows are balanced again. Choose a UDP, DNS or ICMP health monitor; TCP TLS and HTTP processing do not apply.'
        : 'TCP balances connections. HTTP balances requests. Automatic preserves legacy settings: HTTP when enabled, otherwise TCP. Choose No persistence to avoid source or cookie affinity.';
}
function syncHttp(container) {
    container.querySelector('[name=http_enabled]').disabled=busy||value(container,'server_type')!=='standard';
    const enabled = value(container,'http_enabled') === 'true';
    const cookie = enabled && value(container,'persistence_mode') === 'cookie';
    for (const name of ['http_transport_profile','http_rule_sets','http_cookie_profile']) {
        const input = container.querySelector('[name=' + name + ']');
        const visible = enabled && (name !== 'http_cookie_profile' || cookie);
        input.closest('label').hidden = !visible; input.disabled = busy || !visible;
    }
    const section = container.querySelector('.source-persistence'); section.hidden = value(container,'persistence_mode') !== 'source';
    for (const input of section.querySelectorAll('input,select')) if (cookie) input.disabled = true;
    container.querySelector('.rule-assignments').hidden = !enabled; renderRuleAssignments(container);
    syncUdp(container);
}
function httpConfig(container) {
    if (value(container,'http_enabled') !== 'true') return {};
    const rule_sets = JSON.parse(container.querySelector('[name=http_rule_sets]').dataset.assignment);
    return {http:{profile:value(container,'http_transport_profile'),rule_sets,
        ...(value(container,'persistence_mode') === 'cookie' && value(container,'http_cookie_profile') ? {cookie_profile:value(container,'http_cookie_profile')} : {})}};
}
function renderRuleAssignments(container) {
    const input = container.querySelector('[name=http_rule_sets]'), target = container.querySelector('.rule-assignments');
    const assigned = JSON.parse(input.dataset.assignment); target.replaceChildren();
    if (!assigned.length) target.append(node('p','No RiverRules assigned.'));
    assigned.forEach((name,index) => {
        const row = node('div'); row.className = 'object-row'; row.append(node('span',(index+1) + '. ' + name));
        for (const [title,offset] of [['Move up',-1],['Move down',1],['Unassign',0]]) {
            const button = node('button',title); button.type = 'button'; button.disabled = busy || value(container,'http_enabled') !== 'true' || (offset !== 0 && (index+offset < 0 || index+offset >= assigned.length));
            button.onclick = () => {if (offset) [assigned[index],assigned[index+offset]] = [assigned[index+offset],assigned[index]]; else assigned.splice(index,1); input.dataset.assignment = JSON.stringify(assigned); renderRuleAssignments(container); mark();}; row.append(button);
        }
        target.append(row);
    });
}
function syncTls(container,prefix) {
    if(prefix==='management'){
        const https=value(container,'management_protocol')==='https',files=value(container,'management_tls_source')==='files';
        for(const [key,visible] of [['management_tls_source',https],['management_object',https&&!files],['management_certificate',https&&files],['management_private_key',https&&files]]){
            const input=container.querySelector('[name='+key+']');input.disabled=busy||!visible;input.closest('label').hidden=!visible;
        }
        return;
    }
    const managed = !!value(container,prefix + '_object');
    for (const suffix of ['_certificate','_private_key']) {
        const input = container.querySelector('[name=' + prefix + suffix + ']'); input.disabled = busy || managed; input.closest('label').hidden = managed;
    }
}
function syncPersistence(container) {
    const named = !!container.querySelector('[name=persistence_profile]')?.value.trim();
    const hash = value(container,'persistence_kind') === 'source_hash';
    const mode = container.querySelector('[name=persistence_mode]');
    const active = !mode || mode.value === 'source';
    const profile = container.querySelector('[name=persistence_profile]');
    if (profile) profile.disabled = busy || !active;
    for (const key of ['persistence_kind','ipv4_prefix','ipv6_prefix','refresh_on_use','persistence_timeout','persistence_capacity']) {
        const input = container.querySelector('[name=' + key + ']');
        const visible = active && !named && !(hash && ['refresh_on_use','persistence_timeout','persistence_capacity'].includes(key));
        input.disabled = busy || !visible; input.closest('label').hidden = !visible;
    }
}
function persistenceFields(grid,p) {
    select(grid,'Persistence method','persistence_kind',p.kind ?? 'source_address',[['source_address','Source address affinity'],['source_hash','Stateless source hash']]);
    const v4 = field(grid,'IPv4 prefix length (32 = individual address)','ipv4_prefix',p.ipv4_prefix ?? 32,'number'); v4.min = 0; v4.max = 32;
    const v6 = field(grid,'IPv6 prefix length (128 = individual address)','ipv6_prefix',p.ipv6_prefix ?? 128,'number'); v6.min = 0; v6.max = 128;
    select(grid,'Expiry policy','refresh_on_use',p.refresh_on_use === false ? 'false':'true',[['true','Sliding: refresh on each connection'],['false','Fixed: expire after creation']]);
}
function persistenceConfig(c) {
    const kind = value(c,'persistence_kind');
    const p = {timeout_secs:kind === 'source_hash' ? 0:Number(value(c,'persistence_timeout')),max_entries:kind === 'source_hash' ? 0:Number(value(c,'persistence_capacity'))};
    if (kind !== 'source_address') p.kind = kind;
    if (Number(value(c,'ipv4_prefix')) !== 32) p.ipv4_prefix = Number(value(c,'ipv4_prefix'));
    if (Number(value(c,'ipv6_prefix')) !== 128) p.ipv6_prefix = Number(value(c,'ipv6_prefix'));
    if (value(c,'refresh_on_use') === 'false') p.refresh_on_use = false;
    return p;
}
function addPersistence(profile = {name:'',settings:{timeout_secs:180,max_entries:10000}},builtin = false) {
    const {container,grid} = card(profiles,profile.name || 'New persistence profile');
    field(grid,'Profile name','profile_name',profile.name);
    persistenceFields(grid,profile.settings);
    const timeout = field(grid,'Timeout (seconds; 0 = affinity off)','persistence_timeout',profile.settings.timeout_secs,'number'); timeout.min = 0; timeout.max = 86400;
    const capacity = field(grid,'Record capacity','persistence_capacity',profile.settings.max_entries || 10000,'number'); capacity.min = 1; capacity.max = 1000000;
    container.querySelector('[name=persistence_kind]').onchange = () => syncPersistence(container); syncPersistence(container);
    groupSettings(grid,[['General properties',['profile_name']],['Persistence',['persistence_kind','ipv4_prefix','ipv6_prefix','refresh_on_use','persistence_timeout','persistence_capacity']]]);
    addClone(container,'persistence',() => ({name:value(container,'profile_name'),settings:persistenceConfig(container)}),addPersistence);
    if (builtin) makeBuiltin(container);
}
function syncSourceNat(container) {
    const mode = value(container, 'source_nat_mode');
    for (const [name, visible] of [['snat_addresses', mode === 'snat'], ['source_self_ip', mode === 'default']]) {
        const input = container.querySelector('[name=' + name + ']');
        input.closest('label').hidden = !visible; input.disabled = busy || !visible;
    }
}
function syncPoolChoice(container) {
    const domainOnly=value(container,'server_type')==='domain_routing';
    const named = value(container, 'default_pool') !== '';
    container.querySelector('.inline-pool-settings').hidden = named || domainOnly;
    container.querySelector('[name=default_pool]').closest('label').hidden=domainOnly;
    container.querySelector('[name=default_pool]').disabled=busy||domainOnly;
    for(const input of container.querySelectorAll('.member-editor input,.member-editor select,.member-editor button')) input.disabled=busy||named||domainOnly;
    container.querySelector('[name=algorithm]').disabled = busy || named;
    container.querySelector('[name=algorithm]').closest('label').hidden = named;
    container.querySelector('[name=draining_members]').disabled = busy || named;
    container.querySelector('[name=draining_members]').closest('label').hidden = named;
    container.querySelector('[name=member_weights]').disabled = busy || named;
    container.querySelector('[name=member_weights]').closest('label').hidden = named;
    for (const name of ['member_priorities','member_connection_limits','priority_group_min_active']) {
        const input = container.querySelector('[name=' + name + ']'); input.disabled = busy || named; input.closest('label').hidden = named;
    }
    const monitor = container.querySelector('[name=monitor]'); monitor.disabled = busy || named; monitor.required=value(container,'server_type')==='udp'&&!named; monitor.closest('label').hidden = named;
    container.querySelector('.pool-help').textContent = named
        ? 'Members and balancing come from this pool. Edit them on Local Traffic → Pools.'
        : 'Inline members belong to this virtual server. Assign a named pool to reuse backends.';
}
function field(parent, title, name, value, type = 'text', required = true) {
    const label = node('label');
    const input = node('input');
    Object.assign(input, { name, type, value, required });
    label.append(node('span', title), input);
    parent.append(label);
    return input;
}
function select(parent, title, name, value, options) {
    const label = node('label'), input = node('select');
    input.name = name;
    for (const [key, text] of options) {
        const option = node('option', text);
        option.value = key;
        input.append(option);
    }
    input.value = value;
    label.append(node('span', title), input);
    parent.append(label);
}
const commonPorts = [['80','HTTP'],['443','HTTPS'],['8080','HTTP alternate'],['8443','HTTPS alternate'],['22','SSH'],['25','SMTP'],['53','DNS'],['110','POP3'],['143','IMAP'],['389','LDAP'],['636','LDAPS'],['3306','MySQL'],['5432','PostgreSQL'],['6379','Redis'],['3389','RDP']];
function splitEndpoint(address='') {
    const match = address.match(/^\[([^\]]+)\]:(\d+)$/) || address.match(/^([^:]+):(\d+)$/);
    return match ? {ip:match[1],port:match[2]} : {ip:'',port:''};
}
function endpoint(ip,port) {
    ip=ip.trim().replace(/^\[|\]$/g,'');
    if (!ip || !/^\d+$/.test(String(port)) || Number(port)<1 || Number(port)>65535) throw Error('Enter an IP address and a service port between 1 and 65535.');
    return (ip.includes(':') ? '['+ip+']' : ip)+':'+Number(port);
}
function portField(parent,title,name,port) {
    const input=field(parent,title,name,port,'number');input.min=1;input.max=65535;
    const label=input.closest('label');
    const presets=node('select');presets.className='port-presets';presets.setAttribute('aria-label','Common '+title.toLowerCase());
    const custom=node('option','Custom port');custom.value='';presets.append(custom);
    for(const [number,service] of commonPorts){const option=node('option',number+' — '+service);option.value=number;presets.append(option);}
    presets.value=commonPorts.some(([number])=>number===String(port)) ? String(port) : '';
    presets.onchange=()=>{if(presets.value){input.value=presets.value;input.dispatchEvent(new Event('input',{bubbles:true}));}else input.focus();};
    input.addEventListener('input',()=>{presets.value=commonPorts.some(([number])=>number===input.value)?input.value:'';});
    label.append(presets);return input;
}
function nodeByName(name) {return [...nodeConfigs.children].find(c=>value(c,'node_name')===name);}
function remapMemberSettings(oldAddress,newAddress,container=form) {
    if(!oldAddress || oldAddress===newAddress)return;
    for(const input of container.querySelectorAll('[name=draining_members],[name=member_weights],[name=member_priorities],[name=member_connection_limits]')){
        input.value=input.value.split(/\r?\n/).map(line=>{
            const trimmed=line.trim(), equals=trimmed.indexOf('='),address=equals<0?trimmed:trimmed.slice(0,equals).trim();
            if(address!==oldAddress)return line;
            return newAddress ? newAddress+(equals<0?'':trimmed.slice(equals)) : '';
        }).filter(Boolean).join('\n');
    }
}
function ensureMemberNode(name,address,linked) {
    const existing=nodeByName(linked||name), duplicate=[...nodeConfigs.children].find(c=>value(c,'node_address')===address);
    if(existing) {
        if(duplicate && duplicate!==existing) throw Error('This endpoint already belongs to node '+value(duplicate,'node_name')+'. Select that existing node.');
        if(name!==value(existing,'node_name') && nodeByName(name)) throw Error('Node names must be unique.');
        // Renaming a node updates every reference, including domain routes.
        const old=value(existing,'node_name');
        if(old!==name){for(const row of form.querySelectorAll('.member-row')) if(row.dataset.nodeName===old){row.dataset.nodeName=name;row.querySelector('[name=member_name]').value=name;}
            for(const route of domainRouteConfigs.children) if(value(route,'domain_node')===old){const choice=route.querySelector('[name=domain_node]');const option=node('option',name);option.value=name;choice.append(option);choice.value=name;}}
        remapMemberSettings(value(existing,'node_address'),address);existing.dataset.nodeAddress=address;
        existing.querySelector('[name=node_name]').value=name;existing.dataset.nodeName=name;existing.querySelector('[name=node_address]').value=address;
        return name;
    }
    if(duplicate){if(name!==value(duplicate,'node_name')) throw Error('This endpoint already belongs to node '+value(duplicate,'node_name')+'. Select that existing node.');return name;}
    addNode({name,address,enabled:true});return name;
}
function memberEditor(parent,addresses=[],names=[]) {
    const box=node('div');box.className='member-editor';const rows=node('div');rows.className='member-rows';box.append(rows);
    for(const name of names){const c=nodeByName(name);addMemberRow(rows,name,c?value(c,'node_address'):'',name);}
    for(const address of addresses){let c=[...nodeConfigs.children].find(c=>value(c,'node_address')===address);
        if(!c){const base='node-'+address.replace(/[^a-zA-Z0-9_-]/g,'-');let name=base,index=2;while(nodeByName(name))name=base+'-'+index++;addNode({name,address,enabled:true});c=nodeByName(name);}
        const name=value(c,'node_name');if(![...rows.children].some(row=>row.dataset.nodeName===name))addMemberRow(rows,name,address,name);
    }
    const add=node('button','Add member');add.type='button';add.className='add-member';add.onclick=()=>{addMemberRow(rows,'','','');mark();};
    const existing=node('select');existing.name='existing_member';existing.setAttribute('aria-label','Add existing node');
    existing.onchange=()=>{if(!existing.value)return;const c=nodeByName(existing.value);if(![...rows.children].some(row=>row.dataset.nodeName===existing.value))addMemberRow(rows,existing.value,value(c,'node_address'),existing.value);existing.value='';mark();};
    const toolbar=node('div');toolbar.className='member-toolbar';
    const existingLabel=node('label');existingLabel.append(node('span','Add an existing node'),existing);
    toolbar.append(add,existingLabel);box.append(toolbar);parent.append(box);
}
function addMemberRow(rows,name,address,linked) {
    const row=node('div');row.className='member-row';row.dataset.nodeName=linked;
    field(row,'Name','member_name',name);const parts=splitEndpoint(address);
    field(row,'IP address','member_ip',parts.ip);portField(row,'Port','member_port',parts.port);
    const remove=node('button','Remove member');remove.type='button';remove.className='danger';remove.onclick=()=>{try{remapMemberSettings(endpoint(value(row,'member_ip'),value(row,'member_port')),'',row.closest('.editor'));}catch{}row.remove();mark();};row.append(remove);rows.append(row);
}
function nodeMemberConfig(c,allowed=true){
    if(!allowed)return {};
    const names=[];
    for(const row of c.querySelectorAll('.member-row')){
        const name=value(row,'member_name');if(!name)throw Error('Every pool member requires a name.');
        const address=endpoint(value(row,'member_ip'),value(row,'member_port'));
        names.push(ensureMemberNode(name,address,row.dataset.nodeName));row.dataset.nodeName=name;
    }
    if(new Set(names).size!==names.length)throw Error('A node can only appear once in a pool.');
    return names.length?{node_members:names}:{};
}
function syncMemberRows() {
    for(const c of nodeConfigs.children){const address=value(c,'node_address');if(splitEndpoint(address).port){remapMemberSettings(c.dataset.nodeAddress,address);c.dataset.nodeAddress=address;}}
    for(const row of form.querySelectorAll('.member-row')){
        const c=nodeByName(row.dataset.nodeName);if(!c)continue;
        const parts=splitEndpoint(value(c,'node_address'));
        row.querySelector('[name=member_name]').value=value(c,'node_name');
        row.querySelector('[name=member_ip]').value=parts.ip;row.querySelector('[name=member_port]').value=parts.port;
    }
}
function addNode(object={name:'',address:'',description:'',enabled:true}) {
    const {container,grid}=card(nodeConfigs,object.name||'New node');
    container.dataset.nodeName=object.name;container.dataset.nodeAddress=object.address;
    const nodeName=field(grid,'Name','node_name',object.name);
    nodeName.oninput=()=>{if([...nodeConfigs.children].some(c=>c!==container&&value(c,'node_name')===nodeName.value)){nodeName.setCustomValidity('Node names must be unique.');return;}nodeName.setCustomValidity('');const old=container.dataset.nodeName;for(const row of form.querySelectorAll('.member-row'))if(row.dataset.nodeName===old)row.dataset.nodeName=nodeName.value;for(const route of domainRouteConfigs.children)if(value(route,'domain_node')===old){const choice=route.querySelector('[name=domain_node]');const option=node('option',nodeName.value);option.value=nodeName.value;choice.append(option);choice.value=nodeName.value;}container.dataset.nodeName=nodeName.value;};field(grid,'Backend IP:service port','node_address',object.address);field(grid,'Description','node_description',object.description??'','text',false);
    field(grid,'Health monitor (blank = inherit pool monitor)','node_monitor',object.monitor??'','text',false);
    select(grid,'Administrative state','node_enabled',String(object.enabled??true),[['true','Enabled'],['false','Disabled (no new connections)']]);
    groupSettings(grid,[['General properties',['node_name','node_description']],['Backend endpoint',['node_address','node_enabled']],['Health monitoring',['node_monitor']]]);
}
function domainRouteObject(container) {
    const mode=value(container,'domain_tls_mode');
    const certificate=mode==='off'?'':value(container,'domain_certificate');
    if(mode!=='off'&&!certificate)throw Error('Select or create a certificate for this route before applying.');
    return {name:value(container,'domain_route_name'),virtual_server:value(container,'domain_virtual_server'),hostname:value(container,'domain_hostname').toLowerCase().replace(/\.$/,''),node:value(container,'domain_node'),enabled:value(container,'domain_enabled')==='true',...(certificate?{certificate,https_port:Number(value(container,'domain_https_port'))}:{})};
}
function addDomainRoute(object={name:'',virtual_server:'',hostname:'',node:'',enabled:true}) {
    const {container,grid}=card(domainRouteConfigs,object.name||'New domain route');
    field(grid,'Name','domain_route_name',object.name);select(grid,'Enabled','domain_enabled',String(object.enabled??true),[['true','Enabled'],['false','Disabled']]);
    const hostname=field(grid,'Full browser hostname (without scheme, path or port)','domain_hostname',object.hostname);
    hostname.placeholder='test.zeon-saf.net';
    grid.append(node('p','Match the full hostname in the browser. “test” only matches http://test/, not test.zeon-saf.net.'));
    select(grid,'HTTP virtual server','domain_virtual_server',object.virtual_server,[[object.virtual_server,object.virtual_server||'Select virtual server']]);
    select(grid,'Destination node','domain_node',object.node,[[object.node,object.node||'Select node']]);
    select(grid,'HTTPS certificate','domain_tls_mode',object.certificate?'existing':'off',[['off','No additional HTTPS listener'],['existing','Use existing certificate'],['self_signed','Generate self-signed certificate'],['lets_encrypt',"Let's Encrypt"]]);
    select(grid,'Managed certificate','domain_certificate',object.certificate??'',[[object.certificate??'',object.certificate??'Select certificate']]);
    portField(grid,'HTTPS port','domain_https_port',object.https_port??443);
    field(grid,'Certificate object name','domain_certificate_name',(object.hostname||'')+'-tls','text',false);
    const days=field(grid,'Self-signed lifetime (days)','domain_certificate_days',365,'number',false);days.min=1;days.max=825;
    field(grid,"Let's Encrypt contact email",'domain_le_email','','email',false);
    select(grid,"Let's Encrypt environment",'domain_le_directory','https://acme-v02.api.letsencrypt.org/directory',[["https://acme-v02.api.letsencrypt.org/directory","Production (trusted certificates)"],["https://acme-staging-v02.api.letsencrypt.org/directory","Staging (test certificates; not trusted)"]]);
    field(grid,"Accept Let's Encrypt subscriber agreement",'domain_le_terms','','checkbox',false);
    const action=node('button','Create certificate');action.type='button';action.className='domain-certificate-action';grid.append(action);
    const check=node('button','Check issuance / use certificate');check.type='button';check.className='domain-certificate-check';grid.append(check);
    const status=node('p');status.className='domain-certificate-status';grid.append(status);
    const help=node('p');help.className='domain-tls-help';grid.append(help);
    const addresses=node('p');addresses.className='domain-route-addresses';grid.append(addresses);
    groupSettings(grid,[['General properties',['domain_route_name','domain_enabled']],['Routing',['domain_virtual_server','domain_hostname','domain_node','domain-route-addresses']],['HTTPS',['domain_tls_mode','domain_certificate','domain_https_port','domain_certificate_name','domain_certificate_days','domain_le_email','domain_le_directory','domain_le_terms','domain-certificate-action','domain-certificate-check','domain-certificate-status','domain-tls-help']]]);
    container.syncDomainTls=()=>{
        const mode=value(container,'domain_tls_mode');
        for(const key of ['domain_certificate','domain_https_port','domain_certificate_name','domain_certificate_days','domain_le_email','domain_le_directory','domain_le_terms']) {
            const input=container.querySelector('[name='+key+']');
            const visible=key==='domain_certificate'||key==='domain_https_port'?mode!=='off':key==='domain_certificate_name'?['self_signed','lets_encrypt'].includes(mode):key==='domain_certificate_days'?mode==='self_signed':mode==='lets_encrypt';
            input.closest('label').hidden=!visible;input.disabled=busy||!visible;
            input.required=key==='domain_certificate'&&mode==='existing';
        }
        action.hidden=!['self_signed','lets_encrypt'].includes(mode);action.disabled=busy;action.textContent=mode==='lets_encrypt'?"Request Let's Encrypt certificate":'Generate self-signed certificate';
        check.hidden=mode!=='lets_encrypt';check.disabled=busy;
        help.textContent=mode==='off'?'This route uses the selected virtual server’s protocol.':mode==='self_signed'?'Creates an HTTPS listener on the same VIP when applied. Clients must trust the self-signed certificate.':mode==='lets_encrypt'?"Let's Encrypt must reach this hostname on public port 80. Its challenges are served before domain rules and redirects. Request issuance, check for the issued certificate, then Save and apply.":'Save and apply creates a matching HTTPS listener on the same VIP and assigns this hostname’s certificate using SNI.';
        const server=[...servers.children].find(c=>value(c,'name')===value(container,'domain_virtual_server'));
        const host=value(container,'domain_hostname');
        addresses.textContent=server&&host?'HTTP: http://'+host+(value(server,'listen_port')==='80'?'':':'+value(server,'listen_port'))+'/ · VIP '+value(server,'listen_ip')+':'+value(server,'listen_port')+(mode!=='off'?' · HTTPS: https://'+host+(value(container,'domain_https_port')==='443'?'':':'+value(container,'domain_https_port'))+'/':''):'';
    };
    for(const key of ['domain_tls_mode','domain_hostname','domain_virtual_server','domain_https_port'])container.querySelector('[name='+key+']').addEventListener('input',container.syncDomainTls);
    const certName=()=>{const host=value(container,'domain_hostname').toLowerCase().replace(/\.$/,'');const name=value(container,'domain_certificate_name');return name&&name!=='-tls'?name:host+'-tls';};
    action.onclick=async()=>{
        if(busy)return;const mode=value(container,'domain_tls_mode'),host=value(container,'domain_hostname').toLowerCase().replace(/\.$/,'');
        if(!host||host.includes('/')||host.includes(':')){say('Enter the full DNS hostname before requesting a certificate.',true);return;}
        if(mode==='lets_encrypt'&&(!value(container,'domain_le_email')||!container.querySelector('[name=domain_le_terms]').checked)){say("Enter the contact email and accept Let's Encrypt’s subscriber agreement.",true);return;}
        const name=certName();lock(true);status.textContent='Creating certificate…';
        try {
            if(mode==='self_signed'){
                await api('/api/v1/certificates/self-signed','POST',{name,hostname:host,days:Number(value(container,'domain_certificate_days'))});
                await refreshCertificates();container.querySelector('[name=domain_certificate]').value=name;status.textContent='Created '+name+'. Save and apply to enable HTTPS. Clients must trust this certificate.';mark();
            }else{
                const server=[...servers.children].find(c=>value(c,'name')===value(container,'domain_virtual_server'));
                if(!server)throw Error('Select the HTTP virtual server first.');
                await api('/api/v1/renewals','POST',{name,domains:[host],directory:value(container,'domain_le_directory'),email:value(container,'domain_le_email'),terms_agreed:true,enabled:true,challenge_listen:endpoint(value(server,'listen_ip'),value(server,'listen_port')),renew_before_days:30});
                container.dataset.pendingCertificate=name;container.querySelector('[name=domain_certificate]').value='';mark();status.textContent='Issuance queued for '+name+'. Check issuance to select it when ready.';
            }
        }catch(error){status.textContent=error.message;say(error.message,true);}finally{lock(false);container.syncDomainTls();}
    };
    check.onclick=async()=>{
        if(busy)return;const name=container.dataset.pendingCertificate||certName();lock(true);
        try {
            await refreshCertificates();
            if([...byId('certificate-names').children].some(c=>c.value===name)) {
                const active=await api('/api/v1/config');
                if(JSON.stringify(active.config)!==baseConfiguration)throw Error('The active configuration changed while issuing. Reload configuration before assigning '+name+'.');
                revision=active.revision;container.querySelector('[name=domain_certificate]').value=name;status.textContent='Certificate '+name+' is available. Save and apply to enable HTTPS.';mark();
            }else{
                const jobs=await api('/api/v1/renewals'),job=jobs.find(j=>j.settings.name===name);
                status.textContent=job?.last_error?'Issuance failed: '+job.last_error:'Certificate is not issued yet. Check public DNS and port 80 reachability, then check again.';
            }
        }catch(error){status.textContent=error.message;say(error.message,true);}finally{lock(false);container.syncDomainTls();}
    };
    container.syncDomainTls();
}
function addSniRow(target,host,certificate) {
    const row=node('div');row.className='sni-row';
    field(row,'DNS hostname','sni_host',host);
    select(row,'Managed certificate','sni_certificate',certificate,[[certificate,certificate || 'Select managed certificate']]);
    const remove=node('button','Remove hostname');remove.type='button';remove.className='danger';remove.onclick=()=>{row.remove();mark();};row.append(remove);target.append(row);
}
function sniConfig(container) {
    const names={};
    for(const row of container.querySelectorAll('.sni-row')) {
        const host=value(row,'sni_host'),certificate=value(row,'sni_certificate');
        if(!host || !certificate || Object.hasOwn(names,host))throw Error('SNI assignments need unique hostnames and a managed certificate.');
        names[host]=certificate;
    }
    return names;
}
function card(target, title) {
    const container = node('div'), grid = node('div');
    container.className = 'editor'; grid.className = 'grid';
    const actions = node('div'); actions.className = 'actions editor-actions';
    container.append(node('h4', title), grid, actions);
    const remove = node('button', 'Remove');
    remove.type = 'button'; remove.className = 'danger';
    const route = Object.keys(objectPages).find(route => objectPages[route].target === target);
    container.dataset.draftRoute = 'new-' + Math.random().toString(36).slice(2);
    remove.onclick = () => {
        if(target===nodeConfigs){const name=value(container,'node_name');if([...form.querySelectorAll('.member-row')].some(row=>row.dataset.nodeName===name)||[...domainRouteConfigs.children].some(c=>value(c,'domain_node')===name)){say('Remove this node from its pool members and domain routes before deleting it.',true);return;}}
        container.remove(); mark(); poolSuggestions(); if (route) navigate(route); };
    if (route) {
        const done = node('button', 'Done'); done.type = 'button';
        done.onclick = () => { navigate(route); if (dirty) say('Changes staged. Save and apply to activate them.'); };
        actions.append(done);
        container.hidden = true;
    }
    actions.append(remove); target.append(container);
    return { container, grid };
}
function groupSettings(grid, groups) {
    grid.className = 'config-sections';
    for (const [title, names, className] of groups) {
        const section = node('fieldset'); section.className = 'config-section' + (className ? ' ' + className : '');
        section.append(node('legend', title));
        for (const name of names) {
            const item = ['pool-help','rule-assignments','sni-assignments','member-editor','domain-route-addresses','domain-certificate-action','domain-certificate-check','domain-certificate-status','domain-tls-help'].includes(name) ? grid.querySelector('.' + name) : grid.querySelector('[name=' + name + ']').closest('label');
            section.append(item);
        }
        grid.append(section);
    }
}
function drainField(grid, object) {
    const label = node('label'), input = node('textarea');
    Object.assign(input, { name: 'draining_members', rows: 2, value: (object.draining_members ?? []).join('\n') });
    label.append(node('span', 'Drain members — one existing IP:port per line; existing sessions finish'), input);
    grid.append(label);
    const weightsLabel = node('label'), weights = node('textarea');
    Object.assign(weights, { name: 'member_weights', rows: 2, value: Object.entries(object.member_weights ?? {}).map(([address, weight]) => address + '=' + weight).join('\n') });
    weightsLabel.append(node('span', 'Member ratios — IP:port=weight per line (1–1000; default 1); used by weighted round robin and weighted least connections'), weights);
    grid.append(weightsLabel);
    for (const [key,title] of [['member_priorities','Member priorities: IP:port=priority per line (0–65535; highest first)'],['member_connection_limits','Member connection limits: IP:port=limit per line (1–1000000; omit for unlimited)']]) {
        const label = node('label'), input = node('textarea');
        Object.assign(input,{name:key,rows:2,value:Object.entries(object[key] ?? {}).map(([address,value]) => address + '=' + value).join('\n')});
        label.append(node('span',title),input); grid.append(label);
    }
    const minimum = field(grid,'Priority group minimum eligible members (0 = all groups)','priority_group_min_active',object.priority_group_min_active ?? 0,'number'); minimum.min = 0; minimum.max = 1000000;
}
function drainConfig(container) {
    const addresses = value(container, 'draining_members').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
    const weights = Object.create(null);
    for (const line of value(container, 'member_weights').split(/\r?\n/).map(x => x.trim()).filter(Boolean)) {
        const parts = line.split('=');
        const address = parts[0].trim(), weight = Number(parts[1]);
        if (parts.length !== 2 || !address || !Number.isInteger(weight) || weight < 1 || weight > 1000 || Object.hasOwn(weights, address)) {
            throw Error('Member ratios require unique IP:port=weight lines, with whole weights 1–1000.');
        }
        weights[address] = weight;
    }
    const settings = { ...(addresses.length ? { draining_members: addresses } : {}), ...(Object.keys(weights).length ? { member_weights: weights } : {}) };
    for (const [key,min,max] of [['member_priorities',0,65535],['member_connection_limits',1,1000000]]) {
        const entries = Object.create(null);
        for (const line of value(container,key).split(/\r?\n/).map(s => s.trim()).filter(Boolean)) {
            const parts = line.split('='), address = parts[0].trim(), number = Number(parts[1]);
            if (parts.length !== 2 || !address || parts[1].trim() === '' || !Number.isInteger(number) || number < min || number > max || Object.hasOwn(entries,address)) throw Error('Enter unique IP:port=value lines for ' + key + ', with values ' + min + '–' + max + '.');
            entries[address] = number;
        }
        if (Object.keys(entries).length) settings[key] = entries;
    }
    const minimum = Number(value(container,'priority_group_min_active')); if (minimum > 0) settings.priority_group_min_active = minimum;
    return settings;
}
function tlsFields(grid, tls, prefix, object) {
    field(grid, 'Managed certificate name (optional)', prefix + '_object', object ?? '', 'text', false).setAttribute('list','certificate-names');
    field(grid, 'TLS certificate PEM path (blank = TCP/plain HTTP)', prefix + '_certificate', tls?.certificate ?? '', 'text', false);
    field(grid, 'TLS private key PEM path', prefix + '_private_key', tls?.private_key ?? '', 'text', false);
}
function tlsConfig(container, prefix) {
    if (value(container,prefix + '_object')) return null;
    const certificate = value(container, prefix + '_certificate'), private_key = value(container, prefix + '_private_key');
    if (!!certificate !== !!private_key) throw Error('TLS requires both a certificate and private key path.');
    return certificate ? { certificate, private_key } : null;
}
function addServer(server = { name: '', server_type:'tcp', listen: '127.0.0.1:8081', algorithm: 'round_robin', members: [] }) {
    const { container, grid } = card(servers, server.name ? 'Edit ' + server.name : 'New virtual server');
    container.dataset.originalName = server.name;
    field(grid, 'Name', 'name', server.name);
    const persistenceMode = server.http?.cookie_profile || server.http?.cookie ? 'cookie' : server.persistence_profile || server.persistence?.timeout_secs > 0 || server.persistence?.kind === 'source_hash' ? 'source' : 'none';
    select(grid,'Persistence','persistence_mode',persistenceMode,[['none','No persistence'],['source','Source persistence (profile or inline)'],['cookie','Cookie persistence (HTTP)']]);
    select(grid,'Virtual server type','server_type',server.server_type??'standard',[['standard','Automatic (legacy TCP / HTTP settings)'],['tcp','TCP proxy (balance each connection)'],['udp','UDP proxy (balance each flow)'],['http','HTTP proxy (balance each request)'],['domain_routing','Domain routing only']]);
    const protocolHelp=node('p');protocolHelp.className='protocol-help';grid.append(protocolHelp);
    const udpIdle=field(grid,'UDP flow idle timeout (seconds)','udp_idle_timeout_secs',server.udp_idle_timeout_secs??30,'number');udpIdle.min=1;udpIdle.max=3600;
    const missLabel=node('label'),missBody=node('textarea');
    Object.assign(missBody,{name:'hostname_miss_body',rows:4,maxLength:65536,value:server.hostname_miss_body??'No domain route for this hostname'});
    missLabel.append(node('span','Hostname miss: 404 response body'),missBody);grid.append(missLabel);
    const listen=splitEndpoint(server.listen);
    field(grid,'Destination IP address','listen_ip',listen.ip);portField(grid,'Service port','listen_port',listen.port);
    field(grid, 'Ingress VLAN (blank = any interface)', 'ingress_vlan', server.ingress_vlan ?? '', 'text', false);
    field(grid, 'Backend VLAN (blank = system routing)', 'backend_vlan', server.backend_vlan ?? '', 'text', false);
    const limit = field(grid,'Virtual server connection limit (0 = unlimited)','connection_limit',server.connection_limit ?? 0,'number'); limit.min = 0; limit.max = 1000000;
    tlsFields(grid, server.tls, 'vs', server.certificate);
    memberEditor(grid,server.members??[],server.node_members??[]);
    const sni = node('div'); sni.className='sni-assignments';
    sni.append(node('p','SNI certificates: assign hostnames below and select a managed default certificate above for unknown/no-SNI clients.'));
    const sniRows=node('div');sniRows.className='sni-rows';sni.append(sniRows);
    const addSni=node('button','Add SNI hostname');addSni.type='button';addSni.onclick=()=>{addSniRow(sniRows,'','');poolSuggestions();mark();};sni.append(addSni);grid.append(sni);
    for(const [host,name] of Object.entries(server.sni_certificates ?? {}))addSniRow(sniRows,host,name);
    field(grid,'Backend server TLS profile (optional)','server_tls_profile',server.server_tls_profile ?? '', 'text',false).setAttribute('list','server-tls-names');
    field(grid, 'Description', 'description', server.description ?? '', 'text', false);
    field(grid, 'App launch URL (optional HTTP/HTTPS URL)', 'app_url', server.app_url ?? '', 'url', false);
    field(grid, 'Health monitor name (blank = default TCP; named pool owns monitor)', 'monitor', server.monitor ?? '', 'text', false);
    const pool = field(grid, 'Default pool (optional)', 'default_pool', server.default_pool ?? '', 'text', false);
    pool.setAttribute('list', 'pool-names');
    const help = node('p'); help.className = 'pool-help'; grid.append(help);
    select(grid, 'Balancing algorithm', 'algorithm', server.algorithm, [
        ['round_robin', 'Round robin'], ['weighted_round_robin', 'Weighted round robin'], ['weighted_least_connections','Weighted least connections'], ['least_connections', 'Least connections'], ['source_hash', 'Source IP hash']
    ]);
    select(grid, 'Accept new connections', 'enabled', server.enabled === false ? 'false' : 'true', [
        ['true', 'Enabled'], ['false', 'Disabled']
    ]);
    select(grid, 'Source address translation', 'source_nat_mode', server.source_nat?.mode ?? 'default', [['default','Default proxy source / legacy self IP'],['automap','Automap (egress self IP)'],['snat','SNAT address pool']]);
    field(grid, 'SNAT translation IPs (comma separated)', 'snat_addresses', (server.source_nat?.addresses ?? []).join(', '), 'text', false);
    field(grid, 'Backend source self IP name (optional)', 'source_self_ip', server.source_self_ip ?? '', 'text', false);
    field(grid, 'Persistence profile name (optional)', 'persistence_profile', server.persistence_profile ?? '', 'text', false).setAttribute('list','persistence-names');
    persistenceFields(grid, server.persistence ?? {}, 'inline');
    const persistenceTimeout = field(grid, 'Source IP persistence idle timeout (seconds; 0 = off)', 'persistence_timeout', server.persistence?.timeout_secs ?? 0, 'number');
    persistenceTimeout.min = 0; persistenceTimeout.max = 86400;
    const persistenceCapacity = field(grid, 'Persistence table capacity', 'persistence_capacity', server.persistence?.max_entries || 10000, 'number');
    persistenceCapacity.min = 1; persistenceCapacity.max = 1000000;
    drainField(grid, server);
    select(grid,'Application protocol','http_enabled',server.http ? 'true':'false',[['false','TCP passthrough'],['true','HTTP/1 proxy (RiverRules and cookie persistence)']]);
    field(grid,'HTTP profile','http_transport_profile',server.http?.profile ?? 'http','text',true);
    field(grid,'Cookie persistence profile','http_cookie_profile',server.http?.cookie_profile ?? '', 'text',false);
    select(grid,'Add RiverRules object (assignments execute in the order below)','http_rule_sets','',[]);
    const assignedRules = container.querySelector('[name=http_rule_sets]');
    assignedRules.dataset.assignment = JSON.stringify(server.http?.rule_sets ?? []);
    const assignmentList = node('div'); assignmentList.className = 'rule-assignments'; grid.append(assignmentList);
    assignedRules.oninput = assignedRules.onchange = () => {const chosen = assignedRules.value; if (!chosen) return; const assigned = JSON.parse(assignedRules.dataset.assignment); if (!assigned.includes(chosen)) assigned.push(chosen); assignedRules.dataset.assignment = JSON.stringify(assigned); assignedRules.value = ''; renderRuleAssignments(container); mark();};
    renderRuleAssignments(container);
    groupSettings(grid, [
        ['General properties', ['name','server_type','udp_idle_timeout_secs','description','app_url','enabled','persistence_mode']],
        ['Domain routing', ['hostname_miss_body']],
        ['Listener and capacity', ['listen_ip','listen_port','ingress_vlan','connection_limit']],
        ['Pool assignment', ['default_pool','pool-help']],
        ['Inline pool settings', ['member-editor','monitor','algorithm','member_weights','member_priorities','priority_group_min_active','member_connection_limits','draining_members'], 'inline-pool-settings'],
        ['Client TLS', ['vs_object','vs_certificate','vs_private_key','sni-assignments']],
        ['Server TLS', ['server_tls_profile']],
        ['Source address translation', ['backend_vlan','source_nat_mode','snat_addresses','source_self_ip']],
        ['HTTP', ['http_enabled','http_transport_profile']],
        ['RiverRules', ['http_rule_sets','rule-assignments']],
        ['Cookie persistence', ['http_cookie_profile']],
        ['Source persistence', ['persistence_profile','persistence_kind','ipv4_prefix','ipv6_prefix','refresh_on_use','persistence_timeout','persistence_capacity'],'source-persistence']
    ]);
    pool.addEventListener('input', () => syncPoolChoice(container));
    const typeInput=container.querySelector('[name=server_type]');
    typeInput.oninput=typeInput.onchange=()=>{
        const kind=typeInput.value;
        if(kind!=='standard')container.querySelector('[name=http_enabled]').value=['tcp','udp'].includes(kind)?'false':'true';
        if(kind==='udp'&&value(container,'persistence_mode')==='cookie')container.querySelector('[name=persistence_mode]').value='none';
        syncPoolChoice(container);syncHttp(container);syncPersistence(container);poolSuggestions();mark();
    };
    container.querySelector('[name=source_nat_mode]').addEventListener('input', () => syncSourceNat(container));
    container.querySelector('[name=source_nat_mode]').addEventListener('change', () => syncSourceNat(container));
    syncPoolChoice(container);
    syncSourceNat(container);
    container.querySelector('[name=persistence_mode]').oninput = () => {
        const mode = value(container,'persistence_mode');
        if (mode !== 'cookie') container.querySelector('[name=http_cookie_profile]').value = '';
        if (mode === 'none') {
            container.querySelector('[name=persistence_profile]').value = '';
            container.querySelector('[name=persistence_kind]').value = 'source_address';
            container.querySelector('[name=persistence_timeout]').value = 0;
        } else if (mode === 'source' && !value(container,'persistence_profile') && !Number(value(container,'persistence_timeout')) && value(container,'persistence_kind') !== 'source_hash') {
            container.querySelector('[name=persistence_timeout]').value = 180;
        }
        syncPersistence(container); syncHttp(container);
    };
    container.querySelector('[name=persistence_profile]').oninput = () => {
        if (value(container,'persistence_profile')) {
            container.querySelector('[name=persistence_mode]').value = 'source';
            container.querySelector('[name=http_cookie_profile]').value = '';
        }
        syncPersistence(container); syncHttp(container);
    };
    container.querySelector('[name=vs_object]').oninput = () => syncTls(container,'vs');
    container.querySelector('[name=persistence_kind]').onchange = () => syncPersistence(container);
    syncPersistence(container); syncTls(container,'vs');
    for (const name of ['http_enabled','http_cookie_profile']) {
        const input = container.querySelector('[name=' + name + ']');
        input.oninput = input.onchange = () => {
            if (name === 'http_cookie_profile') {
                container.querySelector('[name=persistence_mode]').value = input.value ? 'cookie' : 'none';
                if (input.value) container.querySelector('[name=persistence_profile]').value = '';
            }
            syncPersistence(container); syncHttp(container);
        };
    }
    syncHttp(container);
    if(server.domain_tls_parent){container.dataset.generatedDomainTls=server.domain_tls_parent;makeBuiltin(container);container.querySelector('h4').textContent=server.name+' (managed HTTPS listener; edit the domain routes)';}
}
function addPool(pool = { name: '', algorithm: 'round_robin', members: [] }) {
    const { grid } = card(poolConfigs, pool.name || 'New pool');
    field(grid, 'Pool name', 'pool_name', pool.name);
    memberEditor(grid,pool.members??[],pool.node_members??[]);
    field(grid, 'Health monitor name (blank = default TCP)', 'monitor', pool.monitor ?? '', 'text', false);
    select(grid, 'Balancing algorithm', 'algorithm', pool.algorithm, [
        ['round_robin', 'Round robin'], ['weighted_round_robin', 'Weighted round robin'], ['weighted_least_connections','Weighted least connections'], ['least_connections', 'Least connections'], ['source_hash', 'Source IP hash']
    ]);
    drainField(grid, pool);
    groupSettings(grid, [
        ['General properties', ['pool_name']],
        ['Health monitoring', ['monitor']],
        ['Members', ['member-editor','draining_members']],
        ['Load balancing', ['algorithm','member_weights']],
        ['Priority groups', ['member_priorities','priority_group_min_active']],
        ['Connection limits', ['member_connection_limits']]
    ]);
}
function monitorObject(c) {
    const kind = value(c,'kind');
    return {name:value(c,'monitor_name'),kind,...Object.fromEntries(['interval_secs','timeout_ms','rise','fall'].map(k=>[k,Number(value(c,k))])),
        ...(['http','https'].includes(kind)?{path:value(c,'path'),host:value(c,'host'),expected_status:Number(value(c,'expected_status')),body_contains:value(c,'body_contains')}:{}),
        ...(kind==='tls'?{host:value(c,'host')}:{}),
        ...(['https','tls'].includes(kind)?{ca_certificate:value(c,'ca_certificate')}:{}),
        ...(kind==='udp'?{send:value(c,'send'),receive:value(c,'receive')}:{}),
        ...(kind==='dns'?{query:value(c,'query'),record_type:value(c,'record_type')}:{})};
}
function addMonitor(m = { name: '', kind: 'http', interval_secs: 5, timeout_ms: 2000, rise: 2, fall: 2, path: '/health', host: 'localhost', expected_status: 200, body_contains: '', ca_certificate: '' }) {
    const {container, grid} = card(monitors, m.name || 'New monitor');
    field(grid, 'Monitor name', 'monitor_name', m.name);
    select(grid, 'Protocol', 'kind', m.kind, [['tcp','TCP connect'],['http','HTTP readiness'],['https','HTTPS readiness'],['icmp','ICMP echo'],['udp','UDP request / response'],['dns','DNS query'],['tls','TLS handshake']]);
    for (const [key,title,max] of [['interval_secs','Interval (seconds)',3600],['timeout_ms','Complete probe deadline (ms)',60000],['rise','Successful probes to mark up',1000],['fall','Failed probes to mark down',1000]]) {
        const input = field(grid,title,key,m[key],'number'); input.min = 1; input.max = max;
    }
    field(grid,'Request path','path',m.path ?? '/health');
    field(grid,'Host header / HTTPS TLS server name','host',m.host ?? 'localhost');
    const status = field(grid,'Expected HTTP status','expected_status',m.expected_status ?? 200,'number'); status.min = 100; status.max = 599;
    field(grid,'Required response text (optional; first 64 KiB)','body_contains',m.body_contains ?? '', 'text', false);
    field(grid,'Trusted CA certificate PEM path','ca_certificate',m.ca_certificate ?? '');
    field(grid,'UDP request text','send',m.send ?? 'ping');
    field(grid,'Required UDP response text','receive',m.receive ?? 'pong');
    field(grid,'DNS query name','query',m.query ?? 'example.com');
    select(grid,'DNS record type','record_type',m.record_type ?? 'A',['A','AAAA','CNAME','MX','NS','TXT','SOA','SRV'].map(t=>[t,t]));
    groupSettings(grid,[['General properties',['monitor_name','kind']],['Timing and thresholds',['interval_secs','timeout_ms','rise','fall']],['HTTP request and response',['path','expected_status','body_contains']],['Server identity and trust',['host','ca_certificate']],['UDP request and response',['send','receive']],['DNS query',['query','record_type']]]);
    const sync = () => {
        const kind = value(container,'kind');
        for (const key of ['path','host','expected_status','body_contains','ca_certificate','send','receive','query','record_type']) {
            const input = container.querySelector('[name=' + key + ']');
            const visible = key === 'ca_certificate' ? ['https','tls'].includes(kind) : key === 'host' ? ['http','https','tls'].includes(kind) : ['send','receive'].includes(key) ? kind==='udp' : ['query','record_type'].includes(key) ? kind==='dns' : ['http','https'].includes(kind);
            input.disabled = busy || !visible; input.closest('label').hidden = !visible;
        }
        container.querySelector('[name=host]').closest('label').querySelector('span').textContent=kind==='http'?'HTTP Host header':'TLS server name (no port)';
        for(const section of grid.querySelectorAll('.config-section'))section.hidden=[...section.querySelectorAll('label')].every(label=>label.hidden);
    };
    container.syncMonitor = sync; container.querySelector('[name=kind]').onchange = sync; sync();
    addClone(container,'monitors',()=>monitorObject(container),addMonitor);
}
function addServerTls(profile = {name:'',server_name:'',ca_certificate:'system'},builtin = false) {
    const {container,grid} = card(serverTlsProfiles,profile.name || 'New server TLS profile');
    field(grid,'Profile name','server_tls_name',profile.name);
    field(grid,'TLS server name (blank = verify member IP)','server_name',profile.server_name,'text',false);
    field(grid,'Trusted CA PEM path (or system)','ca_certificate',profile.ca_certificate);
    groupSettings(grid,[['General properties',['server_tls_name']],['Verification',['server_name','ca_certificate']]]);
    addClone(container,'server-tls',() => ({name:value(container,'server_tls_name'),server_name:value(container,'server_name'),ca_certificate:value(container,'ca_certificate')}),addServerTls);
    if (builtin) makeBuiltin(container);
}
const httpDefaults = {max_body_bytes:8388608,max_header_bytes:32768,keep_alive:true,streaming:false,websockets:true};
function httpObject(c) {return {name:value(c,'http_profile_name'),description:value(c,'http_description'),settings:{max_body_bytes:Number(value(c,'http_max_body')),max_header_bytes:Number(value(c,'http_max_header')),keep_alive:value(c,'http_keep_alive') === 'true',streaming:value(c,'http_streaming') === 'true',websockets:value(c,'http_websockets') === 'true'}};}
function addHttpProfile(profile = {name:'',description:'',settings:httpDefaults},builtin = false) {
    const {container,grid} = card(httpProfiles,profile.name || 'New HTTP profile');
    field(grid,'Profile name','http_profile_name',profile.name); field(grid,'Description','http_description',profile.description ?? '', 'text',false);
    const settings = {...httpDefaults,...profile.settings};
    const body = field(grid,'Maximum request/response body (bytes)','http_max_body',settings.max_body_bytes,'number'); body.min = 1; body.max = 1099511627776;
    const header = field(grid,'HTTP parser header buffer limit (bytes)','http_max_header',settings.max_header_bytes,'number'); header.min = 8192; header.max = 1048576;
    select(grid,'Client keepalive','http_keep_alive',String(settings.keep_alive),[['true','Enabled'],['false','Disabled']]);
    select(grid,'Body forwarding','http_streaming',String(settings.streaming),[['false','Buffered'],['true','Streaming']]);
    select(grid,'WebSocket upgrades','http_websockets',String(settings.websockets),[['true','Enabled'],['false','Disabled']]);
    groupSettings(grid,[['General properties',['http_profile_name','http_description']],['HTTP behavior',['http_max_body','http_max_header','http_keep_alive','http_streaming','http_websockets']]]);
    addClone(container,'http-profiles',() => httpObject(container),addHttpProfile); if (builtin) makeBuiltin(container);
}
function makeBuiltin(container) {
    container.dataset.builtin = 'true';
    for (const input of container.querySelectorAll('input,textarea,select,.danger')) {input.disabled = true; input.dataset.builtinReadonly = 'true';}
    container.querySelector('h4').textContent += ' (built-in default; clone to customize)';
}
function draftValues(editor) {
    return JSON.stringify([...editor.querySelectorAll('input[name],select[name],textarea[name]')].map(input =>
        [input.name,input.multiple ? [...input.selectedOptions].map(option=>option.value) : input.type==='checkbox' ? input.checked : input.value]));
}
function discardEmptyDrafts() {
    let removed=false;
    for(const {target} of Object.values(objectPages)) {
        for(const editor of [...target.children]) {
            if(editor.dataset.emptyDraft && editor.dataset.emptyDraft===draftValues(editor)){editor.remove();removed=true;}
        }
    }
    if(removed)poolSuggestions();
}
function createObject(route,create,object) {
    if(route==='river-rules')for(const id of ['river-rule-search','river-rule-category','river-rule-source'])byId(id).value='';
    if (object === undefined) {
        const {target,key} = objectPages[route];
        const draft = [...target.children].find(c => !value(c,key));
        if (draft) {openObject(draft,route); return;}
    }
    create(object); poolSuggestions();
    const editor=objectPages[route].target.lastElementChild;
    if(object===undefined)editor.dataset.emptyDraft=draftValues(editor);
    openObject(editor,route); mark();
}
function addClone(container,route,snapshot,create) {
    const clone = node('button','Clone'); clone.type = 'button'; clone.onclick = () => {
        try {const copy = snapshot(); copy.name = cloneName(objectPages[route].target,objectPages[route].key,copy.name || 'profile'); createObject(route,create,copy);} catch(e) {say(e.message,true);}
    }; const actions=container.querySelector('.editor-actions');clone.className='secondary';actions.insertBefore(clone,actions.querySelector('.danger'));
}
const cookieDefaults = {name:'RIVERLB',ttl_secs:3600,max_entries:10000,method:'insert',http_only:true,secure:'auto',same_site:'lax',path:'/',domain:'',session_cookie:false,always_send:true,refresh_on_use:true,hash_offset:0,hash_length:0,override_connection_limit:false};
function cloneName(target,key,name) {
    const used = [...target.children].map(c => value(c,key));
    let candidate = name.slice(0,110) + '-copy', index = 2;
    while (used.includes(candidate)) candidate = name.slice(0,110) + '-copy-' + index++;
    return candidate;
}
let builtinRiverRules = [], builtinRiverRulesRequest = null;
function loadBuiltinRiverRules() {
    if(!builtinRiverRulesRequest)builtinRiverRulesRequest=api('/api/v1/river-rules/builtins').then(data=>{
        if(!Array.isArray(data.rule_sets))throw Error('The server returned an invalid catalog.');
        const names=new Set();
        for(const entry of data.rule_sets){
            if(!entry || !['name','description','category','usage'].every(key=>typeof entry[key]==='string'&&entry[key].trim()) || !Array.isArray(entry.rules) || names.has(entry.name))throw Error('The server returned an invalid rule set.');
            names.add(entry.name);
        }
        builtinRiverRules=data.rule_sets;
        return builtinRiverRules;
    }).catch(error=>{builtinRiverRulesRequest=null;throw Error('Built-in RiverRules catalog could not be loaded: '+error.message);});
    return builtinRiverRulesRequest;
}
function showRiverRulesList() {
    const list=byId('river-rule-list');list.replaceChildren();list.hidden=false;list.classList.add('table-scroll');
    list.tabIndex=0;list.setAttribute('role','region');list.setAttribute('aria-label','RiverRules catalog. Scroll horizontally to view all columns.');
    const category=byId('river-rule-category'),selectedCategory=category.value;
    const categories=[...new Set([...riverRules.children].map(editor=>editor.dataset.ruleCategory??'Custom'))].sort();
    setChoices(category,[['','All categories'],...categories.map(name=>[name,name])]);
    if(categories.includes(selectedCategory))category.value=selectedCategory;
    const query=byId('river-rule-search').value.trim().toLowerCase(),source=byId('river-rule-source').value;
    const editors=[...riverRules.children];
    for(const editor of editors)editor.hidden=true;
    const matches=editors.filter(editor=>{
        const builtin=editor.dataset.builtin==='true',name=value(editor,'rule_name'),description=value(editor,'rule_description'),group=editor.dataset.ruleCategory??'Custom',usage=editor.dataset.ruleUsage??'';
        return (!source||source===(builtin?'builtin':'custom'))&&(!category.value||group===category.value)&&(!query||[name,description,group,usage].some(text=>text.toLowerCase().includes(query)));
    });
    const builtins=editors.filter(editor=>editor.dataset.builtin==='true').length;
    byId('river-rule-count').textContent=matches.length+' of '+editors.length+' rule sets · '+builtins+' built-in · '+(editors.length-builtins)+' custom';
    if(!matches.length){list.append(emptyState(editors.length?'No matching rule sets':'No rule sets available',editors.length?'Clear the search or choose another category or source.':'Create a custom rule set, or reload the configuration to load the built-in catalog.'));return;}
    const table=node('table');table.className='object-table rule-catalog-table';table.dataset.objectKind='river-rules';
    const caption=node('caption','RiverRules catalog');caption.className='visually-hidden';table.append(caption);
    const head=node('thead'),header=node('tr'),body=node('tbody');
    for(const title of ['Rule set','Category','Usage']){const cell=node('th',title);cell.scope='col';header.append(cell);}head.append(header);table.append(head,body);
    for(const editor of matches){
        const row=node('tr');row.className='object-row';row.dataset.ruleName=value(editor,'rule_name');
        const name=node('td'),open=node('button',value(editor,'rule_name')||'(New rule set)');open.type='button';open.onclick=()=>openObject(editor,'river-rules');
        const builtin=editor.dataset.builtin==='true',badge=node('span',builtin?'Built-in':'Custom');badge.className='rule-source-badge';
        name.append(open,badge,node('p',value(editor,'rule_description')||(builtin?'':'No description.')));
        const usage=node('td'),preview=node('p',editor.dataset.ruleUsage??'Custom rules. Review the actions before assigning.');preview.className='rule-usage-preview';usage.append(preview);
        row.append(name,node('td',editor.dataset.ruleCategory??'Custom'),usage);
        body.append(row);
    }
    list.append(table);
}
byId('river-rule-search').oninput=()=>showObjectList('river-rules');
for(const id of ['river-rule-category','river-rule-source'])byId(id).onchange=()=>showObjectList('river-rules');
function ruleObject(c) {
    const rules = JSON.parse(value(c,'rule_json') || '[]'); if (!Array.isArray(rules)) throw Error('RiverRules must be a JSON array.');
    return {name:value(c,'rule_name'),description:value(c,'rule_description'),rules};
}
function addRuleSet(object = {name:'',description:'',rules:[]}, builtin = false) {
    const {container,grid} = card(riverRules,object.name || 'New RiverRules object');
    field(grid,'Object name','rule_name',object.name); field(grid,'Description','rule_description',object.description ?? '', 'text',false);
    const label = node('label'), input = node('textarea'); Object.assign(input,{name:'rule_json',rows:16,value:JSON.stringify(object.rules,null,2)});
    label.append(node('span','Ordered JSON rules — see docs/river-rules.md'),input); grid.append(label);
    groupSettings(grid,[['General properties',['rule_name','rule_description']],['Rules',['rule_json']]]);
    const clone = node('button','Copy'); clone.type = 'button'; clone.onclick = () => {
        try {const copy = ruleObject(container); copy.name = cloneName(riverRules,'rule_name',copy.name || 'rules'); createObject('river-rules',addRuleSet,copy);} catch(e) {say(e.message,true);}
    }; const actions=container.querySelector('.editor-actions');clone.className='secondary';actions.insertBefore(clone,actions.querySelector('.danger'));
    if(builtin) {
        container.dataset.ruleCategory=object.category;container.dataset.ruleUsage=object.usage;
        const guidance=node('div');guidance.className='rule-usage';guidance.append(node('span',object.category),node('h3','Using this built-in rule set'),node('p',object.usage),node('p','Assign this rule set in an HTTP virtual server’s RiverRules section, then Save and apply. Copy creates an editable local rule set; viewing this page does not change your configuration.'));
        grid.before(guidance);
        makeBuiltin(container);container.querySelector('h4').textContent=object.name+' (built-in; copy to customize)';
    }
}
function cookieObject(c) {
    const settings = {};
    for (const key of Object.keys(cookieDefaults)) {
        const raw = value(c,'cookie_' + key);
        settings[key] = typeof cookieDefaults[key] === 'number' ? Number(raw) : typeof cookieDefaults[key] === 'boolean' ? raw === 'true' : raw;
    }
    if (value(c,'cookie_expiration_secs') !== '') settings.expiration_secs = Number(value(c,'cookie_expiration_secs'));
    return {name:value(c,'cookie_profile_name'),description:value(c,'cookie_description'),settings};
}
function addCookieProfile(profile = {name:'',description:'',settings:cookieDefaults},builtin = false) {
    const {container,grid} = card(cookieProfiles,profile.name || 'New cookie profile'); container.dataset.builtin = String(builtin);
    const settings = {...cookieDefaults,...profile.settings};
    field(grid,'Profile name','cookie_profile_name',profile.name);
    field(grid,'Description','cookie_description',profile.description ?? '', 'text',false);
    select(grid,'Cookie method','cookie_method',settings.method,[['insert','Insert opaque cookie'],['rewrite','Rewrite application cookie'],['passive','Learn application cookie'],['hash','Hash application cookie']]);
    for (const [key,title] of [['name','Cookie name'],['path','Cookie Path'],['domain','Cookie Domain (blank = host only)']]) field(grid,title,'cookie_' + key,settings[key],'text',key !== 'domain');
    for (const [key,title,max,min] of [['ttl_secs','Record timeout (seconds)',86400,1],['max_entries','Maximum records',1000000,1],['hash_offset','Hash offset (bytes)',4096,0],['hash_length','Hash length (0 = remainder)',4096,0]]) {
        const input = field(grid,title,'cookie_' + key,settings[key],'number'); input.min = min; input.max = max;
    }
    const expiry = field(grid,'Browser expiry (seconds; blank = record timeout, 0 = session)','cookie_expiration_secs',settings.expiration_secs ?? '', 'number',false); expiry.min = 0; expiry.max = 315360000;
    select(grid,'Secure attribute','cookie_secure',settings.secure,[['auto','Automatic with client TLS'],['always','Always'],['never','Never']]);
    select(grid,'SameSite','cookie_same_site',settings.same_site,[['lax','Lax'],['strict','Strict'],['none','None (requires Secure)']]);
    for (const [key,title] of [['http_only','HttpOnly'],['session_cookie','Browser session cookie'],['always_send','Always send cookie'],['refresh_on_use','Sliding record timeout'],['override_connection_limit','Persisted clients may exceed member limits']]) select(grid,title,'cookie_' + key,String(settings[key]),[['true','Enabled'],['false','Disabled']]);
    groupSettings(grid,[['General properties',['cookie_profile_name','cookie_description','cookie_method','cookie_name']],['Lifetime and capacity',['cookie_ttl_secs','cookie_max_entries','cookie_refresh_on_use','cookie_override_connection_limit']],['Cookie attributes',['cookie_path','cookie_domain','cookie_expiration_secs','cookie_session_cookie','cookie_http_only','cookie_secure','cookie_same_site','cookie_always_send']],['Hash settings',['cookie_hash_offset','cookie_hash_length']]]);
    container.syncCookie = () => {
        const method = value(container,'cookie_method'), managed = ['insert','rewrite'].includes(method);
        for (const key of ['path','domain','expiration_secs','session_cookie','http_only','secure','same_site','always_send','hash_offset','hash_length','ttl_secs','max_entries','refresh_on_use']) {
            const visible = key.startsWith('hash_') ? method === 'hash' : ['ttl_secs','max_entries','refresh_on_use'].includes(key) ? method !== 'hash' : managed;
            const input = container.querySelector('[name=cookie_' + key + ']'); input.closest('label').hidden = !visible; input.disabled = busy || builtin || !visible;
        }
    };
    container.querySelector('[name=cookie_method]').oninput = container.querySelector('[name=cookie_method]').onchange = container.syncCookie;
    const clone = node('button','Clone'); clone.type = 'button'; clone.onclick = () => {const copy = cookieObject(container); copy.name = cloneName(cookieProfiles,'cookie_profile_name',copy.name || 'cookie'); createObject('cookie-profiles',addCookieProfile,copy);}; const actions=container.querySelector('.editor-actions');clone.className='secondary';actions.insertBefore(clone,actions.querySelector('.danger'));
    if (builtin) {
        for (const input of container.querySelectorAll('input,textarea,select,.danger')) {input.disabled = true; input.dataset.builtinReadonly = 'true';}
        container.querySelector('h4').textContent += ' (built-in; clone to customize)';
    }
    container.syncCookie();
}
const defaultPersistenceProfiles = [
    {name:'source_addr',settings:{kind:'source_address',ipv4_prefix:32,ipv6_prefix:128,refresh_on_use:true,timeout_secs:180,max_entries:10000}},
    {name:'source_hash',settings:{kind:'source_hash',ipv4_prefix:32,ipv6_prefix:128,refresh_on_use:true,timeout_secs:0,max_entries:0}}
];
let availableInterfaces = [];
const defaultMonitors = [
    {name:'tcp',kind:'tcp',interval_secs:5,timeout_ms:2000,rise:1,fall:3},
    {name:'http',kind:'http',interval_secs:5,timeout_ms:2000,rise:1,fall:3,path:'/',host:'localhost',expected_status:200,body_contains:''}
];
function setChoices(input, choices) {
    if(input.options.length===choices.length && choices.every(([key,title],i)=>
        input.options[i].value===key && input.options[i].textContent===title))return;
    const fragment=document.createDocumentFragment();
    for(const [key,title] of choices){const option=node('option',title);option.value=key;fragment.append(option);}
    input.replaceChildren(fragment);
}
function referenceChoices(name, names, empty, required = false) {
    for (const original of form.querySelectorAll('[name=' + name + ']')) {
        let input = original;
        const selected = original.value;
        if (original.tagName !== 'SELECT') {
            input = node('select'); input.name = name; input.disabled = original.disabled; input.required = required;
            input.addEventListener('input', () => { original.value = input.value; original.dispatchEvent(new Event('input')); });
            input.addEventListener('change', () => {input.dispatchEvent(new Event('input', {bubbles:true}));});
            original.replaceWith(input);
        }
        const choices=[['',empty], ...[...new Set(names.filter(Boolean))].map(n => [n,n])];
        if(selected && !names.includes(selected))choices.push([selected,selected+' (unavailable)']);
        setChoices(input,choices);
        input.value = selected;
    }
}
function poolSuggestions() {
    const nodes=[...nodeConfigs.children].map(c=>value(c,'node_name')).filter(Boolean);
    referenceChoices('domain_node',nodes,'Select node',true);
    referenceChoices('domain_virtual_server',[...servers.children].filter(c=>!c.dataset.generatedDomainTls&&value(c,'http_enabled')==='true').map(c=>value(c,'name')),'Select HTTP virtual server',true);
    for(const input of document.querySelectorAll('[name=existing_member]')) {
        setChoices(input,[['','Add existing node…'],...nodes.map(name=>[name,name])]);
    }
    for(const c of servers.children)syncPoolChoice(c);
    byId('server-tls-names').replaceChildren();
    for (const profile of serverTlsProfiles.children) {const option = node('option'); option.value = value(profile,'server_tls_name'); byId('server-tls-names').append(option);}
    byId('persistence-names').replaceChildren();
    for (const profile of profiles.children) {const option = node('option'); option.value = value(profile,'profile_name'); byId('persistence-names').append(option);}
    byId('pool-names').replaceChildren();
    for (const pool of poolConfigs.children) {
        const option = node('option'); option.value = value(pool, 'pool_name'); byId('pool-names').append(option);
    }
    referenceChoices('default_pool',[...poolConfigs.children].map(c => value(c,'pool_name')),'Inline pool');
    referenceChoices('node_monitor',[...monitors.children].map(c => value(c,'monitor_name')).concat(defaultMonitors.map(p => p.name)),'Inherit pool monitor');
    referenceChoices('monitor',[...monitors.children].map(c => value(c,'monitor_name')).concat(defaultMonitors.map(p => p.name)),'Default TCP monitor');
    referenceChoices('persistence_profile',[...profiles.children].map(c => value(c,'profile_name')).concat(defaultPersistenceProfiles.map(p => p.name)),'Inline persistence settings');
    referenceChoices('server_tls_profile',[...serverTlsProfiles.children].map(c => value(c,'server_tls_name')),'Plain TCP to backend');
    const certificates = [...byId('certificate-names').children].map(c => c.value);
    referenceChoices('vs_object',certificates,'PEM files / no client TLS');
    referenceChoices('domain_certificate',certificates,'Select managed certificate');
    for(const route of domainRouteConfigs.children)route.syncDomainTls?.();
    referenceChoices('sni_certificate',certificates,'Select managed certificate',true);
    referenceChoices('management_object',[...byId('device-certificate-names').children].map(c=>c.value),'Select a device certificate');
    referenceChoices('source_self_ip',[...selfIps.children].map(c => value(c,'self_name')),'Default proxy source');
    referenceChoices('vlan',[...vlans.children].map(c => value(c,'vlan_name')),'Select VLAN',true);
    referenceChoices('ingress_vlan',[...vlans.children].map(c => value(c,'vlan_name')),'Any interface');
    referenceChoices('backend_vlan',[...vlans.children].map(c => value(c,'vlan_name')),'System routing');
    referenceChoices('interface',availableInterfaces,'Select interface',true);
    referenceChoices('http_cookie_profile',[...cookieProfiles.children].map(c => value(c,'cookie_profile_name')),'No cookie persistence');
    referenceChoices('http_transport_profile',[...httpProfiles.children].map(c => value(c,'http_profile_name')),'Select HTTP profile',true);
    const availableRules = [...riverRules.children].map(c => value(c,'rule_name')).filter(Boolean);
    for (const input of servers.querySelectorAll('[name=http_rule_sets]')) {
        const chosen = JSON.parse(input.dataset.assignment);
        input.replaceChildren(); const empty = node('option','Select a RiverRules object'); empty.value = ''; input.append(empty);
        for (const name of [...new Set([...availableRules,...chosen])]) {
            const option = node('option',name + (availableRules.includes(name) ? '' : ' (unavailable)')); option.value = name; option.selected = chosen.includes(name); input.append(option);
        }
        input.value = ''; renderRuleAssignments(input.closest('.editor'));
    }
    for(const server of servers.children)syncUdp(server);
}
function addVlan(vlan = { name: '', interface: '', tag: null }) {
    const { grid } = card(vlans, vlan.name || 'New VLAN');
    field(grid, 'VLAN name / tagged device name', 'vlan_name', vlan.name);
    field(grid, 'Parent / existing interface', 'interface', vlan.interface);
    select(grid, 'Network role', 'vlan_role', vlan.role ?? 'unspecified', [['unspecified','Unspecified'],['external','External (client network)'],['internal','Internal (backend network)']]);
    const tag = field(grid, '802.1Q tag (blank = untagged)', 'tag', vlan.tag ?? '', 'number', false);
    tag.min = 1; tag.max = 4094;
    field(grid,'IPv4 return gateway (for routed clients)','ipv4_gateway',vlan.ipv4_gateway??'','text',false);
    field(grid,'IPv6 return gateway (for routed clients)','ipv6_gateway',vlan.ipv6_gateway??'','text',false);
    groupSettings(grid,[['General properties',['vlan_name','vlan_role']],['Interface and tagging',['interface','tag']],['Return routing',['ipv4_gateway','ipv6_gateway']]]);
}
function addSelfIp(ip = { name: '', address: '', vlan: '' }) {
    const { grid } = card(selfIps, ip.name || 'New self IP');
    field(grid, 'Self IP name', 'self_name', ip.name);
    field(grid, 'Address/prefix', 'address', ip.address);
    field(grid, 'VLAN name', 'vlan', ip.vlan);
    groupSettings(grid,[['General properties',['self_name']],['Address and network',['address','vlan']]]);
}
function addRoute(route = { name: '', destination: '0.0.0.0/0', gateway: '', vlan: '', metric: 100 }) {
    const { grid } = card(routes, route.name || 'New route');
    field(grid, 'Route name', 'route_name', route.name);
    field(grid, 'Destination CIDR', 'destination', route.destination);
    field(grid, 'Gateway', 'gateway', route.gateway);
    field(grid, 'VLAN name', 'vlan', route.vlan);
    const metric = field(grid, 'Metric', 'metric', route.metric, 'number');
    metric.min = 0; metric.max = 4294967295;
    groupSettings(grid,[['General properties',['route_name']],['Route destination',['destination','gateway','vlan','metric']]]);
}
function value(container, name) { return container.querySelector('[name=' + name + ']').value.trim(); }
function fill(config) {
    baseConfiguration=JSON.stringify(config);
    config = JSON.parse(JSON.stringify(config));
    config.river_rules ??= []; config.cookie_profiles ??= []; config.http_profiles ??= [];
    let migrated = config.virtual_servers.some(v=>v.members?.length)||(config.pools??[]).some(p=>p.members?.length);
    function migratedName(objects,base) {let name = base.slice(0,110), index = 2; while (objects.some(o => o.name === name)) name = base.slice(0,110) + '-' + index++; return name;}
    for (const server of config.virtual_servers) {
        if (server.http && !server.http.profile) {
            const settings = {max_body_bytes:server.http.max_body_bytes ?? httpDefaults.max_body_bytes,max_header_bytes:server.http.max_header_bytes ?? httpDefaults.max_header_bytes,keep_alive:server.http.keep_alive ?? true,streaming:server.http.streaming ?? false,websockets:server.http.websockets ?? true};
            const custom = Object.keys(httpDefaults).some(k => settings[k] !== httpDefaults[k]);
            const name = custom ? migratedName(config.http_profiles,server.name + '-http') : 'http';
            if (custom) config.http_profiles.push({name,description:'Migrated inline HTTP settings',settings});
            server.http.profile = name; delete server.http.max_body_bytes; delete server.http.max_header_bytes; delete server.http.keep_alive; delete server.http.streaming; delete server.http.websockets; migrated = true;
        }
        if (server.http?.cookie) {
            migrated = true;
            const name = migratedName(config.cookie_profiles,server.name + '-cookie');
            config.cookie_profiles.push({name,description:'Migrated inline cookie settings',settings:server.http.cookie});
            server.http.cookie_profile = name; delete server.http.cookie;
        }
        if (server.http?.rules?.length) {
            migrated = true;
            const name = migratedName(config.river_rules,server.name + '-rules');
            config.river_rules.push({name,description:'Migrated inline rules',rules:server.http.rules});
            server.http.rule_sets = [name]; delete server.http.rules;
        }
    }
    for (const key of ['management', 'connect_timeout_ms', 'session_timeout_secs', 'health_interval_secs', 'max_connections']) {
        form.elements.namedItem(key).value = config[key];
    }
    form.elements.management_protocol.value=config.management_protocol??(config.management_certificate||config.management_tls?'https':'http');
    form.elements.management_tls_source.value=config.management_tls?'files':'managed';
    // Preserve a selected name until its device inventory is loaded.
    const managementChoice=form.elements.management_object;managementChoice.replaceChildren();const managementOption=node('option',config.management_certificate??'Select a device certificate');managementOption.value=config.management_certificate??'';managementChoice.append(managementOption);managementChoice.value=config.management_certificate??'';
    form.elements.management_certificate.value = config.management_tls?.certificate ?? '';
    form.elements.management_private_key.value = config.management_tls?.private_key ?? '';
    form.elements.health_rise.value = config.health_rise ?? 1;
    form.elements.health_fall.value = config.health_fall ?? 1;
    const mounts=[];
    for(const target of [servers,vlans,selfIps,routes,poolConfigs,monitors,profiles,serverTlsProfiles,cookieProfiles,riverRules,httpProfiles,nodeConfigs,domainRouteConfigs]){
        target.replaceChildren();
        const marker=document.createComment('configuration mount');target.replaceWith(marker);
        mounts.push([marker,target]);
    }
    // Construct editors off the live form and attach each section as one DOM update.
    try {
        for(const object of config.nodes??[])addNode(object);
        for(const object of config.domain_routes??[])addDomainRoute(object);
        addHttpProfile({name:'http',description:'Default bounded HTTP/1 proxy',settings:httpDefaults},true);
        for (const profile of config.http_profiles) addHttpProfile(profile);
        addCookieProfile({name:'cookie',description:'RiverLB built-in opaque insert persistence',settings:cookieDefaults},true);
        for (const profile of config.cookie_profiles) addCookieProfile(profile);
        for (const object of config.river_rules) addRuleSet(object);
        for (const object of builtinRiverRules) addRuleSet(object,true);
        addServerTls({name:'server_tls',server_name:'',ca_certificate:'system'},true);
        for (const profile of config.server_tls_profiles ?? []) addServerTls(profile);
        for (const profile of defaultPersistenceProfiles) if (!(config.persistence_profiles ?? []).some(p => p.name === profile.name)) addPersistence(profile,true);
        for (const profile of config.persistence_profiles ?? []) addPersistence(profile);
        for (const monitor of config.health_monitors ?? []) addMonitor(monitor);
        for (const pool of config.pools ?? []) addPool(pool);
        for (const server of config.virtual_servers) addServer(server);
        for (const vlan of config.network?.vlans ?? []) addVlan(vlan);
        for (const ip of config.network?.self_ips ?? []) addSelfIp(ip);
        for (const route of config.network?.routes ?? []) addRoute(route);
    } finally {for(const [marker,target] of mounts)marker.replaceWith(target);}
    poolSuggestions();
    syncTls(form,'management');
    for (const route of Object.keys(objectPages)) showObjectList(route);
    navigate(window.location.hash.slice(1), false);
    return migrated;
}
function collect() {
    discardEmptyDrafts();
    for (const profile of defaultPersistenceProfiles) {
        if ([...servers.children].some(c => value(c,'persistence_profile') === profile.name) && ![...profiles.children].some(c => value(c,'profile_name') === profile.name)) addPersistence(profile);
    }
    for (const monitor of defaultMonitors) {
        if ([...servers.children,...poolConfigs.children,...nodeConfigs.children].some(c => value(c,c.parentElement===nodeConfigs?'node_monitor':'monitor') === monitor.name) && ![...monitors.children].some(c => value(c,'monitor_name') === monitor.name)) addMonitor(monitor);
    }
    if (!form.checkValidity()) {
        const invalid = form.querySelector(':invalid');
        const page = invalid?.closest('[data-page]');
        if (page) {
            navigate(page.dataset.page);
            const editor = invalid.closest('.editor');
            if (editor && objectPages[page.dataset.page]) openObject(editor, page.dataset.page);
        }
        form.reportValidity(); throw Error('Complete the highlighted required fields.');
    }
    const config = { management: form.elements.management.value.trim() };
    for (const server of servers.children) {
        if (value(server,'persistence_mode') === 'cookie' && value(server,'http_enabled') !== 'true') {
            throw Error('Cookie persistence requires HTTP processing on ' + (value(server,'name') || 'the new virtual server') + '.');
        }
        if (value(server,'persistence_mode') === 'cookie' && !value(server,'http_cookie_profile')) {
            throw Error('Select a cookie persistence profile, or choose No persistence.');
        }
    }
    for (const key of ['connect_timeout_ms', 'session_timeout_secs', 'health_interval_secs', 'max_connections', 'health_rise', 'health_fall']) {
        const number = Number(form.elements.namedItem(key).value);
        if (!Number.isSafeInteger(number) || number < 1) throw Error('Timeouts and limits must be positive whole numbers.');
        config[key] = number;
    }
    config.management_protocol=value(form,'management_protocol');
    if(config.management_protocol==='https'){
        if(value(form,'management_tls_source')==='files'){
            const certificate=value(form,'management_certificate'),private_key=value(form,'management_private_key');
            if(!certificate||!private_key)throw Error('HTTPS management requires both certificate and private key PEM paths.');
            config.management_tls={certificate,private_key};
        }else{
            if(!value(form,'management_object'))throw Error('Select a device certificate for HTTPS management.');
            config.management_certificate=value(form,'management_object');
        }
    }
    config.virtual_servers = [...servers.children].filter(c=>!c.dataset.generatedDomainTls).map(c => ({
        ...nodeMemberConfig(c,!value(c,'default_pool') && value(c,'server_type')!=='domain_routing'),
        ...(value(c,'server_type')==='udp'?{udp_idle_timeout_secs:Number(value(c,'udp_idle_timeout_secs'))}:{}),
        server_type:value(c,'server_type'),hostname_miss_body:value(c,'hostname_miss_body'),
        name: value(c, 'name'), listen: endpoint(value(c,'listen_ip'),value(c,'listen_port')), algorithm: value(c, 'algorithm'),
        ...(value(c,'ingress_vlan') ? {ingress_vlan:value(c,'ingress_vlan')} : {}),
        ...(value(c,'backend_vlan') ? {backend_vlan:value(c,'backend_vlan')} : {}),
        ...httpConfig(c),
        ...(Number(value(c,'connection_limit')) > 0 ? {connection_limit:Number(value(c,'connection_limit'))} : {}),
        ...(value(c,'server_type')!=='udp' && tlsConfig(c, 'vs') ? { tls: tlsConfig(c, 'vs') } : {}),
        ...(value(c,'server_type')!=='udp' && value(c,'vs_object') ? {certificate:value(c,'vs_object')} : {}),
        sni_certificates: value(c,'server_type')==='udp'?{}:sniConfig(c),
        ...(value(c,'server_type')!=='udp' && value(c,'server_tls_profile') ? {server_tls_profile:value(c,'server_tls_profile')} : {}),
        enabled: value(c, 'enabled') === 'true', description: value(c, 'description'),
        ...(value(c, 'app_url') ? { app_url: value(c, 'app_url') } : {}),
        ...(!value(c, 'default_pool') && value(c, 'monitor') ? { monitor: value(c, 'monitor') } : {}),
        source_self_ip: value(c, 'source_nat_mode') === 'default' ? value(c, 'source_self_ip') || null : null,
        ...(value(c, 'source_nat_mode') === 'default' ? {} : { source_nat: value(c, 'source_nat_mode') === 'automap' ? { mode: 'automap' } : { mode: 'snat', addresses: value(c, 'snat_addresses').split(',').map(x => x.trim()).filter(Boolean) } }),
        default_pool: value(c,'server_type')==='domain_routing' ? null : value(c, 'default_pool') || null,
        ...(value(c, 'default_pool') || value(c,'server_type')==='domain_routing' ? {} : drainConfig(c)),
        ...(value(c,'persistence_mode') !== 'source' ? {persistence:{timeout_secs:0,max_entries:0}} : value(c,'persistence_profile') ? {persistence_profile:value(c,'persistence_profile')} : {persistence:persistenceConfig(c)}),
        members: []
    }));
    config.pools = [...poolConfigs.children].map(c => ({
        ...nodeMemberConfig(c),
        name: value(c, 'pool_name'), algorithm: value(c, 'algorithm'), ...drainConfig(c),
        ...(value(c, 'monitor') ? { monitor: value(c, 'monitor') } : {}),
        members: []
    }));
    if (monitors.children.length) config.health_monitors = [...monitors.children].map(monitorObject);
    config.persistence_profiles = [...profiles.children].filter(c => c.dataset.builtin !== 'true').map(c => ({name:value(c,'profile_name'),settings:persistenceConfig(c)}));
    config.server_tls_profiles = [...serverTlsProfiles.children].filter(c => c.dataset.builtin !== 'true').map(c => ({name:value(c,'server_tls_name'),server_name:value(c,'server_name'),ca_certificate:value(c,'ca_certificate')}));
    config.http_profiles = [...httpProfiles.children].filter(c => c.dataset.builtin !== 'true').map(httpObject);
    config.cookie_profiles = [...cookieProfiles.children].filter(c => c.dataset.builtin !== 'true').map(cookieObject);
    config.river_rules = [...riverRules.children].filter(c=>c.dataset.builtin!=='true').map(ruleObject);
    config.nodes=[...nodeConfigs.children].map(c=>({name:value(c,'node_name'),address:value(c,'node_address'),description:value(c,'node_description'),enabled:value(c,'node_enabled')==='true',...(value(c,'node_monitor')?{monitor:value(c,'node_monitor')}:{})}));
    config.domain_routes=[...domainRouteConfigs.children].map(domainRouteObject);
    config.network = {
        vlans: [...vlans.children].map(c => ({ name: value(c, 'vlan_name'), interface: value(c, 'interface'), tag: value(c, 'tag') === '' ? null : Number(value(c, 'tag')), ...(value(c,'ipv4_gateway') ? {ipv4_gateway:value(c,'ipv4_gateway')} : {}), ...(value(c,'ipv6_gateway') ? {ipv6_gateway:value(c,'ipv6_gateway')} : {}), ...(value(c,'vlan_role') === 'unspecified' ? {} : {role:value(c,'vlan_role')}) })),
        self_ips: [...selfIps.children].map(c => ({ name: value(c, 'self_name'), address: value(c, 'address'), vlan: value(c, 'vlan') })),
        routes: [...routes.children].map(c => ({ name: value(c, 'route_name'), destination: value(c, 'destination'), gateway: value(c, 'gateway'), vlan: value(c, 'vlan'), metric: Number(value(c, 'metric')) }))
    };
    return config;
}
async function api(path, method = 'GET', body) {
    const response = await fetch(path, {
        method, headers: body ? { 'Content-Type': 'application/json', 'X-RiverLB-Request': 'configure' } : {},
        body: body ? JSON.stringify(body) : undefined
    });
    if (response.status === 401) { window.location.assign('/login'); throw Error('Sign in required'); }
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { throw Error(text || 'Invalid server response'); }
    if (!response.ok) throw Error(data.error || text);
    return data;
}
let statusRefreshInFlight=null;
function refresh(background=false) {
    if(statusRefreshInFlight)return statusRefreshInFlight;
    statusRefreshInFlight=refreshStatus(background===true).finally(()=>{statusRefreshInFlight=null;});
    return statusRefreshInFlight;
}
async function refreshStatus(background) {
    try {
        const page=document.querySelector('[data-page]:not([hidden])')?.dataset.page;
        if(background && !['overview','virtual-servers','pools','nodes','monitors'].includes(page)){
            const status=await api('/api/v1/appliance');haRole=status.role??'standalone';renderApplianceHeader(status);
            if(!busy)byId('apply').disabled=haRole==='standby';return;
        }
        const [data,nodes] = await Promise.all([api('/api/v1/status'),api('/api/v1/nodes')]);
        haRole=data.ha?.role??'standalone';
        renderApplianceHeader({...data.ha,version:data.version,release_stage:data.release_stage});
        if(!busy)byId('apply').disabled=haRole==='standby';
        objectLatency['virtual-servers']=new Map(data.virtual_servers.map(v=>[v.name,v.traffic]));
        objectLatency.pools=new Map((data.pools??[]).map(p=>[p.name,p.traffic]));
        objectLatency.nodes=new Map(nodes.map(n=>[n.name,n]));
        objectLatency.monitors=new Map();
        for(const v of data.virtual_servers){if(!v.monitor||!v.traffic?.probe_latency?.samples)continue;const sample=v.traffic.probe_latency,prior=objectLatency.monitors.get(v.monitor)?.probe_latency??{samples:0,total_us:0,maximum_ms:0};const merged={samples:prior.samples+sample.samples,total_us:prior.total_us+sample.total_us,maximum_ms:Math.max(prior.maximum_ms,sample.maximum_ms)};merged.average_ms=merged.total_us/merged.samples/1000;objectLatency.monitors.set(v.monitor,{probe_latency:merged});}
        health['virtual-servers'] = new Map(data.virtual_servers.map(v => [v.name,v.state ?? (v.enabled === false ? 'disabled' : 'unknown')]));
        health.pools = new Map((data.pools ?? []).map(p => [p.name,p.state]));
        health.nodes = new Map(nodes.map(n => [n.name,({Up:'up',Down:'down',Disabled:'disabled',Unavailable:'unavailable'})[n.state] ?? 'unknown']));
        for(const c of nodeConfigs.children){
            const name=value(c,'node_name');if(health.nodes.has(name))continue;
            const members=data.virtual_servers.filter(v=>v.enabled!==false).flatMap(v=>v.members).filter(m=>m.address===value(c,'node_address'));
            const state=members.some(m=>m.healthy&&!m.draining)?'up':members.some(m=>m.healthy)?'unavailable':!members.length||members.some(m=>m.last_probe==null)?'unknown':'down';
            health.nodes.set(name,state);
        }
        updateHealthBadges();
        if(!document.querySelector('[data-page=overview]').hidden){
        const focusedOverview=document.activeElement;
        const focusedMember=focusedOverview?.tagName==='SUMMARY'?focusedOverview.closest('[data-member-key]')?.dataset.memberKey:null;
        const focusedEdit=focusedOverview?.dataset.overviewEdit,focusedLink=focusedOverview?.dataset.overviewLink;
        const memberDetailsOpen=new Set([...byId('pools').querySelectorAll('details[open][data-member-key]')].map(d=>d.dataset.memberKey));
        byId('pools').replaceChildren();
        if(!data.virtual_servers.length){const empty=emptyState('No virtual servers yet','Create a virtual server to start routing traffic and see live backend health.');const create=node('button','Create virtual server');create.type='button';create.onclick=()=>createObject('virtual-servers',addServer);empty.append(create);byId('pools').append(empty);}
        for (const pool of data.virtual_servers) {
            const section = node('section');
            const heading = node('h2',pool.name); heading.prepend(healthBadge(health['virtual-servers'].get(pool.name),'virtual-servers',pool.name));
            section.append(heading, node('p', pool.listen + ' · ' + pool.algorithm));
            if (pool.description) section.append(node('p', pool.description));
            if (pool.app_url) {
                const url = new URL(pool.app_url);
                if (['http:','https:'].includes(url.protocol) && !url.username && !url.password) {
                    const link = node('a','Open app'); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer';link.dataset.overviewLink=pool.name; section.append(link);
                }
            }
            if(pool.traffic){
                const metrics=node('div');metrics.className='overview-latency';
                for(const [title,key] of [['Backend connect','connect_latency'],['Backend response','response_latency'],['Health check','probe_latency']]){const sample=pool.traffic[key],card=node('div');card.append(node('span',title),node('strong',sample?.samples?sample.average_ms.toFixed(2)+' ms avg':'—'),node('small',sample?.samples?sample.maximum_ms.toFixed(2)+' ms max':'No samples yet'));metrics.append(card);}
                section.append(metrics);
            }
            if (pool.traffic) section.append(node('p','Failures: '+pool.traffic.failures+' · Session timeouts: '+(pool.traffic.session_timeouts??'—')+' · Transport errors: '+(pool.traffic.transport_errors??'—')+' · Backend errors: '+(pool.traffic.backend_errors??'—')));
            if (pool.monitor) section.append(node('p','Readiness monitor: ' + pool.monitor));
            if (pool.connection_limit) section.append(node('p','Capacity (all generations): ' + (pool.admission_active ?? '—') + ' / ' + pool.connection_limit));
            if (pool.priority_group_min_active) section.append(node('p','Priority group minimum: ' + pool.priority_group_min_active));
            if (pool.default_pool) section.append(node('p', 'Default pool: ' + pool.default_pool));
            const edit = node('button', 'Edit virtual server');
            edit.type = 'button';edit.dataset.overviewEdit=pool.name;
            edit.onclick = () => {
                const editor = [...servers.children].find(c => c.dataset.originalName === pool.name);
                if (!editor) { say('Reload configuration to edit this virtual server.', true); return; }
                openObject(editor, 'virtual-servers');
                editor.scrollIntoView({ behavior: 'smooth', block: 'center' });
                editor.querySelector('[name=name]').focus();
            };
            section.append(edit);
            const table = node('table'), head = node('tr'),thead=node('thead'),body=node('tbody');
            table.className='overview-table';
            const caption=node('caption',pool.name+' backend health and traffic');caption.className='visually-hidden';table.append(caption);
            for (const title of ['Member', 'Health', 'Active', 'Completed', 'Failures', 'Last probe', 'Probe result']) {const cell=node('th', title);cell.scope='col';head.append(cell);}
            thead.append(head);table.append(thead,body);
            for (const member of pool.members) {
                const row = node('tr'),name=node('th',member.address);name.scope='row';
                const details=node('details');details.dataset.memberKey=pool.name+' / '+member.address;details.open=memberDetailsOpen.has(details.dataset.memberKey);
                details.append(node('summary','Traffic and latency details'),node('p','Bytes to backend / client: '+member.bytes_to_backend+' / '+member.bytes_to_client),node('p','Priority: '+(member.priority??0)+' · Capacity: '+(member.admission_active??member.active)+' / '+(member.connection_limit||'Unlimited')),node('p',latencyText(member.traffic)));name.append(details);row.append(name);
                const memberState = member.draining ? 'unavailable' : member.healthy ? 'up' : member.last_probe == null ? 'unknown' : 'down';
                const badge=node('td');badge.append(healthBadge(memberState));row.append(badge);
                for(const text of [member.active,member.completed,member.failures,member.last_probe?new Date(member.last_probe*1000).toLocaleTimeString():'Pending',member.probe_error??(member.probe_latency_ms==null?'Pending':member.probe_latency_ms+' ms')])row.append(node('td',text));
                body.append(row);
            }
            section.append(pool.members.length?scrollTable(table,pool.name+' backend members'):emptyState('No pool members','Edit this virtual server or its assigned pool to add backends.'));byId('pools').append(section);
        }
        if(focusedMember)[...byId('pools').querySelectorAll('[data-member-key]')].find(d=>d.dataset.memberKey===focusedMember)?.querySelector('summary').focus({preventScroll:true});
        else if(focusedEdit)[...byId('pools').querySelectorAll('[data-overview-edit]')].find(b=>b.dataset.overviewEdit===focusedEdit)?.focus({preventScroll:true});
        else if(focusedLink)[...byId('pools').querySelectorAll('[data-overview-link]')].find(b=>b.dataset.overviewLink===focusedLink)?.focus({preventScroll:true});
        }
        byId('error').textContent = ''; byId('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (error) {
        renderApplianceHeader({role:'unknown',hostname:byId('appliance-hostname').textContent,configuration_sync:'unknown',sync_error:'Live appliance state unavailable'});
        for (const key of Object.keys(health)) health[key].clear();
        for(const map of Object.values(objectLatency))map.clear();
        updateHealthBadges();
        for (const badge of byId('pools').querySelectorAll('.health-badge:not([data-health-kind])')) badge.replaceWith(healthBadge('unknown'));
        byId('error').textContent = error.message + ' — displayed data may be stale';
    }
}
async function showInterfaces() {
    try {
        const data = await api('/api/v1/network/interfaces');
        availableInterfaces = data.map(i => i.ifname); poolSuggestions();
        const target = byId('interfaces'); target.replaceChildren();
        const table = node('table'), header = node('tr');
        for (const title of ['Interface','Enabled','Link state','MTU','MAC address','Addresses','VLAN roles (current draft)','Actions']) header.append(node('th',title));
        table.append(header);
        for (const i of data) {
            const mappings = [...vlans.children].filter(c => value(c,'interface') === i.ifname || (value(c,'tag') && value(c,'vlan_name') === i.ifname));
            const row = node('tr');
            for (const text of [i.ifname,Array.isArray(i.flags)?(i.flags.includes('UP')?'Enabled':'Disabled'):'Unknown',i.operstate ?? 'Unknown',i.mtu ?? '',i.address ?? '',(i.addr_info ?? []).map(a => a.local + '/' + a.prefixlen).join(', '),mappings.map(c => value(c,'vlan_name') + ' (' + value(c,'vlan_role') + (value(c,'tag') ? ', tag ' + value(c,'tag') : ', untagged') + ')').join(', ')]) row.append(node('td',text));
            const action=node('td');
            if(i.ifname!=='lo' && !i.link && !i.master && !mappings.some(c=>value(c,'tag') && value(c,'vlan_name')===i.ifname)) {
                const edit=node('button','Configure');edit.type='button';edit.setAttribute('aria-label','Configure '+i.ifname);edit.onclick=()=>navigate('interface-editor/'+encodeURIComponent(i.ifname));action.append(edit);
            }
            row.append(action);
            table.append(row);
        }
        for(const cell of header.children)cell.scope='col';
        table.className='interface-table';target.append(data.length?scrollTable(table,'Network interfaces'):emptyState('No interfaces available','Refresh to check the appliance network interfaces.'));
        renderInterfaceChange(await api('/api/v1/network/adapter-change'));
    } catch (error) { byId('interfaces').textContent = error.message; }
}
function renderInterfaceChange(state) {
    interfaceChange=state??{pending:false};
    for(const target of [byId('interface-change'),byId('interface-editor-confirmation')].filter(Boolean)) {
        target.replaceChildren();target.hidden=!interfaceChange.pending;
        if(!interfaceChange.pending)continue;
        target.append(node('p',interfaceChange.ifname+' is awaiting connectivity confirmation. '+interfaceChange.seconds_remaining+' seconds remain before automatic rollback.'));
        if(interfaceChange.can_confirm===false)target.append(node('p','The trial failed and could not be fully restored. Revert it or check the local console.'));
        const actions=node('div');actions.className='actions';
        for(const [label,action] of [['Keep interface changes','confirm'],['Revert interface changes','revert']]) {
            const button=node('button',label);button.type='button';button.dataset.interfaceAction=action;
            button.disabled=action==='confirm'&&(interfaceChange.can_confirm===false||interfaceChange.seconds_remaining===0);
            button.onclick=async()=>{
                const token=interfaceChange.token;
                for(const b of document.querySelectorAll('[data-interface-action]'))b.disabled=true;
                try {
                    const result=await api('/api/v1/network/adapter-change/'+action,'POST',{token});
                    renderInterfaceChange(result);say(result.message);navigate('interfaces');
                } catch(error) {say(error.message,true);try{renderInterfaceChange(await api('/api/v1/network/adapter-change'));}catch{}}
            };
            actions.append(button);
        }
        target.append(actions);
    }
    const apply=byId('interface-apply');if(apply)apply.disabled=interfaceChange.pending||apply.dataset.unavailable==='true';
    const disable=byId('interface-disable');if(disable)disable.disabled=interfaceChange.pending||disable.dataset.unavailable==='true';
    renderPendingChanges();
}
async function editInterface(ifname) {
    const target=byId('interface-editor');target.replaceChildren(node('p','Loading interface settings…'));
    byId('interface-title').textContent='Configure '+ifname;
    try {
        const data=await api('/api/v1/network/adapters/'+encodeURIComponent(ifname)),settings=data.settings;
        const inactive=Boolean(settings.uuid&&!data.active);
        target.replaceChildren();
        const error=node('p');error.className='feedback feedback-error';error.hidden=true;error.setAttribute('role','alert');error.tabIndex=-1;
        target.append(error);
        const pending=node('div');pending.id='interface-editor-confirmation';pending.className='notice';target.append(pending);
        target.append(node('p',data.active?'Connection is active.':'Connection is inactive. Enable the interface to bring it up.'));
        if(inactive)target.append(node('p','Enable the interface using its saved settings and confirm connectivity before editing those settings.'));
        if(!data.active&&!settings.uuid)target.append(node('p','Enable this interface with the settings below. Leave both address families set to None for a link without an IP address. DHCP and default routing remain disabled unless selected.'));
        target.append(node('p','An enabled interface can still show a down link when its cable, virtual NIC connection, or upstream switch port is disconnected.'));
        if(!data.editing_supported)target.append(node('p','Interface editing is unavailable in OS-provisioned mode. Start RiverLB in managed network mode to configure adapters here.'));
        const fields=node('fieldset');fields.className='editor';fields.disabled=inactive||!data.editing_supported;target.append(fields);
        fields.append(node('legend','Ethernet connection'));
        const general=node('div');general.className='grid';fields.append(general);
        const mtu=field(general,'MTU','adapter_mtu',settings.mtu,'number');mtu.min='1280';mtu.max='9216';
        const metric=field(general,'Route metric','adapter_route_metric',settings.route_metric,'number');metric.min='1';metric.max='65535';
        metric.closest('label').title='Lower values are preferred. New connections default to 600 so they do not outrank typical management routes.';
        select(general,'Reconnect on boot','adapter_autoconnect',String(settings.autoconnect),[['true','Enabled'],['false','Disabled']]);
        for(const family of ['ipv4','ipv6']) {
            const section=node('section');section.append(node('h3',family==='ipv4'?'IPv4 addressing':'IPv6 addressing'));
            const grid=node('div');grid.className='grid';section.append(grid);fields.append(section);
            const config=settings[family],prefix='adapter_'+family+'_';
            select(grid,'Address assignment',prefix+'method',config.method,[['disabled','None — no IP address'],['manual','Static'],['auto',family==='ipv4'?'DHCP':'Automatic (router advertisements / DHCPv6)']]);
            const addresses=field(grid,'Addresses with prefix',prefix+'addresses',config.addresses.join(', '),'text',false);addresses.placeholder=family==='ipv4'?'192.0.2.10/24':'2001:db8::10/64';
            addresses.closest('label').title='Separate multiple addresses with commas. Keep the current management IP while adding a new management address.';
            select(grid,'Allow default routing',prefix+'default_route',String(config.default_route),[['false','Disabled — preserve existing routing'],['true','Enabled — use this interface as a default route']]);
            const gateway=field(grid,'Default gateway',prefix+'gateway',config.gateway??'','text',false);
            gateway.closest('label').title='Optional with automatic addressing. Default routing must be enabled. Other routes are configured under Static Routes.';
            field(grid,'DNS servers',prefix+'dns',config.dns.join(', '),'text',false);
            const sync=()=>{
                const method=value(target,prefix+'method'),routing=value(target,prefix+'default_route')==='true';
                addresses.disabled=method!=='manual';addresses.required=method==='manual';
                gateway.disabled=method==='disabled'||!routing;
                grid.querySelector('[name='+prefix+'dns]').disabled=method==='disabled';
                grid.querySelector('[name='+prefix+'default_route]').disabled=method==='disabled';
            };
            grid.addEventListener('change',sync);sync();
        }
        target.append(node('p','Applying an interface change may briefly interrupt traffic. For traffic VLANs and floating addresses, use VLANs and Self IPs. The management listener keeps its configured address; add a secondary IP first when migrating it.'));
        const actions=node('div');actions.className='actions editor-actions';target.append(actions);
        const apply=node('button',inactive?'Enable interface':!data.active?'Enable and apply interface settings':'Apply interface changes');apply.id='interface-apply';apply.type='button';apply.dataset.unavailable=String(!data.editing_supported);apply.disabled=!data.editing_supported;actions.append(apply);
        if(settings.uuid) {
            const disable=node('button','Disable interface');disable.id='interface-disable';disable.type='button';disable.className='danger';disable.dataset.unavailable=String(!data.editing_supported);disable.title='Disconnect this interface and prevent its saved connection from reconnecting on boot. Confirm within 90 seconds to keep it disabled.';actions.append(disable);
            disable.onclick=async()=>{
                if(!window.confirm('Disable '+ifname+'? Its connection and traffic will stop. Keep the change within 90 seconds or it will roll back.'))return;
                error.hidden=true;disable.disabled=true;apply.disabled=true;
                try {renderInterfaceChange(await api('/api/v1/network/adapters','POST',{...JSON.parse(JSON.stringify(settings)),activate_only:false,disable:true}));say('Interface disabled temporarily. Click Keep interface changes to keep it disabled, including after reboot.');}
                catch(cause) {error.textContent=cause.message;error.hidden=false;error.focus();renderInterfaceChange(await api('/api/v1/network/adapter-change'));}
            };
        }
        const done=node('button','Done');done.type='button';done.className='secondary';done.onclick=()=>navigate('interfaces');actions.insertBefore(done,actions.querySelector('.danger'));
        apply.onclick=async()=>{
            error.hidden=true;
            const split=name=>value(target,name).split(',').map(s=>s.trim()).filter(Boolean);
            const request=JSON.parse(JSON.stringify(settings));request.activate_only=inactive;
            if(!inactive){
                if(![...fields.querySelectorAll('input,select')].every(input=>input.reportValidity()))return;
                request.mtu=Number(value(target,'adapter_mtu'));request.route_metric=Number(value(target,'adapter_route_metric'));request.autoconnect=value(target,'adapter_autoconnect')==='true';
                for(const family of ['ipv4','ipv6']) {
                    const prefix='adapter_'+family+'_',method=value(target,prefix+'method'),routing=method!=='disabled'&&value(target,prefix+'default_route')==='true';
                    request[family]={method,addresses:method==='manual'?split(prefix+'addresses'):[],gateway:method!=='disabled'&&routing?value(target,prefix+'gateway')||null:null,dns:method!=='disabled'?split(prefix+'dns'):[],default_route:routing};
                }
            }
            apply.disabled=true;
            try {renderInterfaceChange(await api('/api/v1/network/adapters','POST',request));say('Interface change applied temporarily. Verify connectivity and click Keep interface changes.');}
            catch(cause) {error.textContent=cause.message+' If connectivity was interrupted, wait 90 seconds for automatic rollback and refresh.';error.hidden=false;error.focus();apply.disabled=!data.editing_supported;}
        };
        renderInterfaceChange(await api('/api/v1/network/adapter-change'));
    } catch(error) {target.replaceChildren(node('p',error.message));const done=node('button','Back to interfaces');done.type='button';done.onclick=()=>navigate('interfaces');target.append(done);}
}
async function showHistory() {
    try {
        const data = await api('/api/v1/config/history');
        const target = byId('configuration-history'); target.replaceChildren();
        for (const entry of data) {
            const row = node('div'); row.className = 'object-row';
            row.append(node('span','Revision ' + entry.revision + ' · ' + new Date(entry.created * 1000).toLocaleString() + ' · ' + entry.actor));
            const button = node('button','Load into draft'); button.type = 'button';
            button.onclick = async () => {
                if (busy || (dirty && !window.confirm('Replace your unsaved draft with this saved revision?'))) return;
                lock(true);
                try { const config = await api('/api/v1/config/history/' + entry.revision); await api('/api/v1/config/validate','POST',config); fill(config); mark(); say('Revision ' + entry.revision + ' loaded into draft. Review, then Save and apply.'); }
                catch (error) { say(error.message,true); }
                finally { lock(false); }
            };
            row.append(button); target.append(row);
        }
    } catch (error) { byId('configuration-history').textContent = error.message; }
}
async function refreshCertificates() {
    try {
        const stores=['virtual_server','device'];
        const data=await Promise.all(stores.map(async store=>{
            const [certificates,requests]=await Promise.all([api(certificateBase(store)),api(certificateBase(store)+'/requests')]);
            return {store,certificates,requests};
        }));
        certificateDetails.clear();certificateRequestDetails.clear();
        for(const {store,certificates,requests} of data){
            const device=store==='device',target=byId(device?'device-certificate-list':'certificate-list'),choices=byId(device?'device-certificate-names':'certificate-names');target.replaceChildren();choices.replaceChildren();
            for(const cert of certificates){
                const option=node('option');option.value=cert.name;choices.append(option);
                const row=node('div');row.className='editor';
                row.append(node('h3',cert.name),node('p',(cert.valid_now?'Valid':'Outside validity period')+' · '+cert.days_remaining+' days remaining · Expires '+new Date(cert.not_after*1000).toLocaleString()));
                const details=node('details');details.append(node('summary','Certificate details'));
                for(const [key,label] of [['subject','Subject'],['issuer','Issuer'],['serial','Serial'],['fingerprint_sha256','SHA-256 fingerprint'],['chain_length','Chain certificates']])details.append(node('p',label+': '+cert[key]));
                details.append(node('p','Store: '+(device?'Device / management':'Virtual server')),node('p','DNS names: '+cert.dns_names.join(', ')),node('p','IP addresses: '+(cert.ip_addresses??[]).join(', ')),node('p','Not before: '+new Date(cert.not_before*1000).toLocaleString()),node('p','Assigned to: '+(cert.used_by.join(', ')||'No active assignments')));row.append(details);
                const download=node('a','Download public certificate chain');download.href=certificateBase(store)+'/objects/'+encodeURIComponent(cert.name)+'/pem';download.download=cert.name+'.pem';row.append(download);
                const remove=node('button','Delete');remove.type='button';remove.disabled=cert.used_by.length>0;remove.dataset.certificateInUse=String(cert.used_by.length>0);remove.className='danger';remove.title=cert.used_by.length?'Unassign this certificate before deleting it.':'Delete this certificate from the inventory';
                remove.onclick=async()=>{if(busy||!window.confirm('Delete certificate '+cert.name+'? Saved revisions referencing it will require reimport before restore.'))return;lock(true);try{await api(certificateBase(store)+'/objects/'+encodeURIComponent(cert.name),'DELETE',{});await refreshCertificates();say('Certificate deleted.');}catch(error){say(error.message,true);}finally{lock(false);}};const actions=node('div');actions.className='actions editor-actions';actions.append(download,remove);row.append(actions);certificateDetails.set(store+'/'+cert.name,row);
                const summary=node('div');summary.className='object-row';const open=node('button',cert.name);open.type='button';open.onclick=()=>navigate('certificate-detail/'+store+'/'+encodeURIComponent(cert.name));summary.append(open,node('span',(cert.valid_now?'Valid':'Outside validity period')+' · '+cert.days_remaining+' days remaining'));target.append(summary);
            }
            if(!certificates.length)target.append(node('p','No certificates in this store. Import or generate one.'));
            const pending=byId(device?'device-certificate-request-list':'certificate-request-list');pending.replaceChildren();
            for(const request of requests){
                const detail=node('div');detail.className='editor';detail.append(node('h3',request.name),node('p','Pending CA signature · '+request.names.join(', ')));
                const download=node('a','Download CSR');download.href=certificateBase(store)+'/requests/'+encodeURIComponent(request.name);download.download=request.name+'.csr';detail.append(download);
                const publicCsr=node('pre',request.csr);detail.append(publicCsr);
                const label=node('label'),input=node('textarea');input.rows=8;label.append(node('span','Signed certificate chain (PEM, leaf certificate first)'),input);detail.append(label);
                const upload=node('input');upload.type='file';upload.accept='.pem,.crt,.cer';upload.setAttribute('aria-label','Upload signed certificate chain');
                upload.onchange=async()=>{const file=upload.files[0];if(!file)return;try{if(file.size>262144)throw Error('Certificate exceeds 256 KiB limit.');input.value=await file.text();}catch(error){say(error.message,true);}};detail.append(upload);
                const complete=node('button','Import signed certificate');complete.type='button';complete.onclick=async()=>{if(busy)return;if(!input.value.trim()){say('Paste or upload the certificate chain signed by your CA.',true);return;}lock(true);try{await api(certificateBase(store)+'/requests/'+encodeURIComponent(request.name)+'/complete','POST',{certificate:input.value});await refreshCertificates();navigate(certificateListPage(store));say('Signed certificate imported. Assign it, then Save and apply.');}catch(error){say(error.message,true);}finally{lock(false);}};detail.append(complete);
                const remove=node('button','Delete request');remove.type='button';remove.className='danger';remove.onclick=async()=>{if(busy||!confirm('Delete this signing request and its stored private key?'))return;lock(true);try{await api(certificateBase(store)+'/requests/'+encodeURIComponent(request.name),'DELETE',{});await refreshCertificates();navigate(certificateListPage(store));say('Signing request deleted.');}catch(error){say(error.message,true);}finally{lock(false);}};const actions=node('div');actions.className='actions editor-actions';actions.append(complete,remove);detail.append(actions);
                certificateRequestDetails.set(store+'/'+request.name,detail);
                const row=node('div');row.className='object-row';const open=node('button',request.name);open.type='button';open.onclick=()=>navigate('certificate-request-detail/'+store+'/'+encodeURIComponent(request.name));row.append(open,node('span',request.names.join(', ')+' · Pending signature'));pending.append(row);
            }
            if(!requests.length)pending.append(node('p','No pending signing requests.'));
        }
        const route=window.location.hash.slice(1);if(route.startsWith('certificate-detail/')||route.startsWith('certificate-request-detail/'))navigate(route,false);
        poolSuggestions();
    }catch(error){say(error.message,true);throw error;}
}
byId('certificates-refresh').onclick=byId('device-certificates-refresh').onclick=refreshCertificates;
for (const [id,target,limit] of [['certificate-file','certificate-import-pem',262144],['private-key-file','certificate-import-key',65536]]) {
    byId(id).onchange = async () => {
        const file = byId(id).files[0]; if (!file) return;
        try {if (file.size > limit) throw Error('PEM file exceeds size limit.'); byId(target).value = await file.text();}
        catch (error) {byId(target).value = ''; say(error.message,true);}
    };
}
byId('certificate-import').onclick = async () => {
    if (busy) return;
    const body = {name:byId('certificate-import-name').value.trim(),certificate:byId('certificate-import-pem').value,private_key:byId('certificate-import-key').value};
    lock(true);
    try {
        await api(certificateBase(byId('certificate-import-store').value),'POST',body); await refreshCertificates(); navigate(certificateListPage(byId('certificate-import-store').value));
        byId('certificate-import-name').value = ''; byId('certificate-import-pem').value = ''; byId('certificate-file').value = '';
        say('Certificate imported into its selected store. Assign it, then Save and apply.');
    } catch (error) {say(error.message,true);}
    finally {body.private_key = ''; byId('certificate-import-key').value = ''; byId('private-key-file').value = ''; lock(false);}
};
function openCertificateImport(store){
    certificateStore=store;byId('certificate-import-store').value=store;
    for(const id of ['certificate-import-name','certificate-import-pem','certificate-import-key','certificate-file','private-key-file'])byId(id).value='';navigate('certificate-import');
}
byId('certificate-create').onclick=()=>openCertificateImport('virtual_server');
byId('device-certificate-create').onclick=()=>openCertificateImport('device');
byId('certificate-import-back').onclick=()=>navigate(certificateListPage(byId('certificate-import-store').value));
byId('certificate-detail-back').onclick=byId('certificate-request-back').onclick=()=>navigate(certificateListPage(certificateStore));
function syncCertificateGeneration(){
    const csr=byId('certificate-generate-mode').value==='csr';byId('certificate-generate-days').closest('label').hidden=csr;byId('certificate-generate-days').disabled=busy||csr;
    byId('certificate-generate').textContent=csr?'Generate signing request':'Generate self-signed certificate';
    byId('certificate-generate-help').textContent=csr?'Submit the CSR to your external CA. Return to its pending request to import the signed certificate. RiverLB keeps the private key; include every DNS name and IP address clients use.':'Include every DNS name or IP address clients use. Self-signed certificates require client trust.';
}
function openCertificateGeneration(store){
    certificateStore=store;byId('certificate-generate-store').value=store;byId('certificate-generate-mode').value='self_signed';byId('certificate-generate-name').value='';byId('certificate-generate-names').value='';byId('certificate-generate-days').value=365;
    for(const key of ['organization','organizational_unit','country','state','locality'])byId('certificate-subject-'+key).value='';syncCertificateGeneration();navigate('certificate-generate');
}
byId('certificate-generate-create').onclick=()=>openCertificateGeneration('virtual_server');
byId('device-certificate-generate-create').onclick=()=>openCertificateGeneration('device');
byId('certificate-generate-mode').onchange=syncCertificateGeneration;
byId('certificate-generate-back').onclick=()=>navigate(certificateListPage(byId('certificate-generate-store').value));
byId('certificate-generate').onclick=async()=>{
    if(busy)return;
    const store=byId('certificate-generate-store').value,csr=byId('certificate-generate-mode').value==='csr';
    const body={name:byId('certificate-generate-name').value.trim(),names:byId('certificate-generate-names').value.trim().toLowerCase().split(/[\s,]+/).filter(Boolean),subject:Object.fromEntries(['organization','organizational_unit','country','state','locality'].map(key=>[key,byId('certificate-subject-'+key).value.trim()]))};body.subject.country=body.subject.country.toUpperCase();
    if(!body.name||!body.names.length){say('Enter an object name and at least one DNS name or IP address.',true);return;}
    if(!csr)body.days=Number(byId('certificate-generate-days').value);
    lock(true);try{await api(certificateBase(store)+(csr?'/requests':'/self-signed'),'POST',body);await refreshCertificates();if(csr)navigate('certificate-request-detail/'+store+'/'+encodeURIComponent(body.name));else navigate(certificateListPage(store));say(csr?'Signing request created. Download it and submit it to your CA.':'Self-signed certificate created. Assign it, then Save and apply. Clients must trust it.');}catch(error){say(error.message,true);}finally{lock(false);syncCertificateGeneration();}
};
for(const key of ['management_protocol','management_tls_source'])form.elements[key].oninput=form.elements[key].onchange=()=>syncTls(form,'management');
byId('renewal-back').onclick = () => navigate('renewals');
byId('renewal-create').onclick = () => {
    for (const id of ['renewal-name','renewal-domains','renewal-email','renewal-ca']) byId(id).value = '';
    byId('renewal-directory').value = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    byId('renewal-listen').value = '0.0.0.0:80'; byId('renewal-days').value = 30;
    byId('renewal-store').value='virtual_server';
    byId('renewal-enabled').value = 'true'; byId('renewal-terms').checked = false;
    navigate('renewal-editor');
};
async function refreshPersistence() {
    try {
        const data = await api('/api/v1/persistence'); const target = byId('persistence-records'); target.replaceChildren();
        for (const vs of data.virtual_servers) {
            const section = node('div'); section.className = 'editor'; section.append(node('h3',vs.virtual_server),node('p',(vs.profile || 'Inline settings') + ' · ' + vs.total_records + ' records · revision ' + data.revision));
            const clear = node('button','Clear records'); clear.type = 'button';
            clear.onclick = async () => {
                if (busy || !window.confirm('Clear persistence records for ' + vs.virtual_server + '? New connections may select a different backend.')) return;
                lock(true);
                try {await api('/api/v1/persistence/' + encodeURIComponent(vs.virtual_server) + '/clear','POST',{}); await refreshPersistence(); say('Persistence records cleared.');}
                catch (error) {say(error.message,true);} finally {lock(false);}
            };
            section.append(clear);
            const table = node('table'), head = node('tr'); for (const title of ['Source key','Member','Expires in (seconds)']) head.append(node('th',title)); table.append(head);
            for (const record of vs.records) {const row = node('tr'); for (const text of [record.source,record.member,record.expires_in_secs]) row.append(node('td',text)); table.append(row);}
            section.append(scrollTable(table,'Persistence records for '+vs.virtual_server)); if (vs.total_records > vs.records.length) section.append(node('p','Showing the first ' + vs.records.length + ' records.'));
            target.append(section);
        }
    } catch (error) {say(error.message,true);}
}
byId('persistence-refresh').onclick = refreshPersistence;
byId('history-refresh').onclick = showHistory;
async function load() {
    say('Loading configuration…');
    const [data]=await Promise.all([api('/api/v1/config'),refreshCertificates(),loadBuiltinRiverRules()]);
    const migrated=fill(data.config);
    byId('network-mode').textContent = data.network_mode === 'managed'
        ? 'Managed mode: Save and apply changes Linux networking. Network changes may interrupt existing traffic.'
        : 'OS-provisioned mode (--external-network): network objects are saved only. Start RiverLB without this option to apply Linux networking automatically; CAP_NET_ADMIN is required.';
    configurationConfirmation=data.confirmation??{pending:false};window.riverlbRenderConfirmation?.(configurationConfirmation);
    activeManagement = data.config.management; activeManagementIdentity=managementIdentity(data.config); revision = data.revision; dirty = false; renderPendingChanges();
    byId('revision').textContent = 'Active revision ' + revision;
    if (migrated) {mark(); say('Existing inline settings and backend members copied to reusable draft objects. Save and apply to persist the migration.');}
    else say('Configuration loaded.');
    showInterfaces();
}
form.addEventListener('input', event => {
    if(event.target.closest('.interface-editor'))return;
    if(event.target.closest('.rule-catalog-toolbar'))return;
    if(event.target.name==='existing_member')return;
    const member=event.target.closest('.member-row');
    if(member){try{const name=value(member,'member_name'),address=endpoint(value(member,'member_ip'),value(member,'member_port'));if(name){member.dataset.nodeName=ensureMemberNode(name,address,member.dataset.nodeName);syncMemberRows();}}catch(error){say(error.message,true);}}
    if(event.target.closest('#node-configs')) syncMemberRows();
    if (event.target.type === 'password' || event.target.id.startsWith('certificate-') || event.target.id === 'private-key-file') return; mark(); poolSuggestions(); });
form.addEventListener('change', event => { if (!event.target.closest('.interface-editor') && !event.target.closest('.rule-catalog-toolbar') && event.target.type !== 'password' && !event.target.id.startsWith('certificate-') && event.target.id !== 'private-key-file') mark(); });
byId('add').onclick = () => createObject('virtual-servers',addServer);
byId('add-server-tls').onclick = () => createObject('server-tls',addServerTls);
byId('add-cookie-profile').onclick = () => createObject('cookie-profiles',addCookieProfile);
byId('add-http-profile').onclick = () => createObject('http-profiles',addHttpProfile);
byId('add-node').onclick=()=>createObject('nodes',addNode);
byId('add-domain-route').onclick=()=>createObject('domain-routing',addDomainRoute);
byId('node-status-refresh').onclick=async()=>{
    try{const objects=await api('/api/v1/nodes'),target=byId('node-status');target.replaceChildren();
        for(const object of objects){const row=node('div');row.className='editor';const heading=node('h4',object.name+' · '+object.address);heading.prepend(healthBadge(({Up:'up',Down:'down',Disabled:'disabled',Unavailable:'unavailable'})[object.state]??'unknown'));row.append(heading,node('p','Active: '+object.active+' · Completed: '+object.completed+' · Failures: '+object.failures),node('p',latencyText(object)),node('p','References: '+(object.instances.map(i=>i.virtual_server).join(', ')||'Unused')));target.append(row);}
        if(!objects.length)target.append(node('p','No saved nodes.'));
    }catch(e){say(e.message,true);}
};
byId('add-river-rule').onclick = () => createObject('river-rules',addRuleSet);
byId('add-persistence').onclick = () => createObject('persistence',addPersistence);
form.elements.management_object.oninput = () => syncTls(form,'management');
byId('add-monitor').onclick = () => createObject('monitors',addMonitor);
byId('add-pool').onclick = () => createObject('pools',addPool);
byId('add-vlan').onclick = () => createObject('vlans',addVlan);
byId('add-self-ip').onclick = () => createObject('self-ips',addSelfIp);
byId('add-route').onclick = () => createObject('routes',addRoute);
byId('refresh').onclick = refresh;
byId('logout').onclick = async () => { try { await api('/api/v1/auth/logout', 'POST', {}); window.location.assign('/login'); } catch (error) { say(error.message, true); } };
byId('change-password').onclick = async () => {
    try { await api('/api/v1/auth/password', 'POST', { current_password: byId('current-password').value, new_password: byId('new-password').value }); window.location.assign('/login'); }
    catch (error) { say(error.message, true); }
    finally { byId('current-password').value = ''; byId('new-password').value = ''; }
};
byId('metrics-refresh').onclick = async () => {
    try {
        const response = await fetch('/metrics');
        if (!response.ok) throw Error('Metrics unavailable');
        byId('metrics-output').textContent = await response.text();
    } catch (error) { byId('metrics-output').textContent = error.message; }
};
byId('interfaces-refresh').onclick = showInterfaces;
byId('reload').onclick = async () => {
    if (dirty && !confirm('Discard your unsaved changes?')) return;
    lock(true);
    try { await load(); } catch (error) { say(error.message, true); } finally { lock(false); }
};
byId('validate').onclick = async () => {
    try { const config = collect(); lock(true); await api('/api/v1/config/validate', 'POST', config); say('Configuration is valid. Listener availability is checked when applying.'); }
    catch (error) { say(error.message, true); } finally { lock(false); }
};
byId('network-plan').onclick = async () => {
    try {
        const config = collect(); lock(true);
        const data = await api('/api/v1/network/plan', 'POST', config);
        byId('network-preview').textContent = (data.mode === 'managed' ? 'Commands applied when saving:' : 'External mode: RiverLB will not execute these commands:') + '\n' + (data.steps.map(s => (s.command[0]==='firewall-cmd'?'':'ip ') + s.command.join(' ')).join('\n') || 'No network changes.');
    } catch (error) { say(error.message, true); } finally { lock(false); }
};
form.onsubmit = async event => {
    event.preventDefault();
    if(['ha','ha-sync','administrators','system-health','alerts','backups','audit-events','security','updates','interface-editor'].includes(document.querySelector('[data-page]:not([hidden])')?.dataset.page))return;
    const started=performance.now(),timings={};let phase=started;
    const measure=name=>{const now=performance.now();timings[name]=Math.round(now-phase);phase=now;};
    try {
        const config = collect(); lock(true); measure('collect_and_lock_ms');say('Saving and applying…');
        if(window.reviewConfiguration && !await window.reviewConfiguration({revision,config})){say('Changes remain staged.');return;}
        const result = await api('/api/v1/config', 'PUT', { revision, config });
        configurationConfirmation=result.confirmation??{pending:false};window.riverlbRenderConfirmation?.(configurationConfirmation);
        measure('save_request_ms');timings.server_apply_ms=result.duration_ms??null;
        revision = result.revision; dirty = false; renderPendingChanges();
        const currentRoute = window.location.hash.slice(1).split('/')[0], objectPage = objectPages[currentRoute];
        const visibleEditor = objectPage && [...objectPage.target.children].find(c => !c.hidden);
        if (visibleEditor) window.history.replaceState(null,'','#' + currentRoute);
        const managementChanged=managementIdentity(config)!==activeManagementIdentity;
        if(!managementChanged){const applied=await api('/api/v1/config');measure('config_read_ms');revision=applied.revision;fill(applied.config);}else fill(config);
        measure('render_ms');
        byId('revision').textContent = 'Active revision ' + revision; say(result.message);
        const link = byId('new-address'); link.hidden = !managementChanged; activeManagement = config.management;activeManagementIdentity=managementIdentity(config);
        if (!link.hidden) { clearInterval(statusTimer); link.href = result.management_url; byId('error').textContent = 'Management protocol, address or certificate changed. Open the new portal using the link below; you may need to sign in again.'; }
        else { refresh(); showInterfaces(); }
    } catch (error) { say(error.message, true); } finally {
        lock(false);measure('finish_and_unlock_ms');timings.total_ms=Math.round(performance.now()-started);
        if(timings.total_ms>=1000)console.info('RiverLB apply timings (milliseconds)',timings);
    }
};
byId('export').onclick = () => {
    try {
        const url = URL.createObjectURL(new Blob([JSON.stringify(collect(), null, 2)], { type: 'application/json' }));
        const link = node('a'); link.href = url; link.download = 'riverlb-config.json'; link.click(); URL.revokeObjectURL(url);
    } catch (error) { say(error.message, true); }
};
byId('import').onclick = async () => {
    try {
        const config = JSON.parse(byId('import-json').value); lock(true);
        await api('/api/v1/config/validate', 'POST', config); fill(config); mark(); say('Imported into the form. Save and apply to activate.');
    } catch (error) { say(error.message, true); } finally { lock(false); }
};
async function refreshRenewals() {
    try {
        const jobs = await api('/api/v1/renewals'), list = byId('renewal-list'); list.replaceChildren();
        for (const job of jobs) {
            const s = job.settings, row = node('div'); row.className = 'editor';
            row.append(node('h4',s.name),node('p',s.domains.join(', ') + ' · ' + (s.enabled ? 'Enabled' : 'Disabled')),node('p','Last success: ' + (job.last_success ? new Date(job.last_success*1000).toLocaleString() : 'Never') + ' · Next check: ' + (job.next_attempt ? new Date(job.next_attempt*1000).toLocaleString() : 'Queued')));
            if(job.last_error) row.append(node('p','Last error: ' + job.last_error));
            const edit = node('button','Edit schedule'); edit.type = 'button'; edit.onclick = () => {
                for (const [id,key] of [['name','name'],['directory','directory'],['email','email'],['listen','challenge_listen'],['days','renew_before_days']]) byId('renewal-'+id).value = s[key];
                byId('renewal-store').value=s.store??'virtual_server';byId('renewal-domains').value = s.domains.join('\n'); byId('renewal-enabled').value = String(s.enabled); byId('renewal-terms').checked = s.terms_agreed; byId('renewal-ca').value = s.ca_certificate ?? '';
                navigate('renewal-editor'); byId('page-title').textContent = s.name;
            };
            const remove=node('button','Delete schedule');remove.type='button';remove.onclick=async()=>{if(!window.confirm('Delete renewal schedule '+s.name+'? The certificate will remain in inventory.')) return;try{await api('/api/v1/renewals/'+encodeURIComponent(s.name),'DELETE',{});await refreshRenewals();}catch(e){say(e.message,true);}};
            remove.className='danger';const actions=node('div');actions.className='actions editor-actions';actions.append(edit,remove);row.append(actions);list.append(row);
        }
        if(!jobs.length) list.append(node('p','No renewal schedules.'));
    } catch(e) {say(e.message,true);}
}
byId('renewals-refresh').onclick=refreshRenewals;
byId('renewal-save').onclick=async()=>{
    if(busy) return;lock(true);
    try {
        const settings={store:byId('renewal-store').value,name:byId('renewal-name').value.trim(),domains:byId('renewal-domains').value.split('\n').map(v=>v.trim()).filter(Boolean),directory:byId('renewal-directory').value.trim(),email:byId('renewal-email').value.trim(),challenge_listen:byId('renewal-listen').value.trim(),renew_before_days:Number(byId('renewal-days').value),enabled:byId('renewal-enabled').value==='true',terms_agreed:byId('renewal-terms').checked,ca_certificate:byId('renewal-ca').value.trim()||null};
        const result=await api('/api/v1/renewals','POST',settings);say(result.message);await refreshRenewals();navigate('renewals');
    } catch(e){say(e.message,true);}finally{lock(false);}
};
byId('backup-download').onclick=async()=>{
    if(busy)return;lock(true);
    try{const snapshot=await api('/api/v1/backup','POST',{});const url=URL.createObjectURL(new Blob([JSON.stringify(snapshot)],{type:'application/json'}));const link=node('a');link.href=url;link.download='riverlb-private-backup.json';link.click();URL.revokeObjectURL(url);say('Private backup downloaded. It contains private keys and account credentials.');}catch(e){say(e.message,true);}finally{lock(false);}
};
byId('backup-stage').onclick=async()=>{
    if(busy)return; const file=byId('backup-file').files[0];if(!file){say('Select a backup file.',true);return;}if(file.size>33554432){say('Backup exceeds 32 MiB limit.',true);return;}lock(true);
    try{const result=await api('/api/v1/restore/stage','POST',JSON.parse(await file.text()));byId('backup-file').value='';byId('backup-message').textContent=result.message;say('Backup validated and staged; live service is unchanged.');}catch(e){say(e.message,true);}finally{lock(false);}
};
window.addEventListener('beforeunload', event => { if (dirty || busy) { event.preventDefault(); event.returnValue = ''; } });
navigate(window.location.hash.slice(1), false);
refresh(); const statusTimer = setInterval(()=>{if(!document.hidden)refresh(true);}, 3000);
lock(true); load().catch(error => say(error.message, true)).finally(() => lock(false));
/* Help is attached to labels, including editors created after navigation. */
const configurationHelp = {
    listen_ip:'The virtual IP clients connect to. RiverLB provisions this address on the selected ingress VLAN when managing Linux networking.',
    listen_port:'The TCP service port clients connect to. Choose a common port or enter a custom number from 1 to 65535.',
    member_ip:'The backend server IP address that receives balanced traffic.',
    member_port:'The TCP port where the backend application listens; it can differ from the virtual server port.',
    member_name:'A reusable node name for this backend endpoint.',
    existing_member:'Choose an existing node to add its backend address to this pool.',
    node_monitor:'Checks this node endpoint with the selected monitor, overriding its pool monitor. Unassigned nodes are also checked. Blank inherits the pool monitor.',
    node_address:'Backend IP and TCP port, such as 192.168.1.20:8080. Use [IPv6]:port for IPv6.',
    algorithm:'Select how eligible pool members receive traffic. TCP balances connections; HTTP proxy mode balances requests.',
    persistence_mode:'None allows each connection or HTTP request to be balanced independently. Source or cookie persistence keeps clients assigned to a backend.',
    persistence_kind:'Source address affinity stores backend assignments. Source hash selects a backend deterministically without storing assignments.',
    ingress_vlan:'The VLAN receiving client connections. Leave blank to accept connections through any interface.',
    backend_vlan:'The VLAN used to connect to backends. Leave blank to follow Linux routing.',
    interface:'The Linux parent interface, such as eth1. Tagged VLAN traffic is created on this interface.',
    tag:'The 802.1Q VLAN ID. Leave blank for untagged traffic; tagged traffic also requires compatible host networking and switch configuration.',
    vlan_role:'Identifies this VLAN as internal or external for the network configuration.',
    vlan:'The VLAN on which RiverLB provisions this self IP.',
    address:'Self IP with prefix length, such as 192.168.11.69/24.',
    ipv4_gateway:'The reachable IPv4 gateway on this VLAN used for return routing.',
    ipv6_gateway:'The reachable IPv6 gateway on this VLAN used for return routing.',
    destination:'Destination network in CIDR notation, such as 10.0.0.0/24 or 0.0.0.0/0.',
    gateway:'The next-hop router reachable through the selected VLAN.',
    metric:'Route preference. Linux prefers lower metrics for otherwise equal routes.',
    monitor:'The named health monitor used to decide which backends are eligible. Blank uses the default TCP check.',
    kind:'TCP checks connection establishment. HTTP and HTTPS also check the configured response.',
    rise:'Consecutive successful health probes required before marking a backend up.',
    fall:'Consecutive failed health probes required before marking a backend down.',
    health_rise:'Default consecutive successful probes required to mark a backend up.',
    health_fall:'Default consecutive failed probes required to mark a backend down.',
    interval_secs:'Seconds between health probes.',
    health_interval_secs:'Default interval in seconds between backend health probes.',
    timeout_ms:'Maximum time in milliseconds allowed for a health probe.',
    connect_timeout_ms:'Maximum time in milliseconds allowed to establish a backend connection.',
    session_timeout_secs:'Maximum proxy session lifetime in seconds.',
    max_connections:'Global limit on simultaneous proxy connections.',
    connection_limit:'Maximum active connections for this virtual server. Zero means unlimited.',
    default_pool:'Reuse the members and settings of this named pool instead of the inline members.',
    server_type:'TCP balances connections; UDP balances client IP/port flows; HTTP balances requests. Automatic (formerly Standard) uses HTTP when enabled, otherwise TCP. Domain routing selects by hostname.',
    udp_idle_timeout_secs:'Seconds without client or backend datagrams before a UDP flow releases its backend and capacity slot. A later datagram creates a new flow.',
    http_enabled:'Enable HTTP parsing for per-request balancing, HTTP profiles, RiverRules and cookie persistence.',
    http_rule_sets:'Assign a configured RiverRules object. Assigned rules execute in the displayed order.',
    rule_json:'JSON actions for this RiverRules object. Copy a built-in rule before customizing it.',
    source_nat_mode:'Select the source address RiverLB uses when connecting to a backend: default proxy source, egress self IP (automap), or an explicit SNAT pool.',
    snat_addresses:'Comma-separated local source IP addresses used for backend connections.',
    source_self_ip:'Use this configured self IP as the backend connection source.',
    domain_hostname:'Match the complete HTTP Host name, such as test.example.com, without a scheme, port or path.',
    domain_virtual_server:'The HTTP virtual server on which this hostname is matched.',
    domain_node:'The destination node receiving requests that match this hostname.',
    domain_tls_mode:'Use a stored certificate or generate one to add an HTTPS listener for this domain route.',
    domain_https_port:'The HTTPS listener port created for this route, normally 443.',
    domain_le_directory:'Production issues trusted certificates. Staging issues test certificates.',
    domain_le_terms:'Required consent to the selected certificate authority’s subscriber agreement.',
    management_protocol:'HTTP serves the administration interface in plaintext. HTTPS uses the selected device certificate. After applying, open the management link with the new protocol.',
    management:'Specific local management IP and TCP port, such as 192.168.1.7:18090.',
    management_tls_source:'Use a certificate from the device store or existing PEM files on the RiverLB host.',
    management_object:'A device certificate used by the HTTPS administration interface.',
    vs_object:'A virtual server certificate used to terminate client TLS.',
    sni_host:'The client TLS hostname selecting this certificate on the virtual server.',
    sni_certificate:'Virtual server certificate presented when the client requests the matching SNI hostname.',
    server_tls_profile:'TLS settings used to encrypt and verify connections from RiverLB to backends.',
    server_name:'TLS hostname sent to the backend and used to verify its certificate.',
    ca_certificate:'PEM trust certificate file on the RiverLB host used to verify the remote TLS certificate.',
    'certificate-generate-store':'Device certificates serve administration HTTPS. Virtual server certificates serve application traffic.',
    'certificate-generate-mode':'Self-signed creates a usable certificate immediately. CSR retains the private key and produces a request for an external certificate authority.',
    'certificate-generate-names':'One DNS name or IP per line. All names are included in the certificate request or certificate; the first is the common name.',
    'certificate-generate-days':'Self-signed certificate lifetime, from 1 to 825 days. An external CA sets the lifetime for a CSR.',
    'certificate-subject-country':'Optional two-letter country code included in the certificate subject.',
    'certificate-import-store':'Choose whether the imported certificate belongs to device management or virtual server traffic.',
    'certificate-import-pem':'PEM certificate chain, beginning with the leaf certificate followed by intermediate certificates.',
    'certificate-import-key':'The matching PEM private key. For a pending CSR, use its signed-certificate import workflow to retain the existing key.',
    'certificate-file':'Upload a PEM certificate chain; the leaf certificate must appear first.',
    'private-key-file':'Upload the PEM private key matching the leaf certificate.',
    'renewal-store':'The certificate store in which this ACME schedule issues and renews certificates.',
    'renewal-domains':'DNS names included in the renewed certificate. Every name must pass the ACME challenge.',
    'renewal-listen':'HTTP-01 challenge listener. Public validation must reach this host on port 80.',
    'renewal-days':'Start renewing when the certificate has this many days remaining.',
    'renewal-directory':'ACME certificate authority directory URL. Staging certificates are for testing.',
    'renewal-ca':'Optional PEM trust file for a custom ACME certificate authority.',
    'renewal-terms':'Required consent to the selected certificate authority’s terms.',
    'backup-file':'Select a private RiverLB backup to validate and stage for offline restoration.',
    'import-json':'Load configuration JSON into the editor. Review it, then Save and apply to activate it.',
    ipv4_prefix:'Source persistence groups IPv4 clients by this prefix length. 32 treats each address separately.',
    ipv6_prefix:'Source persistence groups IPv6 clients by this prefix length. 128 treats each address separately.',
    refresh_on_use:'Sliding expiry refreshes on use. Fixed expiry expires after the assignment was created.',
    persistence_timeout:'Seconds before a source persistence assignment expires.',
    persistence_capacity:'Maximum number of stored source persistence assignments.',
    path:'HTTP health-check request path, normally a readiness endpoint such as /health.',
    host:'HTTP Host header, or certificate server name for HTTPS/TLS checks. HTTPS/TLS names must omit the port.',
    send:'UTF-8 text sent in one UDP datagram. The monitor requires a response; sending alone does not prove service health.',
    receive:'Text required in the UDP response from the selected member.',
    query:'DNS name queried directly against each member IP and port.',
    record_type:'DNS record type that must be present in a successful, complete DNS response.',
    expected_status:'HTTP response status required for a successful health check.',
    body_contains:'Optional text that must appear in the health-check response body.',
    draining_members:'Members that finish existing sessions but receive no new assignments.',
    member_weights:'Relative traffic weights for members, entered as address=weight entries.',
    member_priorities:'Priority groups for members, entered as address=priority entries.',
    member_connection_limits:'Per-member connection limits, entered as address=limit entries.',
    priority_group_min_active:'Minimum eligible members before using a lower priority group. Zero enables all groups.',
    persistence_profile:'Reuse the source address persistence settings of this named profile.',
    http_transport_profile:'HTTP profile controlling body limits, connection reuse, streaming and WebSockets.',
    http_cookie_profile:'Cookie persistence profile used to keep HTTP clients assigned to a backend.',
    http_max_body:'Maximum request or response body size in bytes.',
    http_max_header:'Maximum buffer size in bytes for parsing HTTP headers.',
    app_url:'Optional HTTP or HTTPS URL used to launch the application from the portal.',
    domain_certificate:'Virtual server certificate covering the hostname of this route.',
    domain_certificate_days:'Validity in days for the generated self-signed route certificate.',
    domain_le_email:'Contact email registered with the ACME certificate authority.',
    cookie_method:'Insert creates an opaque persistence cookie. Rewrite replaces an application cookie. Passive learns its value. Hash selects a backend from its value.',
    cookie_ttl_secs:'Seconds before a stored cookie persistence assignment expires.',
    cookie_max_entries:'Maximum stored cookie persistence assignments.',
    cookie_expiration_secs:'Cookie browser lifetime in seconds. Blank uses the record timeout; zero creates a browser session cookie.',
    cookie_session_cookie:'Make the persistence cookie last for the browser session rather than setting an explicit expiry.',
    cookie_always_send:'Send the managed persistence cookie on every response rather than only when needed.',
    cookie_refresh_on_use:'Refresh the stored persistence assignment timeout whenever it is used.',
    cookie_override_connection_limit:'Allow persisted clients to reconnect to their assigned member even when its connection limit is reached.',
    cookie_hash_offset:'Byte offset in the application cookie value at which hashing begins.',
    cookie_hash_length:'Number of cookie bytes to hash. Zero hashes the remainder after the offset.',
    'certificate-subject-organization':'Optional organization included in the certificate subject.',
    'certificate-subject-organizational_unit':'Optional department or organizational unit included in the certificate subject.',
    'certificate-subject-state':'Optional state or province included in the certificate subject.',
    'certificate-subject-locality':'Optional city or locality included in the certificate subject.',
    'renewal-email':'Contact email registered for the ACME account.',
    'current-password':'Your current administrator password, required to authorize the password change.',
    'new-password':'The new administrator password used for subsequent sign-ins.',
    cookie_name:'Cookie name used to identify backend persistence assignments.',
    cookie_path:'URL path for which the browser sends the persistence cookie.',
    cookie_domain:'Optional domain scope for the persistence cookie.',
    cookie_secure:'Send the persistence cookie only over HTTPS.',
    cookie_http_only:'Prevent browser JavaScript from reading the persistence cookie.',
    cookie_same_site:'Controls when the browser sends the cookie with requests originating from another site.',
    http_keep_alive:'Allow reuse of HTTP connections.',
    http_streaming:'Forward request and response bodies incrementally instead of buffering entire bodies.',
    http_websockets:'Allow HTTP Upgrade requests to establish WebSocket tunnels.'
};
function attachConfigurationHelp(root=document) {
    const labels=[...(root.matches?.('label')?[root]:[]),...root.querySelectorAll('label')];
    for(const label of labels) {
        if(label.dataset.configHelp)continue;
        const control=label.querySelector('input,select,textarea');if(!control)continue;
        const key=control.name||control.id;
        let text=configurationHelp[key];
        if(!text) {
            if(/private_key/.test(key))text='Path to the matching PEM private key on the RiverLB host.';
            else if(/certificate$/.test(key))text='Certificate used for this TLS configuration; PEM file paths refer to the RiverLB host.';
            else if(/enabled$/.test(key)||key==='enabled')text='Enable this object to accept new traffic or run its configured behavior. Disable it to stop new assignments.';
            else if(/name$/.test(key))text='A unique name identifying this object in its configuration area.';
            else if(/description/.test(key))text='Optional description to help identify this configuration object.';
            else if(control.tagName==='SELECT')text='Choose a value from the available options. Save and apply activates configuration changes.';
            else if(control.type==='checkbox')text='Check to enable this option; clear to disable it. Save and apply activates configuration changes.';
            else text='Enter the value for this option. Save and apply activates configuration changes.';
        }
        if(control.min||control.max)text+=' Allowed range: '+(control.min||'no minimum')+' to '+(control.max||'no maximum')+'.';
        label.dataset.configHelp=text;
        control.setAttribute('aria-description',text);
    }
}
const configTooltip=node('div');configTooltip.id='configuration-tooltip';configTooltip.className='configuration-tooltip';configTooltip.setAttribute('role','tooltip');configTooltip.hidden=true;document.body.append(configTooltip);
let helpLabel=null;
function hideConfigurationHelp(){configTooltip.hidden=true;helpLabel?.querySelectorAll('input,select,textarea').forEach(control=>control.removeAttribute('aria-describedby'));helpLabel=null;}
function showConfigurationHelp(label) {
    if(!label?.dataset.configHelp){hideConfigurationHelp();return;}
    hideConfigurationHelp();helpLabel=label;configTooltip.textContent=label.dataset.configHelp;configTooltip.hidden=false;
    label.querySelectorAll('input,select,textarea').forEach(control=>control.setAttribute('aria-describedby',configTooltip.id));
    const box=label.getBoundingClientRect(),tip=configTooltip.getBoundingClientRect();
    configTooltip.style.left=Math.max(8,Math.min(box.left,window.innerWidth-tip.width-8))+'px';
    configTooltip.style.top=(box.bottom+tip.height+12<window.innerHeight?box.bottom+8:Math.max(8,box.top-tip.height-8))+'px';
}
document.addEventListener('pointerover',event=>{const label=event.target.closest?.('label[data-config-help]');if(label!==helpLabel)showConfigurationHelp(label);});
document.addEventListener('pointerout',event=>{if(helpLabel&&!helpLabel.contains(event.relatedTarget))hideConfigurationHelp();});
document.addEventListener('focusin',event=>showConfigurationHelp(event.target.closest?.('label[data-config-help]')));
document.addEventListener('focusout',hideConfigurationHelp);
document.addEventListener('keydown',event=>{if(event.key==='Escape')hideConfigurationHelp();});
window.addEventListener('scroll',hideConfigurationHelp,true);window.addEventListener('resize',hideConfigurationHelp);
attachConfigurationHelp();
new MutationObserver(records=>{
    const roots=new Set();
    for(const record of records){
        if(record.target.matches?.('label') && !record.target.dataset.configHelp)roots.add(record.target);
        for(const added of record.addedNodes){
            if(added.nodeType!==1 || !added.isConnected || added===configTooltip)continue;
            // Option text and other leaves cannot contain configuration labels.
            if(added.matches('label') || added.childElementCount)roots.add(added);
        }
    }
    // Building and regrouping an editor produces many overlapping mutation records.
    // Scan the outermost connected roots once, including their nested labels.
    for(const root of roots){
        if(!root.isConnected)continue;
        let ancestor=root.parentElement;
        while(ancestor && !roots.has(ancestor))ancestor=ancestor.parentElement;
        if(!ancestor)attachConfigurationHelp(root);
    }
}).observe(form,{childList:true,subtree:true});

async function refreshHaGroup() {
    try {
        const data=await api('/api/v1/ha'),g=data.group??{},s=data.settings??{};
        const grid=byId('ha-group-fields');grid.replaceChildren();
        const entries=[
            ['Group name','cluster_id',g.cluster_id??s.cluster_id??'riverlb-cluster'],
            ['Local appliance name','node_id',g.node_id??s.node_id??data.status?.hostname??'riverlb-a'],
            ['Peer appliance name','peer_id',g.peer_id??s.peer_id??'riverlb-b'],
            ['Local cluster IP','local_address',g.local_address??''],
            ['Peer cluster IP','peer_address',g.peer_address??''],
            ['Floating self IP names (comma separated)','floating_self_ips',(g.floating_self_ips??s.floating_self_ips??[]).join(', ')],
            ['Fencing resource IDs (comma separated)','fencing_resources',(g.fencing_resources??[]).join(', ')]
        ];
        for(const [label,key,val] of entries){const input=field(grid,label,key,val);input.title=label+' is local to this appliance. Reverse local and peer values on the second device.';}
        select(grid,'Traffic configuration synchronization','automatic_sync',String(g.automatic_sync??s.automatic_sync??true),[['true','Automatic'],['false','Manual']]);
        attachConfigurationHelp(grid);
        const status=data.status??{};renderApplianceHeader(status);renderSyncDetails(status);byId('ha-group-state').textContent='Role: '+(status.role??'standalone')+(data.configuration_sync?' · Configuration: '+data.configuration_sync:'')+(data.restart_required?' · Restart required':'')+(status.sync_error?' · '+status.sync_error:'');
        for(const button of document.querySelectorAll('[data-ha-action]'))button.disabled=(status.role==='standalone'||status.role==='fault')||(button.dataset.haAction==='sync'&&status.role!=='active');
        await refreshHaDeployment();
    }catch(error){byId('ha-group-state').textContent=error.message;}
}
byId('ha-refresh').onclick=refreshHaGroup;
byId('ha-sync-refresh').onclick=refreshHaGroup;
async function refreshHaDeployment() {
    try {
        const data=await api('/api/v1/ha/deployment');
        byId('ha-deploy-state').textContent=!data.installed?'HA deployment tools are missing. Install an updated appliance package set; new ISOs include them.':data.job?.message??'Ready to prepare local HA services.';
        byId('ha-deploy-identity').hidden=!data.identity;
        if(data.identity){byId('ha-deploy-sync-public').value=data.identity.sync_public_key;byId('ha-deploy-host-public').value=data.identity.host_public_key;byId('ha-deploy-host-fingerprint').value=data.identity.host_fingerprint;}
        for(const button of document.querySelectorAll('[data-ha-deploy]'))button.disabled=!data.installed||Boolean(data.job?.running)||Boolean(data.busy);
        await window.riverlbFencing?.refresh(data);
    } catch(error){byId('ha-deploy-state').textContent=error.message;}
}
byId('ha-deploy-refresh').onclick=refreshHaDeployment;
for(const button of document.querySelectorAll('[data-ha-deploy]'))button.onclick=async()=>{
    if(window.location.protocol!=='https:'){byId('ha-deploy-state').textContent='Switch management to HTTPS before entering HA deployment credentials.';return;}
    const action=button.dataset.haDeploy;
    if(['prepare','trust','start'].includes(action)&&!window.confirm(action==='start'?'Switch to HA standby? Standalone traffic will stop until the cluster is enabled.':action==='trust'?'Install the peer keys and fingerprint verified directly in its GUI?':'Prepare HA services and set the dedicated cluster account password on this appliance?'))return;
    const request={action,current_password:byId('ha-deploy-password').value,code:byId('ha-deploy-code').value||null,cluster_password:byId('ha-deploy-cluster-password').value,peer_sync_key:byId('ha-deploy-peer-sync').value.trim(),peer_host_key:byId('ha-deploy-peer-host').value.trim(),peer_host_fingerprint:byId('ha-deploy-peer-fingerprint').value.trim()};
    if(['fence','fence_probe'].includes(action)){
        try{Object.assign(request,window.riverlbFencing.request(button.dataset.fenceProbe));}
        catch(error){byId('ha-deploy-state').textContent=error.message;return;}
    }
    for(const b of document.querySelectorAll('[data-ha-deploy]'))b.disabled=true;
    window.riverlbFencing?.setBusy(true);
    try {const result=await api('/api/v1/ha/deployment','POST',request);byId('ha-deploy-state').textContent=result.message;}
    catch(error){byId('ha-deploy-state').textContent=error.message;for(const b of document.querySelectorAll('[data-ha-deploy]'))b.disabled=false;window.riverlbFencing?.setBusy(false);}
    finally {for(const id of ['ha-deploy-password','ha-deploy-code','ha-deploy-cluster-password'])byId(id).value='';if(['fence','fence_probe'].includes(action))window.riverlbFencing.clearSecrets();}
};
setInterval(()=>{if(!document.querySelector('[data-page="ha"]').hidden)refreshHaDeployment();},3000);
byId('ha-save').onclick=async()=>{
    const grid=byId('ha-group-fields'),group={};
    for(const key of ['cluster_id','node_id','peer_id','local_address','peer_address'])group[key]=value(grid,key).trim();
    group.floating_self_ips=value(grid,'floating_self_ips').split(',').map(s=>s.trim()).filter(Boolean);
    group.fencing_resources=value(grid,'fencing_resources').split(',').map(s=>s.trim()).filter(Boolean);
    group.automatic_sync=value(grid,'automatic_sync')==='true';
    try {const result=await api('/api/v1/ha','PUT',group);await refreshHaGroup();byId('ha-group-state').textContent=result.message;}
    catch(error){byId('ha-group-state').textContent=error.message;}
};
for(const button of document.querySelectorAll('[data-ha-action]'))button.onclick=async()=>{
    const action=button.dataset.haAction;
    if(['setup','seed','failover','enable'].includes(action)&&!window.confirm(action==='failover'?'Move traffic to the other appliance? Existing connections will reconnect.':'Perform HA '+action+' on this group?'))return;
    button.disabled=true;
    try{const result=await api('/api/v1/ha/action','POST',{action});await refreshHaGroup();byId('ha-group-state').textContent=result.message;say(result.message);}
    catch(error){byId('ha-group-state').textContent=error.message;say(error.message,true);button.disabled=false;}
};

function indicator(label,state) {
    const span=node('span');span.className='appliance-indicator';
    const dot=node('span');dot.className='health-dot health-'+state;dot.setAttribute('aria-hidden','true');span.append(dot,node('span',label));span.setAttribute('aria-label',label);return span;
}
function renderApplianceHeader(status) {
    if(status.interface_change)renderInterfaceChange(status.interface_change);
    if(status.confirmation){configurationConfirmation=status.confirmation;window.riverlbRenderConfirmation?.(status.confirmation);}
    if(status.version)byId('product-version').textContent='RiverLB '+status.version+(status.release_stage?' · '+status.release_stage:'');
    byId('ha-summary').hidden=false; renderPendingChanges();
    const role=status.role??'unknown',sync=status.configuration_sync??'unknown';
    byId('appliance-hostname').textContent=status.hostname??status.node_id??'RiverLB';
    byId('appliance-role').replaceChildren(indicator(role==='standalone'?'Standalone':role.charAt(0).toUpperCase()+role.slice(1),role==='active'?'up':role==='fault'?'down':role==='standby'?'standby':'unknown'));
    const labels={'synchronized':'Configuration synced','pending changes':'Config not pushed','not synchronized':'Not synchronized','standalone':'Sync not configured',stale:'Sync confirmation stale',error:'Sync error',unknown:'Sync unknown'};
    byId('appliance-sync').replaceChildren(indicator(labels[sync]??sync,sync==='synchronized'?'up':sync==='error'?'down':['pending changes','stale','not synchronized'].includes(sync)?'pending':'unknown'));
    const stamp=status.role==='active'?status.last_sent:status.last_received;
    byId('appliance-sync-time').textContent=stamp?'Last '+(status.role==='active'?'peer acknowledgment':'received')+': '+new Date(stamp*1000).toLocaleString():'';
    byId('ha-summary').title=status.sync_error??'Saved local traffic configuration sync state';
    if(status.sync_error)byId('appliance-sync-time').textContent+=' · '+status.sync_error;
    if(!document.querySelector('[data-page="ha-sync"]').hidden)renderSyncDetails(status);
}
function renderSyncDetails(status) {
    const panel=byId('ha-sync-details');panel.replaceChildren();
    const rows=[['Appliance',status.hostname??status.node_id??'RiverLB'],['Role',status.role??'unknown'],['Peer',status.peer_id??'—'],
        ['Sync mode',status.role==='standalone'?'Not configured':status.automatic_sync?'Automatic':'Manual'],
        ['Saved local configuration',status.configuration_sync??'unknown'],
        [status.role==='standby'?'Local matches received configuration':'Local configuration pushed to standby',status.local_configuration_acknowledged?'Yes':'No'],
        ['Local revision',status.local_revision??'—'],['Last peer acknowledgment',status.last_sent?new Date(status.last_sent*1000).toLocaleString():'None'],
        ['Last received configuration',status.last_received?new Date(status.last_received*1000).toLocaleString():'None']];
    const table=node('table');table.className='detail-table';for(const [name,val] of rows){const row=node('tr'),heading=node('th',name);heading.scope='row';row.append(heading,node('td',String(val)));table.append(row);}panel.append(scrollTable(table,'Configuration synchronization details'));
    if(status.sync_error)panel.append(node('p',status.sync_error));
}

let accountAction='create',signedInAdministrator='';
function clearAccountPasswords(){
    for(const id of ['admin-account-new-password','admin-account-confirm-password','admin-account-current-password','admin-account-code'])byId(id).value='';
}
function editAdministrator(username,action){
    accountAction=action;clearAccountPasswords();
    byId('admin-account-editor').hidden=false;
    byId('admin-account-role').closest('label').hidden=!['create','role'].includes(action);
    byId('admin-account-name').value=username;byId('admin-account-name').disabled=action!=='create';
    byId('admin-account-title').textContent={create:'Create administrator',password:'Reset password',delete:'Delete administrator',revoke:'Revoke sessions',role:'Change account role'}[action];
    for(const id of ['admin-account-new-password','admin-account-confirm-password'])byId(id).closest('label').hidden=!['create','password'].includes(action);
}
async function refreshAdministrators(){
    try {
        const data=await api('/api/v1/administrators?details=true');signedInAdministrator=data.current_user;
        const table=node('table'),header=node('tr');header.append(node('th','Username'),node('th','Access'),node('th','Actions'));table.append(header);
        for(const entry of data.administrators){
            const username=typeof entry==='string'?entry:entry.username;
            const row=node('tr'),actionCell=node('td'),actions=node('div');actions.className='actions';actionCell.append(actions);row.append(node('td',username+(username===signedInAdministrator?' (you)':'')),node('td',typeof entry==='string'?'Administrator':entry.role.replaceAll('_',' ')+(entry.mfa_enabled?' · MFA':'')),actionCell);
            for(const [action,title] of [['password','Reset password'],['role','Change role'],['revoke','Revoke sessions'],['delete','Delete']]){
                const button=node('button',title);button.type='button';button.className=action==='delete'?'danger':'secondary';
                button.disabled=action==='delete'&&(username===signedInAdministrator||data.administrators.length<=1);
                button.onclick=()=>{editAdministrator(username,action);byId('admin-account-role').value=entry.role??'administrator';};actions.append(button);
            }table.append(row);
        }byId('admin-account-list').replaceChildren(table);
    }catch(error){byId('admin-account-message').textContent=error.message;}
}
byId('admin-create').onclick=()=>editAdministrator('','create');
byId('admin-account-cancel').onclick=()=>{clearAccountPasswords();byId('admin-account-editor').hidden=true;};
byId('admin-account-save').onclick=async()=>{
    const button=byId('admin-account-save');button.disabled=true;
    try {
        const request={username:byId('admin-account-name').value.trim(),action:accountAction,current_password:byId('admin-account-current-password').value,code:byId('admin-account-code').value||null};
        if(['create','role'].includes(accountAction))request.role=byId('admin-account-role').value;
        if(['create','password'].includes(accountAction)){
            if(byId('admin-account-new-password').value!==byId('admin-account-confirm-password').value)throw Error('New passwords do not match.');
            request.new_password=byId('admin-account-new-password').value;
        }
        if(accountAction==='delete'&&!window.confirm('Delete local administrator '+request.username+' and revoke their sessions?'))return;
        const result=await api('/api/v1/administrators','POST',request);
        byId('admin-account-message').textContent=result.message;byId('admin-account-editor').hidden=true;
        if(result.sign_in_required){window.location.assign('/login');return;}
        await refreshAdministrators();
    }catch(error){byId('admin-account-message').textContent=error.message;}
    finally{clearAccountPasswords();button.disabled=false;}
};
