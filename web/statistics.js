/* Authenticated traffic snapshots and database history; byte rates never cross revisions. */
(() => {
    let previous = null;
    let refreshing = false;
    let resetting = false;
    const number = value => value == null ? '—' : new Intl.NumberFormat().format(value);
    const compact = (value, units, base) => {
        if (value == null) return '—';
        let index = 0;
        while (Math.abs(value) >= base && index < units.length - 1) { value /= base; index++; }
        return new Intl.NumberFormat(undefined, {maximumFractionDigits:index ? 2 : 0}).format(value) + ' ' + units[index];
    };
    const formatRate = value => compact(value, ['bit/s','kbit/s','Mbit/s','Gbit/s','Tbit/s'], 1000);
    const bytes = value => compact(value, ['B','KiB','MiB','GiB','TiB'], 1024);
    const trafficHelp = {
        'Bytes in':'Cumulative application bytes toward backends. HTTP includes request headers and body/framing; health probes and TLS/TCP/IP overhead are excluded.',
        'Bytes out':'Cumulative application bytes from backends. HTTP includes response headers and body/framing; health probes and TLS/TCP/IP overhead are excluded.',
        'In rate':'Current inbound throughput in bits per second between refreshes. A steady load produces a steady rate; cumulative bytes increase.',
        'Out rate':'Current outbound throughput in bits per second between refreshes. A steady load produces a steady rate; cumulative bytes increase.'
    };
    const views = {
        connections: [['Active','current'],['Peak','peak'],['Accepted','accepted'],['Completed','completed'],['Rejected','rejected']],
        traffic: [['Bytes in','bytes_in',bytes],['Bytes out','bytes_out',bytes],['In rate','in_rate',formatRate],['Out rate','out_rate',formatRate]],
        failures: [['Failures','failures'],['Session timeouts','session_timeouts'],['Transport errors','transport_errors'],['Backend errors','backend_errors']],
        latency: [['Backend connect','connect_latency'],['Backend response latency','response_latency'],['Health check','probe_latency']]
    };
    const kinds = {servers:'Virtual servers',pools:'Pools',members:'Pool members',nodes:'Nodes'};
    let snapshot = null, activeView = 'connections';
    const element = (tag, text, className) => {
        const item = document.createElement(tag); if(text != null)item.textContent=text;
        if(className)item.className=className; return item;
    };
    function table(title, rows, total, query) {
        const section = element('section',null,'statistics-card');
        const heading = element('div',null,'statistics-table-heading');
        const count=number(rows.length)+(rows.length===1?' object':' objects');
        heading.append(element('h3',title),element('span',query?count+' of '+number(total):count,'statistics-count'));section.append(heading);
        if(!rows.length){
            const message=query?'No matching objects. Try a different name or clear the filter.':'No '+title.toLowerCase()+' are available yet.';
            section.append(element('p',message,'statistics-empty'));return section;
        }
        const scroll=element('div',null,'table-scroll'), table=element('table',null,'statistics-table');
        scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label',title+' statistics. Scroll horizontally to view all columns.');
        const caption=element('caption',title+' — '+activeView);caption.className='visually-hidden';table.append(caption);
        const columns=views[activeView],group=element('colgroup');
        const first=element('col');first.style.width='32%';group.append(first);
        for(const _ of columns){const col=element('col');col.style.width=(68/columns.length)+'%';group.append(col);}table.append(group);
        const head=element('thead'),header=element('tr');
        for(const label of ['Object',...columns.map(c=>c[0])]){const cell=element('th',label);cell.scope='col';if(trafficHelp[label])cell.title=trafficHelp[label];if(label==='Backend response latency')cell.title='HTTP: time to response headers. UDP: first response in a flow. TCP: no response sample.';if(label==='Backend connect')cell.title='TCP connection/TLS setup, or UDP socket/source setup; UDP has no handshake.';header.append(cell);}head.append(header);table.append(head);
        const body=element('tbody');
        for(const item of rows){
            const row=element('tr'),name=element('th',item.name);name.scope='row';row.append(name);
            for(const [,key,format=number] of columns){
                const cell=element('td'),value=key.endsWith('_rate')?item[key]:item.traffic[key];
                if(activeView==='latency'&&value?.samples){
                    cell.append(element('strong',value.average_ms.toFixed(2)+' ms avg'));
                    cell.append(element('span',value.minimum_ms.toFixed(2)+'–'+value.maximum_ms.toFixed(2)+' ms','statistics-detail'));
                    cell.append(element('span',number(value.samples)+' samples','statistics-detail'));
                }else {
                    cell.textContent=activeView==='latency'?'—':format(value);
                    if(cell.textContent==='—')cell.setAttribute('aria-label',activeView==='latency'?'No latency samples yet':'Unavailable');
                }
                row.append(cell);
            }body.append(row);
        }table.append(body);scroll.append(table);section.append(scroll);return section;
    }
    function renderTables(){
        if(!snapshot)return;
        const kind=document.getElementById('traffic-kind').value,query=document.getElementById('traffic-filter').value.trim().toLowerCase();
        const rows=snapshot[kind].filter(item=>item.name.toLowerCase().includes(query));
        document.getElementById('traffic-tables').replaceChildren(table(kinds[kind],rows,snapshot[kind].length,query));
        for(const button of document.querySelectorAll('[data-statistics-view]'))button.setAttribute('aria-pressed',String(button.dataset.statisticsView===activeView));
    }
    function renderSummary(servers){
        const totals=servers.reduce((sum,item)=>{for(const key of Object.keys(sum))sum[key]+=item.traffic[key]??0;return sum;},{current:0,completed:0,failures:0,bytes_out:0});
        const root=document.getElementById('traffic-summary');root.replaceChildren();
        for(const [label,value] of [['Active sessions',number(totals.current)],['Completed',number(totals.completed)],['Failures',number(totals.failures)],['Bytes out',bytes(totals.bytes_out)]]){
            const card=element('div',null,'statistics-summary-card');card.append(element('span',label),element('strong',value));root.append(card);
        }
    }
    document.getElementById('traffic-kind').onchange=renderTables;
    document.getElementById('traffic-filter').oninput=renderTables;
    for(const button of document.querySelectorAll('[data-statistics-view]'))button.onclick=()=>{activeView=button.dataset.statisticsView;renderTables();};
    function graph(history, name) {
        const root = document.getElementById('traffic-chart'); root.replaceChildren();
        if(!name){root.append(element('p','Create a virtual server to view its throughput history.','statistics-empty'));return;}
        const rates = [];
        for (let i = 1; i < history.length; i++) {
            const before = history[i - 1], after = history[i];
            const a = before.virtual_servers.find(v => v.name === name), b = after.virtual_servers.find(v => v.name === name);
            const seconds = after.created - before.created;
            if (a && b && seconds > 0 && before.revision === after.revision && before.epoch === after.epoch && b.traffic.bytes_in >= a.traffic.bytes_in && b.traffic.bytes_out >= a.traffic.bytes_out) {
                rates.push({ time: after.created, in: (b.traffic.bytes_in - a.traffic.bytes_in) * 8 / seconds, out: (b.traffic.bytes_out - a.traffic.bytes_out) * 8 / seconds });
            } else rates.push(null);
        }
        const valid = rates.filter(Boolean);
        if (!valid.length) { root.append(element('p','History is sampled every five seconds. Generate traffic and refresh after two samples.','statistics-empty')); return; }
        const ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg');
        const shape=(tag,attributes,text)=>{
            const item=document.createElementNS(ns,tag);
            for(const [key,value] of Object.entries(attributes))item.setAttribute(key,String(value));
            if(text!=null)item.textContent=text;svg.append(item);return item;
        };
        svg.setAttribute('viewBox', '0 0 720 260'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', name + ' inbound and outbound throughput');
        svg.setAttribute('font-family','system-ui, sans-serif');svg.setAttribute('font-size','12');
        const title = document.createElementNS(ns, 'title'); title.textContent = name + ' — application throughput in bits per second'; svg.append(title);
        const maximum = Math.max(1, ...valid.map(p => Math.max(p.in, p.out)));
        const first = history[0].created, last = history[history.length - 1].created;
        const left=88,right=700,top=42,bottom=204;
        const description=document.createElementNS(ns,'desc');description.textContent='Inbound is a solid green line; outbound is a dashed blue line. Scale: zero to '+formatRate(maximum)+'. Gaps indicate a configuration change, statistics reset, or unavailable sample.';svg.append(description);
        for(const fraction of [0,.5,1]){
            const y=bottom-fraction*(bottom-top);
            shape('line',{x1:left,y1:y,x2:right,y2:y,stroke:'var(--chart-grid)','stroke-width':1});
            shape('text',{x:left-10,y:y+4,fill:'var(--muted)','text-anchor':'end'},formatRate(maximum*fraction));
        }
        const time=value=>new Date(value*1000).toLocaleTimeString();
        shape('text',{x:left,y:bottom+24,fill:'var(--muted)'},time(first));
        shape('text',{x:right,y:bottom+24,fill:'var(--muted)','text-anchor':'end'},time(last));
        for(const [key,color,label,x] of [['in','var(--chart-in)','Inbound',left],['out','var(--chart-out)','Outbound',left+124]]){
            const line=shape('line',{x1:x,y1:20,x2:x+26,y2:20,stroke:color,'stroke-width':2});
            if(key==='out')line.setAttribute('stroke-dasharray','6 4');
            shape('text',{x:x+34,y:24,fill:'var(--text)'},label);
        }
        for (const [key, color] of [['in', 'var(--chart-in)'], ['out', 'var(--chart-out)']]) {
            let points = [];
            const flush = () => {
                if (!points.length) return;
                const line=shape('polyline',{points:points.join(' '),fill:'none',stroke:color,'stroke-width':2,'stroke-linejoin':'round'});
                if(key==='out')line.setAttribute('stroke-dasharray','6 4');
                if(points.length===1){const [x,y]=points[0].split(',');shape('circle',{cx:x,cy:y,r:3,fill:color});}
                points = [];
            };
            for (const sample of rates) { if (!sample) { flush(); continue; } points.push((left+(sample.time-first)*(right-left)/Math.max(1,last-first))+','+(bottom-sample[key]*(bottom-top)/maximum)); }
            flush();
        }
        root.append(svg);
        root.append(element('p','Application throughput in bits per second. Gaps mark configuration changes, resets or missing samples.','statistics-note'));
    }
    const updated=document.getElementById('traffic-updated');
    updated.setAttribute('role','status');
    function feedback(message,error=false){updated.textContent=message;updated.classList.toggle('down',error);}
    async function refreshTraffic() {
        if (refreshing) return;
        refreshing = true;
        const button=document.getElementById('traffic-refresh'),label=button.textContent;
        button.disabled=true;button.textContent='Refreshing…';
        document.getElementById('traffic-reset').disabled=true;
        for(const id of ['traffic-tables','traffic-chart'])document.getElementById(id).setAttribute('aria-busy','true');
        if(!snapshot)feedback('Loading traffic statistics…');
        try {
            const response = await fetch('/api/v1/statistics');
            if (!response.ok) throw Error(response.status === 401 ? 'Sign in to view traffic statistics.' : 'Traffic statistics unavailable');
            const data = await response.json(), now = performance.now(), seconds = previous ? (now - previous.time) / 1000 : 0;
            const addRates = (items, prior) => items.map(item => {
                const old = prior?.find(v => v.name === item.name);
                if (old && previous.revision === data.revision && previous.epoch === data.epoch && seconds > 0) {
                    for(const direction of ['in','out']){
                        const key='bytes_'+direction;
                        if(Number.isFinite(item.traffic[key])&&Number.isFinite(old.traffic[key]))item[direction+'_rate']=Math.max(0,item.traffic[key]-old.traffic[key])*8/seconds;
                    }
                }
                return item;
            });
            const servers = addRates(data.virtual_servers, previous?.virtual_servers), pools = addRates(data.pools, previous?.pools);
            const memberRows = servers => servers.flatMap(vs => vs.members.map(m => ({ name: vs.name + ' / ' + m.address, traffic: { ...m.traffic, current: m.active, peak: m.peak_connections, accepted: m.total_connections, completed: m.completed, failures: m.failures, bytes_in: m.bytes_to_backend, bytes_out: m.bytes_to_client } })));
            const members = addRates(memberRows(data.virtual_servers), previous ? memberRows(previous.virtual_servers) : null);
            let nodes=[];
            const nodesResponse=await fetch('/api/v1/nodes');
            if(nodesResponse.ok)nodes=addRates((await nodesResponse.json()).map(n=>({name:n.name,traffic:{current:n.active,completed:n.completed,failures:n.failures,connect_latency:n.connect_latency,response_latency:n.response_latency,probe_latency:n.probe_latency,...(n.instances??[]).reduce((sum,item)=>({bytes_in:sum.bytes_in+(item.bytes_to_backend??0),bytes_out:sum.bytes_out+(item.bytes_to_client??0)}),{bytes_in:0,bytes_out:0})}})),previous?.nodes);
            snapshot={servers,pools,members,nodes};renderSummary(servers);renderTables();
            previous = { ...data, nodes, time: now };
            const updateMessage='Updated '+new Date().toLocaleTimeString()+' · Revision '+data.revision;
            feedback(nodesResponse.ok?updateMessage:updateMessage+' · Node statistics unavailable.',!nodesResponse.ok);
            const select = document.getElementById('traffic-object'), selected = select.value;
            select.replaceChildren();
            for (const vs of servers) { const option = document.createElement('option'); option.value = vs.name; option.textContent = vs.name; select.append(option); }
            select.disabled=!servers.length;
            if(!servers.length){const option=element('option','No virtual servers');option.value='';select.append(option);}
            if (servers.some(v => v.name === selected)) select.value = selected;
            const historyResponse = await fetch('/api/v1/statistics/history');
            if (!historyResponse.ok) throw Error('Traffic history unavailable');
            const history = await historyResponse.json();
            select.onchange = () => graph(history, select.value); graph(history, select.value);
        } catch (error) { feedback(error.message,true); }
        finally {
            refreshing = false;button.disabled=false;button.textContent=label;
            document.getElementById('traffic-reset').disabled=resetting;
            for(const id of ['traffic-tables','traffic-chart'])document.getElementById(id).setAttribute('aria-busy','false');
        }
    }
    document.getElementById('traffic-reset').onclick = async () => {
        if(refreshing||resetting)return;
        if (!confirm('Reset all traffic counters, latency measurements and statistics history? Active connections will continue.')) return;
        resetting=true;
        const button=document.getElementById('traffic-reset'),label=button.textContent;button.disabled=true;button.textContent='Resetting…';
        try {
            const response=await fetch('/api/v1/statistics/reset',{method:'POST',headers:{'Content-Type':'application/json','X-RiverLB-Request':'configure'},body:'{}'});
            const data=await response.json();if(!response.ok)throw Error(data.error||'Statistics reset failed');
            previous=null;await refreshTraffic();
        } catch(error){feedback(error.message,true);}
        finally {resetting=false;button.disabled=false;button.textContent=label;}
    };
    document.getElementById('traffic-refresh').onclick = refreshTraffic;
    setInterval(() => { if (!resetting && !document.hidden && !document.querySelector('[data-page=statistics]').hidden) refreshTraffic(); }, 3000);
})();
