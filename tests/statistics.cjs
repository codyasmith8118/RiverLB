// Statistics reset UI and latency formatting against authenticated API responses.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..');
const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'http://localhost:9090',runScripts:'outside-only'});
const w=dom.window;w.setInterval=()=>1;
let resets=0,confirmed=false,history=[],noObjects=false,failStatistics=false,waitStatistics=null,byteTotal=48;
w.confirm=()=>confirmed;
const latency={samples:2,average_ms:12.5,minimum_ms:10,maximum_ms:15,last_ms:15};
const counters=()=>({accepted:resets?0:3,current:0,peak:resets?0:1,completed:resets?0:3,failures:0,bytes_in:resets?0:byteTotal,bytes_out:resets?0:byteTotal,connect_latency:resets?{samples:0}:latency,response_latency:{samples:0},probe_latency:latency});
w.fetch=async(url,options={})=>{
 let data;
 if(url==='/api/v1/statistics/reset'){
  assert.equal(options.method,'POST');assert.equal(options.headers['X-RiverLB-Request'],'configure');resets++;data={message:'Reset'};
 }else if(url==='/api/v1/statistics'){
  if(waitStatistics)await waitStatistics;
  if(failStatistics)return {ok:false,status:503};
  data={revision:1,epoch:String(resets),virtual_servers:noObjects?[]:[{name:'web',traffic:counters(),members:[{address:'127.0.0.1:80',active:0,traffic:counters()}]}],pools:[{name:'pool',traffic:counters()}]};
 }
 else if(url==='/api/v1/nodes')data=[{name:'node',active:0,connect_latency:counters().connect_latency,probe_latency:latency,instances:[{bytes_to_backend:counters().bytes_in,bytes_to_client:counters().bytes_out}]}];
 else if(url==='/api/v1/statistics/history')data=history;
 else throw Error('Unexpected URL '+url);
 return {ok:true,json:async()=>data};
};
w.eval(fs.readFileSync(path.join(root,'web/statistics.js'),'utf8'));
(async()=>{
 const id=name=>w.document.getElementById(name);
 await id('traffic-refresh').onclick();
 const view=name=>w.document.querySelector('[data-statistics-view='+name+']');
 assert.equal(id('traffic-tables').querySelectorAll('table').length,1);
 assert.equal(id('traffic-tables').querySelector('thead th').scope,'col');
 assert.equal(id('traffic-tables').querySelector('tbody th').scope,'row');
 assert.equal(id('traffic-tables').querySelector('.table-scroll').tabIndex,0);
 assert.match(id('traffic-tables').querySelector('.statistics-count').textContent,/1 object$/);
 assert.equal(id('traffic-updated').getAttribute('role'),'status');
 assert.equal(id('traffic-tables').getAttribute('aria-busy'),'false');
 assert.match(id('traffic-tables').textContent,/Active/);
 assert.doesNotMatch(id('traffic-tables').textContent,/Transport errors/);
 assert.equal(id('traffic-summary').children.length,4);
 view('latency').click();
 assert.equal(view('latency').getAttribute('aria-pressed'),'true');
 assert.match(id('traffic-tables').textContent,/12\.50 ms avg/);
 assert.match(id('traffic-tables').textContent,/Backend response latency/);
 assert.match([...id('traffic-tables').querySelectorAll('th')].find(th=>th.textContent==='Backend response latency').title,/UDP: first response/);
 const widths=[...id('traffic-tables').querySelectorAll('col')].map(c=>c.style.width);
 id('traffic-kind').value='nodes';id('traffic-kind').onchange();
 assert.match(id('traffic-tables').textContent,/Nodes/);
 assert.deepEqual([...id('traffic-tables').querySelectorAll('col')].map(c=>c.style.width),widths);
 id('traffic-filter').value='missing';id('traffic-filter').oninput();
 assert.match(id('traffic-tables').textContent,/No matching objects/);
 assert.match(id('traffic-tables').textContent,/clear the filter/);
 await id('traffic-refresh').onclick();
 assert.equal(id('traffic-filter').value,'missing');assert.equal(view('latency').getAttribute('aria-pressed'),'true');
 id('traffic-filter').value='NODE';id('traffic-filter').oninput();assert.match(id('traffic-tables').textContent,/12\.50 ms avg/);
 id('traffic-filter').value='';id('traffic-kind').value='servers';id('traffic-kind').onchange();
 view('traffic').click();assert.match(id('traffic-tables').textContent,/48 B/);
 assert.match([...id('traffic-tables').querySelectorAll('th')].find(th=>th.textContent==='In rate').title,/Current inbound throughput/);
 byteTotal=96;await id('traffic-refresh').onclick();
 for(const kind of ['servers','pools','nodes']){
  id('traffic-kind').value=kind;id('traffic-kind').onchange();
  const cells=id('traffic-tables').querySelector('tbody tr').children;
  assert.equal(cells[1].textContent,'96 B');
  assert.match(cells[3].textContent,/(?:kbit|Mbit|Gbit|bit)\/s$/);
  assert.doesNotMatch(cells[3].textContent,/^(?:0 bit\/s|—)$/);
 }
 id('traffic-kind').value='servers';id('traffic-kind').onchange();
 view('failures').click();assert.match(id('traffic-tables').textContent,/Transport errors/);
 view('latency').click();
 await id('traffic-reset').onclick();assert.equal(resets,0);
 confirmed=true;await id('traffic-reset').onclick();assert.equal(resets,1);
 assert.equal(id('traffic-reset').disabled,false);
 assert.equal(id('traffic-tables').querySelector('table tbody tr').children[1].textContent,'—');
 assert.equal(id('traffic-tables').querySelector('table tbody tr').children[1].getAttribute('aria-label'),'No latency samples yet');
 assert.match(id('traffic-updated').textContent,/Updated/);
 history=[
  {created:100,revision:1,epoch:'1',virtual_servers:[{name:'web',traffic:{bytes_in:0,bytes_out:0}}]},
  {created:105,revision:1,epoch:'1',virtual_servers:[{name:'web',traffic:{bytes_in:100,bytes_out:50}}]},
  {created:110,revision:1,epoch:'1',virtual_servers:[{name:'web',traffic:{bytes_in:150,bytes_out:175}}]}
 ];
 await id('traffic-refresh').onclick();
 const svg=id('traffic-chart').querySelector('svg');
 assert.equal(svg.getAttribute('role'),'img');
 assert.match(svg.querySelector('desc').textContent,/dashed blue line/);
 assert.match(svg.textContent,/Inbound/);assert.match(svg.textContent,/Outbound/);
 assert.match(svg.textContent,/bit\/s/);
 assert.equal(svg.querySelectorAll('polyline').length,2);
 assert.equal(svg.querySelectorAll('polyline')[1].getAttribute('stroke-dasharray'),'6 4');
 let releaseStatistics;
 waitStatistics=new Promise(resolve=>{releaseStatistics=resolve;});
 const pending=id('traffic-refresh').onclick();
 assert.equal(id('traffic-refresh').disabled,true);
 assert.equal(id('traffic-reset').disabled,true);
 assert.equal(id('traffic-refresh').textContent,'Refreshing…');
 assert.equal(id('traffic-chart').getAttribute('aria-busy'),'true');
 releaseStatistics();await pending;waitStatistics=null;
 assert.equal(id('traffic-refresh').disabled,false);
 assert.equal(id('traffic-reset').disabled,false);
 failStatistics=true;await id('traffic-refresh').onclick();
 assert.match(id('traffic-updated').textContent,/unavailable/);
 assert.equal(id('traffic-updated').classList.contains('down'),true);
 assert.equal(id('traffic-refresh').disabled,false);
 failStatistics=false;noObjects=true;await id('traffic-refresh').onclick();
 assert.equal(id('traffic-updated').classList.contains('down'),false);
 assert.match(id('traffic-tables').textContent,/No virtual servers are available/);
 assert.equal(id('traffic-object').disabled,true);
 assert.match(id('traffic-chart').textContent,/Create a virtual server/);
 console.log('PASS statistics: focused views, aligned columns, filtering, refresh preservation, summaries, latency, accessible chart, loading/error feedback and authenticated reset');
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>w.close());
