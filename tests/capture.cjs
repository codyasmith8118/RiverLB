// Consent, separate proofs, private download, failure cleanup and role gating.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..');
const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'https://localhost:18090',runScripts:'outside-only',pretendToBeVisual:true});
const w=dom.window,d=w.document,id=name=>d.getElementById(name),page=d.querySelector('[data-page=capture]');
page.hidden=false;
let role='administrator',state={state:'idle'},deny=false,calls=[],proofs=[],exportCount=0,download=null,revoked=0,poll;
w.setInterval=fn=>{poll=fn;return 1;};w.URL.createObjectURL=()=> 'blob:private-fixture';w.URL.revokeObjectURL=()=>revoked++;
w.HTMLAnchorElement.prototype.click=function(){download=this.download;};
const json=value=>({ok:true,json:async()=>JSON.parse(JSON.stringify(value))});
w.fetch=async(url,options={})=>{
    calls.push({url,options});const body=options.body?JSON.parse(options.body):null;
    if(url==='/api/v1/auth/me')return json({role,token_scope:null});
    assert.equal(options.headers['X-RiverLB-Request'],'configure');
    if(url.endsWith('/interfaces'))return json({available:true,interfaces:[{name:'ens4',index:4}]});
    if(url==='/api/v1/diagnostics/captures')return json(state);
    if(url==='/api/v1/security/proof'){
        proofs.push(body);
        if(deny)return {ok:false,status:401,json:async()=>({error:'Invalid password or authenticator code'})};
        return json({proof:'fixture-proof-'+body.action,expires_in:60});
    }
    assert.equal(id('capture-password').value,'');assert.equal(id('capture-code').value,'');
    if(url.endsWith('/start')){
        assert.equal(body.proof,'fixture-proof-capture_start');assert.equal(body.request.consent,true);
        state={state:'running',id:'a'.repeat(32),request:body.request};return json(state);
    }
    if(url.endsWith('/cancel')){state={...state,state:'complete',reason:'canceled',bytes:24,packets:0,retention_seconds:600};return json(state);}
    if(url.endsWith('/delete')){state={state:'idle'};return json(state);}
    if(url.endsWith('/export')){
        exportCount++;assert.equal(body.proof,'fixture-proof-capture_export');
        const data=new Uint8Array(24);data.set([0xd4,0xc3,0xb2,0xa1]);let sent=false;
        return {ok:true,headers:new Map([['content-length','24'],['content-type','application/vnd.tcpdump.pcap']]),body:{getReader:()=>({read:async()=>{if(sent)return {done:true};sent=true;return {done:false,value:data};},cancel:async()=>{}})}};
    }
    throw Error('Unexpected capture fixture endpoint');
};
const ready=async()=>{for(let i=0;i<30;i++)await new Promise(resolve=>setImmediate(resolve));};
(async()=>{
    assert.equal(page.closest('form'),null,'Capture must not edit the configuration draft');
    w.eval(fs.readFileSync(path.join(root,'web/capture.js'),'utf8'));await ready();
    assert.equal(id('capture-interface').value,'ens4');assert.equal(id('capture-start').disabled,false);
    id('capture-host').value='10.77.10.100';id('capture-password').value='fixture-password';
    await id('capture-start').onclick();assert.equal(proofs.length,0);assert.equal(id('capture-password').value,'');
    assert.match(id('capture-message').textContent,/consent/);
    id('capture-consent').checked=true;id('capture-host').dispatchEvent(new w.Event('input',{bubbles:true}));
    assert.equal(id('capture-consent').checked,false);
    id('capture-consent').checked=true;id('capture-password').value='fixture-password';id('capture-code').value='123456';
    await id('capture-start').onclick();assert.equal(proofs[0].action,'capture_start');assert.equal(proofs[0].request.host,'10.77.10.100');
    assert.equal(id('capture-password').value,'');assert.equal(id('capture-code').value,'');assert.equal(id('capture-consent').checked,false);
    assert.equal(id('capture-start').disabled,true);assert.equal(id('capture-cancel').disabled,false);assert.equal(id('capture-export').disabled,true);
    await id('capture-cancel').onclick();assert.equal(id('capture-export').disabled,false);
    id('capture-password').value='new-fixture-proof';id('capture-code').value='654321';
    await id('capture-export').onclick();assert.equal(proofs[1].action,'capture_export');assert.equal(proofs[1].capture_id,'a'.repeat(32));
    assert.equal(exportCount,1);assert.equal(download,'riverlb-capture-'+('a'.repeat(32))+'.pcap');assert.equal(revoked,1);
    deny=true;id('capture-password').value='wrong';id('capture-code').value='wrong';await id('capture-export').onclick();
    assert.equal(exportCount,1);assert.equal(id('capture-password').value,'');assert.equal(id('capture-code').value,'');assert.match(id('capture-message').textContent,/Invalid/);
    deny=false;await id('capture-delete').onclick();assert.equal(id('capture-start').disabled,false);
    state={state:'busy'};await id('capture-refresh').onclick();assert.equal(id('capture-delete').disabled,true);assert.equal(id('capture-start').disabled,true);
    const before=calls.filter(c=>c.url.startsWith('/api/v1/diagnostics')).length;role='operator';await id('capture-refresh').onclick();
    assert.equal(id('capture-controls').hidden,true);assert.equal(d.querySelector('[data-route=capture]').hidden,true);
    assert.equal(calls.filter(c=>c.url.startsWith('/api/v1/diagnostics')).length,before);
    id('capture-password').value='discard-on-leave';id('capture-code').value='discard';page.hidden=true;
    w.dispatchEvent(new w.CustomEvent('riverlb:page',{detail:{page:'overview'}}));assert.equal(id('capture-password').value,'');assert.equal(id('capture-code').value,'');
    const count=calls.length;poll();await ready();assert.equal(calls.length,count);
    assert.ok(calls.every(c=>!c.url.includes('fixture-password')&&!c.url.includes('fixture-proof')));
    console.log('PASS capture GUI: consent, exact request proof, separate export proof, bounded private PCAP, stop/delete, denial cleanup, roles and hidden-page polling');
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>w.close());
