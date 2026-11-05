/* Private per-browser diagnostic headers; no payload mode or free-form filters. */
(() => {
    const base='/api/v1/diagnostics/captures',byId=id=>document.getElementById(id);
    const page=document.querySelector('[data-page=capture]');if(!page)return;
    let admin=false,available=false,busy=false,job={state:'idle'},serial=0,loaded=false;
    const secretIds=['capture-password','capture-code'];
    const selectorIds=['capture-interface','capture-host','capture-port','capture-protocol','capture-seconds','capture-limit','capture-consent'];
    const clear=()=>{for(const id of secretIds)byId(id).value='';};
    const active=()=>!page.hidden&&!document.hidden;
    const message=(text,failed=false)=>{const node=byId('capture-message');node.textContent=text;node.className=failed?'feedback feedback-error':'feedback';};
    const idValid=id=>typeof id==='string'&&/^[0-9a-f]{32}$/.test(id);
    function controls(){
        const exists=idValid(job.id),running=job.state==='running';
        byId('capture-controls').hidden=!admin;
        byId('capture-start').disabled=busy||!admin||!available||job.state!=='idle'||!byId('capture-interface').options.length;
        byId('capture-cancel').disabled=busy||!admin||!running||!exists;
        byId('capture-export').disabled=busy||!admin||job.state!=='complete'||!exists;
        byId('capture-delete').disabled=busy||!admin||!exists;
        byId('capture-refresh').disabled=busy;
        for(const id of selectorIds)byId(id).disabled=busy||!available||job.state!=='idle';
        for(const id of secretIds)byId(id).disabled=busy||!admin||!available;
    }
    function paint(value){
        job=value;
        const reasons={time_limit:'Time limit reached',byte_limit:'File size limit reached',packet_limit:'Packet processing limit reached',network_changed:'Interface or address changed',canceled:'Stopped by request',worker_failed:'Capture failed'};
        let text=job.state==='idle'?'No capture is retained.':job.state==='busy'?'Another browser session owns a capture. Wait for its expiry.':job.state==='unavailable'?'Capture is unavailable.':
            [job.state==='running'?'Capturing headers':job.state==='complete'?'Capture complete':'Capture failed',reasons[job.reason],job.state==='complete'?`${job.packets} packets · ${job.bytes} bytes · ${job.retention_seconds} seconds remaining`:null].filter(Boolean).join(' · ');
        byId('capture-status').textContent=text;controls();
    }
    async function response(url,method='GET',body,interactive=false){
        const headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'};
        if(interactive)headers['X-RiverLB-Activity']='interactive';
        const r=await fetch(url,{method,credentials:'same-origin',headers,body:body===undefined?undefined:JSON.stringify(body)});
        if(!r.ok){let text='Capture request failed';try{text=(await r.json()).error||text;}catch{}const error=Error(text);error.status=r.status;throw error;}
        return r;
    }
    async function json(url,method='GET',body,interactive=false){return (await response(url,method,body,interactive)).json();}
    async function refresh(interactive=false){
        if(busy||!active())return;
        const generation=++serial;
        try{
            const principal=await json('/api/v1/auth/me','GET',undefined,interactive);
            if(generation!==serial)return;
            admin=principal.role==='administrator'&&!principal.token_scope;
            document.querySelector('[data-route=capture]')?.toggleAttribute('hidden',!admin);
            if(!admin){clear();message('An administrator browser session is required.');controls();return;}
            if(!loaded){
                const choices=await json(base+'/interfaces');if(generation!==serial)return;
                available=choices.available===true;const select=byId('capture-interface');select.replaceChildren();
                for(const item of choices.interfaces||[]){const option=document.createElement('option');option.value=item.name;option.textContent=item.name;select.append(option);}
                loaded=true;
            }
            if(!available){paint({state:'unavailable'});message('Capture is unavailable on this appliance.');return;}
            const status=await json(base);if(generation!==serial)return;
            paint(status);message(available?'':'Capture is unavailable on this appliance.');
        }catch(error){if(generation!==serial)return;if([401,403].includes(error.status))admin=false;if(error.status===503){available=false;loaded=true;paint({state:'unavailable'});}clear();message(error.message,true);controls();}
    }
    async function proof(action,subject){
        try{return await json('/api/v1/security/proof','POST',{action,...subject,current_password:byId('capture-password').value,code:byId('capture-code').value.trim()||null},true);}
        finally{clear();}
    }
    async function perform(operation){
        if(busy)return;busy=true;++serial;controls();message('');
        try{await operation();}catch(error){message(error.message,true);}
        finally{clear();busy=false;controls();}
    }
    byId('capture-start').onclick=()=>perform(async()=>{
        const request={interface:byId('capture-interface').value,host:byId('capture-host').value.trim(),port:Number(byId('capture-port').value),protocol:byId('capture-protocol').value,duration_seconds:Number(byId('capture-seconds').value),max_bytes:Number(byId('capture-limit').value),consent:byId('capture-consent').checked};
        if(!request.consent)throw Error('Confirm consent before collecting traffic headers.');
        if(!request.host||!Number.isInteger(request.port)||request.port<1||request.port>65535||!Number.isInteger(request.duration_seconds)||request.duration_seconds<1||request.duration_seconds>60)throw Error('Enter one endpoint address/port and a duration from 1 to 60 seconds.');
        const grant=await proof('capture_start',{request});
        paint(await json(base+'/start','POST',{request,proof:grant.proof},true));
        byId('capture-consent').checked=false;message('Header capture started. Payload is excluded.');
    });
    byId('capture-cancel').onclick=()=>perform(async()=>{paint(await json(base+'/'+job.id+'/cancel','POST',{},true));message('Stop requested. Refresh to inspect the completed capture.');});
    byId('capture-delete').onclick=()=>perform(async()=>{paint(await json(base+'/'+job.id+'/delete','POST',{},true));message('Capture deleted.');});
    byId('capture-export').onclick=()=>perform(async()=>{
        if(!idValid(job.id))throw Error('Capture is unavailable.');
        const id=job.id,grant=await proof('capture_export',{capture_id:id});
        const r=await response(base+'/'+id+'/export','POST',{proof:grant.proof},true);
        const length=Number(r.headers.get('content-length'));
        if(!Number.isInteger(length)||length<24||length>16777216||r.headers.get('content-type')!=='application/vnd.tcpdump.pcap')throw Error('Invalid capture download.');
        const reader=r.body.getReader(),chunks=[];let count=0;
        try{while(true){const {value,done}=await reader.read();if(done)break;count+=value.byteLength;if(count>length)throw Error('Capture download exceeds its limit.');chunks.push(value);}}
        catch(error){await reader.cancel();throw error;}
        if(count!==length)throw Error('Capture expired or the download was interrupted.');
        const url=URL.createObjectURL(new Blob(chunks,{type:'application/vnd.tcpdump.pcap'}));
        try{const link=document.createElement('a');link.href=url;link.download='riverlb-capture-'+id+'.pcap';link.click();}finally{URL.revokeObjectURL(url);}
        message('Private PCAP downloaded. Store it securely.');
    });
    byId('capture-refresh').onclick=()=>{loaded=false;return refresh(true);};
    for(const id of selectorIds.filter(id=>id!=='capture-consent'))for(const kind of ['input','change'])byId(id).addEventListener(kind,()=>{byId('capture-consent').checked=false;});
    window.addEventListener('riverlb:page',event=>{if(event.detail.page==='capture')refresh();else {clear();byId('capture-consent').checked=false;}});
    window.addEventListener('pagehide',clear);
    setInterval(()=>{if(active()&&!busy)refresh();},2000);
    controls();if(active())refresh();
})();
