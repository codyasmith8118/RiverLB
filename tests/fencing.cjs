// Guided fencing forms: metadata, mappings, read-only probes and credential lifetime.
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..');
const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'https://riverlb.test',runScripts:'outside-only'});
const {window}=dom,id=name=>window.document.getElementById(name);
id('ha-group-fields').innerHTML='<input name="node_id" value="riverlb-a"><input name="peer_id" value="riverlb-b">';
const families=['vmware','hyperv','proxmox','kvm','aws','azure','gcp','openstack','nutanix','physical','pdu','advanced'];
const agents=families.map(platform=>({name:'fence_'+platform,label:platform,platform,description:'Fixture '+platform,target_parameter:platform==='physical'?null:'port',can_list:platform!=='physical',can_status:true,parameters:[
    {name:'ipaddr',label:'Address',type:'string',required:true},
    {name:'passwd',label:'Password',type:'password',secret:true,required:true},
    {name:'ipport',label:'Port',type:'integer',default:'80'},
    {name:'ssl_secure',label:'Verify certificate',type:'boolean',default:'0'},
    {name:'ssl_insecure',label:'Skip verification',type:'boolean',default:'0',advanced:true},
    {name:'port',label:'Machine',type:'string',required:true,hidden:platform==='physical'},
    {name:'region',label:'Region',type:'select',choices:['east','west'],advanced:true},
]}));
const catalog={platforms:families.map(id=>({id,label:id,available:true,agents:['fence_'+id]})),agents};
window.fetch=async()=>({ok:true,text:async()=>JSON.stringify(catalog)});
window.eval(fs.readFileSync(path.join(root,'web/fencing.js'),'utf8'));
(async()=>{
    await window.riverlbFencing.refresh({installed:true});
    for(const platform of families){
        id('ha-fence-platform').value=platform;id('ha-fence-platform').onchange();
        assert.equal(id('ha-deploy-fence-agent').value,'fence_'+platform);
        assert.equal(id('ha-fence-connection').querySelector('[name=passwd]').type,'password');
        assert.equal(id('ha-fence-connection').querySelector('[name=ipport]').value,'443');
        assert.equal(id('ha-fence-connection').querySelector('[name=ssl_secure]').value,'1');
        assert.equal(id('ha-fence-connection').querySelector('[name=port]'),null,'Target identifiers belong in mapping controls');
        id('ha-fence-connection').querySelector('[name=ipaddr]').value='management.test';
        id('ha-fence-connection').querySelector('[name=passwd]').value='fixture-private-password';
        id('ha-fence-local-target').value='vm-a';id('ha-fence-peer-target').value='vm-b';
        id('ha-fence-coverage').value=platform==='physical'?'local':'both';id('ha-fence-coverage').onchange();
        const request=window.riverlbFencing.request('status');
        assert.equal(request.fence_probe_action,'status');assert.equal(request.fence_target,'riverlb-a');
        assert.equal(request.fence_parameters.passwd,'fixture-private-password');
        assert.equal(request.fence_parameters.pcmk_host_list,platform==='physical'?'riverlb-a':'riverlb-a riverlb-b');
        if(platform!=='physical')assert.equal(request.fence_parameters.pcmk_host_map,'riverlb-a:vm-a;riverlb-b:vm-b');
        window.riverlbFencing.clearSecrets();assert.equal(id('ha-fence-connection').querySelector('[name=passwd]').value,'');
    }
    id('ha-fence-platform').value='vmware';id('ha-fence-platform').onchange();
    id('ha-fence-connection').querySelector('[name=ipaddr]').value='management.test';id('ha-fence-connection').querySelector('[name=passwd]').value='temporary-password';
    id('ha-fence-coverage').value='both';id('ha-fence-coverage').onchange();
    assert.throws(()=>window.riverlbFencing.request('status'),/machine ID/);
    assert.doesNotThrow(()=>window.riverlbFencing.request('list'),'Discovery works before machine mappings exist');
    id('ha-fence-local-target').value='same-machine';id('ha-fence-peer-target').value='same-machine';
    assert.throws(()=>window.riverlbFencing.request(),/different machines/);
    id('ha-fence-peer-target').value='other-machine';id('ha-deploy-fence-parameters').value='{"pcmk_host_map":"b:wrong"}';
    assert.throws(()=>window.riverlbFencing.request(),/mapping fields/);
    id('ha-deploy-fence-parameters').value='';
    await window.riverlbFencing.refresh({installed:true,job:{job:'probe1',running:false,ok:true,probe:'list',message:'Found machines',targets:[{id:'machine-a',label:'Friendly A'}]}});
    assert.equal(id('ha-fence-targets').firstElementChild.value,'machine-a');
    assert.equal(id('ha-fence-state').textContent,'Found machines');
    await window.riverlbFencing.refresh({installed:true,job:{job:'probe2',running:false,ok:true,probe:'status',target:'riverlb-a',power:'off',message:'Power status checked successfully'}});
    assert.match(id('ha-fence-state').textContent,/riverlb-a is powered off/);
    await window.riverlbFencing.refresh({installed:true,busy:true});assert.equal(id('ha-fence-local-target').disabled,true);
    await window.riverlbFencing.refresh({installed:true});assert.equal(id('ha-fence-local-target').disabled,false);
    window.dispatchEvent(new window.CustomEvent('riverlb:page',{detail:{page:'overview'}}));assert.equal(id('ha-fence-connection').querySelector('[name=passwd]').value,'');
    console.log('PASS fencing GUI: platform forms, secure defaults, mappings, discovery, secret clearing and busy state');
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>window.close());
