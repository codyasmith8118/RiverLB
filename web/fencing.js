/* Guided forms use the metadata of the fencing agents installed on this appliance. */
(() => {
    const id=name=>document.getElementById(name);
    const element=(tag,text)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;return node;};
    const platform=id('ha-fence-platform'),selector=id('ha-deploy-fence-agent');
    let catalog,loading,lastJob;
    const controls=new Map();
    const friendly={ipaddr:'Management server address',ipport:'Management port',login:'Username',passwd:'Password or API token',identity_file:'SSH private key path on this appliance',known_hosts:'Pinned SSH host keys file on this appliance'};
    const selectedAgent=()=>catalog?.agents.find(agent=>agent.name===selector.value);
    const nodeNames=()=>({local:id('ha-group-fields').querySelector('[name=node_id]')?.value??'',peer:id('ha-group-fields').querySelector('[name=peer_id]')?.value??''});
    function mapping() {
        const names=nodeNames(),coverage=id('ha-fence-coverage').value;
        const hasTarget=Boolean(selectedAgent()?.target_parameter);
        id('ha-fence-local-label').hidden=!hasTarget||coverage==='peer';id('ha-fence-peer-label').hidden=!hasTarget||coverage==='local';
        id('ha-fence-mapping-help').textContent=hasTarget?'Choose discovered machines or enter their exact IDs. For separate management hosts, create a connection for each appliance.':'This connection controls one machine directly. Select which appliance uses this management controller, then create a separate connection for its peer.';
        id('ha-fence-local-label').querySelector('span').textContent=(names.local||'This appliance')+' — machine ID';
        id('ha-fence-peer-label').querySelector('span').textContent=(names.peer||'Peer appliance')+' — machine ID';
        const check=id('ha-fence-check-target'),previous=check.value;
        const members=Object.entries(names).filter(([side])=>coverage==='both'||coverage===side);
        if(check.dataset.members!==JSON.stringify(members)){
            check.replaceChildren(...members.map(([,name])=>new Option(name||'Save the HA group first',name)));check.dataset.members=JSON.stringify(members);
            if([...check.options].some(option=>option.value===previous))check.value=previous;
        }
    }
    function clearSecrets() {
        for(const control of controls.values())if(control.dataset.secret==='true')control.value='';
        // Advanced parameters can also contain credentials; never retain them.
        id('ha-deploy-fence-parameters').value='';
    }
    function renderAgent() {
        clearSecrets();controls.clear();id('ha-fence-connection').replaceChildren();id('ha-fence-advanced').replaceChildren();id('ha-fence-targets').replaceChildren();
        id('ha-fence-local-target').value='';id('ha-fence-peer-target').value='';
        const agent=selectedAgent();id('ha-fence-agent-help').textContent=agent?.description??'Select an available integration to configure its connection.';
        for(const parameter of agent?.parameters??[]) {
            if(parameter.name===agent.target_parameter||parameter.hidden)continue;
            const label=element('label'),title=friendly[parameter.name]||parameter.label||parameter.name;
            label.append(element('span',title+(parameter.required?' (required)':'')));
            const boolean=['boolean','bool'].includes(parameter.type),choices=parameter.choices??[];
            let control;
            if(boolean||choices.length) {
                control=element('select');control.append(new Option('Use integration default',''));
                for(const choice of boolean?['1','0']:choices)control.append(new Option(boolean?(choice==='1'?'Enabled':'Disabled'):String(choice),String(choice)));
            } else {control=element('input');control.type=parameter.secret?'password':parameter.type==='integer'?'number':'text';control.autocomplete=parameter.secret?'new-password':'off';}
            control.name=parameter.name;control.dataset.fenceParameter=parameter.name;control.dataset.secret=String(Boolean(parameter.secret));
            control.required=Boolean(parameter.required);control.maxLength=4096;
            if(parameter.default!==undefined&&parameter.default!==null&&!parameter.secret)control.value=boolean?(['1','true','yes','on'].includes(String(parameter.default))?'1':'0'):String(parameter.default);
            if(parameter.name==='ssl_secure')control.value='1';
            if(parameter.name==='ssl_insecure')control.value='0';
            if(parameter.name==='ipport'&&String(parameter.default)==='80'&&agent.parameters.some(p=>p.name==='ssl_secure'))control.value='443';
            control.setAttribute('aria-description',parameter.description??title);label.dataset.configHelp=parameter.description??title;
            label.append(control);controls.set(parameter.name,control);id(parameter.advanced?'ha-fence-advanced':'ha-fence-connection').append(label);
        }
        for(const button of document.querySelectorAll('[data-fence-probe]'))button.dataset.unavailable=String(!agent||!(button.dataset.fenceProbe==='list'?agent.can_list:agent.can_status));
        const deviceFields=id('ha-fence-local-target');deviceFields.placeholder=agent?.target_parameter?'Exact machine ID, UUID or outlet':'Optional target identifier';id('ha-fence-peer-target').placeholder=deviceFields.placeholder;
        const both=id('ha-fence-coverage').querySelector('[value=both]');both.disabled=Boolean(agent&&!agent.target_parameter);
        if(both.disabled&&id('ha-fence-coverage').value==='both')id('ha-fence-coverage').value='local';
        mapping();
    }
    function renderPlatform() {
        const row=catalog?.platforms.find(item=>item.id===platform.value);
        selector.replaceChildren(new Option('Select an integration',''),...(catalog?.agents??[]).filter(agent=>row?.agents.includes(agent.name)).map(agent=>new Option(agent.label||agent.name,agent.name)));
        if(selector.options.length===2)selector.selectedIndex=1;
        id('ha-fence-state').textContent=!row?'Choose your hosting platform.':row.available?'Installed integration available. Verify the connection, machine mappings and real fencing before production use.':row.reason||'This integration is not installed on this appliance.';
        renderAgent();
    }
    async function load() {
        if(catalog)return;
        if(!loading)loading=(async()=>{
            const response=await fetch('/api/v1/ha/deployment/fencing',{headers:{'X-RiverLB-Request':'configure','X-RiverLB-Activity':'interactive'}});
            const data=JSON.parse(await response.text());if(!response.ok)throw Error(data.error||'Unable to read installed fencing integrations');
            catalog=data;platform.replaceChildren(new Option('Select a platform',''),...data.platforms.map(row=>new Option(row.label+(row.available?'':' — unavailable'),row.id)));
            renderPlatform();
        })().catch(error=>{loading=null;id('ha-fence-state').textContent=error.message;throw error;});
        await loading;
    }
    function parameters(probe) {
        const agent=selectedAgent();if(!agent)throw Error('Select an installed failover protection integration.');
        const raw=id('ha-deploy-fence-parameters').value.trim();let result={};
        if(raw){result=JSON.parse(raw);if(!result||Array.isArray(result)||typeof result!=='object'||Object.values(result).some(value=>typeof value!=='string'))throw Error('Advanced settings must be a JSON object with string values.');}
        for(const parameter of agent.parameters) {
            const control=controls.get(parameter.name);if(!control)continue;
            const value=control.value;
            if(parameter.required&&!value&&(parameter.default===undefined||parameter.default===null||String(parameter.default)===''))throw Error('Enter '+(friendly[parameter.name]||parameter.label||parameter.name)+'.');
            if(value){if(Object.hasOwn(result,parameter.name))throw Error('Set '+parameter.name+' once, using its form field.');result[parameter.name]=value;}
        }
        const names=nodeNames(),coverage=id('ha-fence-coverage').value,mappings=[];
        const sides=['local','peer'].filter(side=>coverage==='both'||coverage===side);
        for(const side of sides){const target=agent.target_parameter?id('ha-fence-'+side+'-target').value.trim():'';if(!names[side])throw Error('Save the HA group before configuring protection.');if(!target&&agent.target_parameter&&probe!=='list')throw Error('Choose the machine ID for '+names[side]+'.');if(/[;\r\n\0]/.test(target))throw Error('Machine IDs cannot contain semicolons or line breaks.');if(target)mappings.push(names[side]+':'+target);}
        if(sides.length===2&&id('ha-fence-local-target').value.trim()&&id('ha-fence-local-target').value.trim()===id('ha-fence-peer-target').value.trim())throw Error('Select different machines for the two appliances.');
        if(Object.hasOwn(result,'pcmk_host_list')||Object.hasOwn(result,'pcmk_host_map'))throw Error('Use the appliance mapping fields instead of advanced host mappings.');
        result.pcmk_host_list=sides.map(side=>names[side]).join(' ');if(mappings.length)result.pcmk_host_map=mappings.join(';');
        return result;
    }
    platform.onchange=renderPlatform;selector.onchange=renderAgent;id('ha-fence-coverage').onchange=mapping;
    function setBusy(busy){for(const control of id('ha-fencing').querySelectorAll('input,select,textarea'))control.disabled=busy;}
    window.riverlbFencing={
        async refresh(deployment) {
            await load();mapping();
            const job=deployment.job;
            if(job&&!job.running&&job.job!==lastJob&&job.probe){lastJob=job.job;id('ha-fence-state').textContent=job.ok&&job.probe==='status'&&['on','off'].includes(job.power)?`${job.target} is powered ${job.power}. No power command was requested.`:job.message;if(job.ok&&job.targets){const list=id('ha-fence-targets');list.replaceChildren(...job.targets.map(target=>new Option(target.label||target.id,target.id)));}}
            for(const button of document.querySelectorAll('[data-fence-probe]'))button.disabled=!deployment.installed||deployment.busy||Boolean(job?.running)||button.dataset.unavailable==='true';
            const save=document.querySelector('[data-ha-deploy=fence]');save.disabled=!deployment.installed||deployment.busy||Boolean(job?.running)||!selectedAgent();
            setBusy(Boolean(deployment.busy||job?.running));
        },
        request(probe) {return {fence_agent:selector.value,fence_resource:id('ha-deploy-fence-resource').value.trim(),fence_parameters:parameters(probe),...(probe?{fence_probe_action:probe,fence_target:id('ha-fence-check-target').value}:{})};},
        clearSecrets,setBusy
    };
    window.addEventListener('riverlb:page',event=>{if(event.detail.page==='ha')load().catch(()=>{});else clearSecrets();});
})();
