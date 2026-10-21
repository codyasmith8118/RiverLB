// Render installed agent metadata as disposable, credential-free GUI fixtures.
// Usage: node tests/fencing_snapshots.cjs /tmp/catalog.json /tmp/ui-review
const fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..'),[catalogPath,directory]=process.argv.slice(2);
if(!catalogPath||!directory)throw Error('Usage: node tests/fencing_snapshots.cjs CATALOG_JSON SNAPSHOT_DIRECTORY');
const catalog=JSON.parse(fs.readFileSync(catalogPath,'utf8'));
const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'https://riverlb.test',runScripts:'outside-only'});
const {window}=dom,document=window.document,id=name=>document.getElementById(name);
window.fetch=async()=>({ok:true,text:async()=>JSON.stringify(catalog)});
window.eval(fs.readFileSync(path.join(root,'web/fencing.js'),'utf8'));
for(const page of document.querySelectorAll('[data-page]'))page.hidden=page.dataset.page!=='ha';
id('ha-group-fields').innerHTML='<input name="node_id" value="riverlb-a"><input name="peer_id" value="riverlb-b">';
// The full HA page is covered by portal snapshots. Focus these on each actual
// connection form, including advanced fields, without repeating earlier steps.
const fencing=id('ha-fencing');
const group=id('ha-group-fields');group.hidden=true;
document.querySelector('[data-page=ha]').replaceChildren(group,fencing);
for(const detail of fencing.querySelectorAll('details'))detail.open=true;
id('page-title').textContent='Failover protection';id('breadcrumb').textContent='High Availability / Failover protection';
document.querySelector('.apply-bar').hidden=true;
document.querySelector('[data-route=ha]').setAttribute('aria-current','page');
id('appliance-hostname').textContent='riverlb-a';id('appliance-role').textContent='Standby';
function save(agent,theme){
    const html=document.documentElement.cloneNode(true);
    if(theme)html.dataset.theme=theme;
    html.querySelectorAll('script').forEach(script=>script.remove());
    html.querySelector('link[rel=stylesheet]').href='file://'+path.join(root,'web/style.css');
    html.querySelector('link[rel=icon]').remove();
    const live=[...document.querySelectorAll('input,textarea,select')];
    html.querySelectorAll('input,textarea,select').forEach((control,index)=>{
        const original=live[index];
        if(control.tagName==='SELECT')for(const option of control.options)option.toggleAttribute('selected',option.value===original.value);
        else if(control.tagName==='TEXTAREA')control.textContent='';
        else if(control.type!=='password')control.setAttribute('value',original.value);
    });
    fs.writeFileSync(path.join(directory,'fencing-'+agent.name+(theme?'-'+theme:'')+'.html'),'<!doctype html>\n'+html.outerHTML);
}
(async()=>{
    fs.mkdirSync(directory,{recursive:true});
    await window.riverlbFencing.refresh({installed:true});
    for(const agent of catalog.agents){
        id('ha-fence-platform').value=agent.platform;id('ha-fence-platform').onchange();
        id('ha-deploy-fence-agent').value=agent.name;id('ha-deploy-fence-agent').onchange();
        id('ha-fence-coverage').value=agent.target_parameter?'both':'local';id('ha-fence-coverage').onchange();
        await window.riverlbFencing.refresh({installed:true});
        save(agent);
        if(['fence_riverlb_hyperv','fence_vmware_rest','fence_ipmilan','fence_aws','fence_pve'].includes(agent.name))save(agent,'dark');
    }
    console.log('Fencing snapshots:',catalog.agents.length,'installed agents in',directory);
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>window.close());
