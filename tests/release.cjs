// Real embedded pages exercised with authenticated API fixtures and review decisions.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'..');
const clone=value=>JSON.parse(JSON.stringify(value));
const settle=()=>new Promise(resolve=>setTimeout(resolve,10));
const findButton=(parent,text)=>[...parent.querySelectorAll('button')].find(button=>button.textContent===text);
const findInput=(parent,label)=>[...parent.querySelectorAll('label')].find(item=>item.querySelector('span')?.textContent===label)?.querySelector('input');
const card=(parent,title)=>[...parent.querySelectorAll('section')].find(item=>item.querySelector('h3')?.textContent===title);
function environment(role='administrator'){
    const dom=new JSDOM(fs.readFileSync(path.join(root,'web/index.html'),'utf8'),{url:'http://localhost:18090',runScripts:'outside-only'}),w=dom.window;
    w.setInterval=()=>1;w.confirm=()=>true;const calls=[];let tokens=[{id:'fixture-token',name:'monitor',scope:'monitoring',expires:200}],confirmation={pending:false};
    const update={installed_version:'0.1.0',trust_configured:false,activation_supported:false,state:{candidate:{version:'0.2.0',sequence:2,expires:2000000000},history:[]}};
    w.fetch=async(url,options={})=>{
        calls.push({url,options});const body=options.body?JSON.parse(options.body):null;let data;
        if(url==='/api/v1/auth/me')data={username:'fixture',role};
        else if(url==='/api/v1/security/mfa')data={enabled:false};
        else if(url==='/api/v1/security/mfa/enroll'){assert.equal(body.current_password,'fixture-password');data={secret:'FIXTUREBASE32SECRET',uri:'otpauth://totp/RiverLB:fixture?secret=FIXTUREBASE32SECRET'};}
        else if(url==='/api/v1/security/mfa/confirm'){assert.equal(body.code,'123456');data={message:'Store these recovery codes.',recovery_codes:['fixture-recovery-1','fixture-recovery-2']};}
        else if(url==='/api/v1/security/settings')data=options.method==='PUT'?{saved:true}:{idle_timeout_secs:900,source_allowlist:['127.0.0.1/32']};
        else if(url==='/api/v1/security/tokens'){
            if(options.method==='POST'){assert.equal(body.scope,'monitoring');assert.equal(body.current_password,'fixture-password');assert.equal(body.lifetime_secs,172800);tokens.push({id:'new-fixture',name:body.name,scope:body.scope,expires:200});data={id:'new-fixture',token:'rlb_fixture_private_token'};}else data=tokens;
        }else if(url==='/api/v1/security/tokens/fixture-token'){assert.equal(options.method,'DELETE');tokens=tokens.filter(token=>token.id!=='fixture-token');data={revoked:true};}
        else if(url==='/api/v1/config/preview')data={confirmation_required:true,confirmation_seconds:120,changes:[{path:'/management',before:'127.0.0.1:18090',after:'192.0.2.10:18443'}]};
        else if(url==='/api/v1/config/confirmation')data=confirmation;
        else if(url==='/api/v1/config/confirm'){assert.equal(body.revision,8);confirmation={pending:false};data={revision:8};}
        else if(url==='/api/v1/updates/status')data=update;
        else if(url==='/api/v1/updates/stage'){assert.deepEqual(body,{format:'fixture-signed-bundle'});update.state.candidate={version:'0.3.0',sequence:3,expires:2000000000};data={manifest:update.state.candidate};}
        else if(url==='/api/v1/updates/activate')data={message:'Activation started; failed checks roll back.'};
        else throw Error('Unexpected release fixture request '+url);
        return {ok:true,json:async()=>clone(data),text:async()=>JSON.stringify(data)};
    };
    const load=script=>w.eval(fs.readFileSync(path.join(root,'web',script),'utf8'));
    const navigate=async page=>{for(const section of w.document.querySelectorAll('[data-page]'))section.hidden=section.dataset.page!==page;w.dispatchEvent(new w.CustomEvent('riverlb:page',{detail:{page}}));await settle();};
    const snapshot=page=>{
        if(!process.env.UI_SNAPSHOT_DIR)return;
        const html=w.document.documentElement.cloneNode(true);for(const script of html.querySelectorAll('script'))script.remove();html.querySelector('link[rel=stylesheet]').href='file://'+path.join(root,'web/style.css');html.querySelector('#page-title').textContent={security:'Security',updates:'Application Updates','config-preview':'Configuration Preview'}[page];html.querySelector('#breadcrumb').textContent='RiverLB / System / '+html.querySelector('#page-title').textContent;html.querySelector('.apply-bar').hidden=page!=='config-preview';html.querySelector('#appliance-hostname').textContent='riverlb-fixture';html.querySelector('#appliance-role').textContent='Standalone';html.querySelector('#appliance-sync').textContent='Local configuration';
        const originals=[...w.document.querySelectorAll('input')];for(const [index,input]of [...html.querySelectorAll('input')].entries()){input.setAttribute('value',['password','file'].includes(input.type)?'':originals[index].value);if(originals[index].checked)input.setAttribute('checked','');else input.removeAttribute('checked');}
        for(const secret of html.querySelectorAll('pre')){if(/rlb_fixture|fixture-recovery|FIXTUREBASE32/.test(secret.textContent))secret.textContent='Sensitive data omitted from fixture snapshot';}
        if(page==='config-preview'){
            html.querySelector('dialog').removeAttribute('open');
            const script=html.ownerDocument.createElement('script');script.textContent='document.querySelector("dialog").showModal();';html.querySelector('body').append(script);
        }
        fs.mkdirSync(process.env.UI_SNAPSHOT_DIR,{recursive:true});fs.writeFileSync(path.join(process.env.UI_SNAPSHOT_DIR,page+'.html'),'<!doctype html>\n'+html.outerHTML);
    };
    return {dom,w,calls,load,navigate,snapshot,update,setConfirmation:value=>{confirmation=value;}};
}

(async()=>{
    const account=environment();account.load('accounts.js');await account.navigate('security');const security=account.w.document.getElementById('security-controls');
    assert.match(account.w.document.getElementById('account-identity').textContent,/fixture.*administrator/);
    const policy=card(security,'Management security');findInput(policy,'Idle session timeout (seconds)').value='1200';findInput(policy,'Allowed source IPs/CIDRs (comma separated)').value='127.0.0.1/32, 192.0.2.0/24';findInput(policy,'Current password').value='fixture-password';await findButton(policy,'Save security policy').onclick();
    const policySave=account.calls.find(call=>call.url==='/api/v1/security/settings'&&call.options.method==='PUT');assert.deepEqual(JSON.parse(policySave.options.body).settings,{idle_timeout_secs:1200,source_allowlist:['127.0.0.1/32','192.0.2.0/24']});assert.equal(findInput(policy,'Current password').value,'');
    const tokens=card(security,'API tokens');findInput(tokens,'Token name').value='fixture monitor';findInput(tokens,'Lifetime (days)').value='2';findInput(tokens,'Current password').value='fixture-password';await findButton(tokens,'Create token').onclick();assert.match(tokens.textContent,/rlb_fixture_private_token/);assert.equal(findInput(tokens,'Current password').value,'');await findButton(tokens,'Revoke').onclick();assert.equal(account.calls.filter(call=>call.options.method==='DELETE').length,1);
    account.snapshot('security');
    const mfa=card(security,'Your authenticator');findInput(mfa,'Current password').value='fixture-password';await findButton(mfa,'Set up authenticator').onclick();assert.match(mfa.textContent,/otpauth:\/\/totp\/RiverLB/);assert.equal(findInput(mfa,'Current password').value,'');findInput(mfa,'Authenticator or recovery code').value='123456';await findButton(mfa,'Confirm authenticator').onclick();assert.match(mfa.textContent,/Save your recovery codes/);assert.equal(mfa.querySelector('a').getAttribute('href'),'/login');await account.navigate('overview');account.dom.window.close();

    const viewer=environment('read_only');viewer.load('accounts.js');await viewer.navigate('security');const controls=viewer.w.document.getElementById('security-controls');assert.ok(card(controls,'Your authenticator'));assert.equal(card(controls,'Management security'),undefined);assert.equal(card(controls,'API tokens'),undefined);assert.equal(viewer.w.document.body.dataset.accountRole,'read_only');assert.ok([...viewer.w.document.querySelectorAll('#configuration input')].every(input=>input.disabled));viewer.dom.window.close();

    const release=environment(),w=release.w,d=w.document;w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};w.HTMLDialogElement.prototype.close=function(){this.open=false;};release.load('release.js');await settle();
    let review=w.reviewConfiguration({revision:7,config:{management:'192.0.2.10:18443'}});await settle();let dialog=d.querySelector('dialog');assert.match(dialog.textContent,/120 seconds/);assert.match(dialog.querySelector('summary').textContent,/management/);release.snapshot('config-preview');await findButton(dialog,'Keep editing').onclick();assert.equal(await review,false);assert.equal(d.querySelector('dialog'),null);
    review=w.reviewConfiguration({revision:7,config:{management:'192.0.2.10:18443'}});await settle();dialog=d.querySelector('dialog');await findButton(dialog,'Apply reviewed changes').onclick();assert.equal(await review,true);
    review=w.reviewConfiguration({revision:7,config:{management:'192.0.2.10:18443'}});await settle();dialog=d.querySelector('dialog');dialog.dispatchEvent(new w.Event('cancel',{cancelable:true}));assert.equal(await review,false);
    release.setConfirmation({pending:true,revision:8,remaining_seconds:90,previous_management_url:'http://127.0.0.1:18090'});w.riverlbRenderConfirmation({pending:true,revision:8,remaining_seconds:90,previous_management_url:'http://127.0.0.1:18090'});const panel=d.getElementById('configuration-confirmation');assert.equal(panel.hidden,false);assert.match(panel.textContent,/90 seconds/);await findButton(panel,'Confirm configuration').onclick();assert.equal(panel.hidden,true);const polls=release.calls.filter(call=>call.url==='/api/v1/config/confirmation');assert.ok(polls.every(call=>!call.options.headers['X-RiverLB-Activity']));
    await release.navigate('updates');let updates=d.getElementById('update-controls');assert.match(updates.textContent,/Installed RiverLB version: 0\.1\.0/);assert.match(updates.textContent,/publisher public key/);assert.equal(findButton(updates,'Activate staged update').disabled,true);
    release.update.activation_supported=true;await release.navigate('updates');updates=d.getElementById('update-controls');let file=updates.querySelector('input[type=file]');Object.defineProperty(file,'files',{configurable:true,value:[{size:10,text:async()=>JSON.stringify({format:'fixture-signed-bundle'})}]});await findButton(updates,'Verify and stage bundle').onclick();assert.match(updates.textContent,/Version 0\.3\.0/);
    w.confirm=()=>false;await findButton(updates,'Activate staged update').onclick();assert.equal(release.calls.filter(call=>call.url==='/api/v1/updates/activate').length,0);w.confirm=()=>true;await findButton(updates,'Activate staged update').onclick();assert.match(updates.textContent,/Activation started/);release.snapshot('updates');release.dom.window.close();
    console.log('PASS release/security GUI: roles, policy save, MFA enrollment/recovery, one-time tokens/revoke, config diff review/cancel/apply, confirmation polling and signed update staging/activation');
})().catch(error=>{console.error(error);process.exitCode=1;});
