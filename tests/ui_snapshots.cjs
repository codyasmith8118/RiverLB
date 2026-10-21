// Optional static snapshots of the portal fixtures for real-browser layout review.
// These contain disposable test data; no application database is read.
const fs = require('node:fs');
const path = require('node:path');

module.exports = async function snapshots(window, directory) {
    fs.mkdirSync(directory, {recursive:true});
    const document=window.document, routes=[...document.querySelectorAll('[data-page]')].map(page=>page.dataset.page);
    const creators={vlans:'addVlan','self-ips':'addSelfIp',routes:'addRoute',monitors:'addMonitor',
        nodes:'addNode','domain-routing':'addDomainRoute','virtual-servers':'addServer',pools:'addPool',
        persistence:'addPersistence','server-tls':'addServerTls','cookie-profiles':'addCookieProfile',
        'http-profiles':'addHttpProfile','river-rules':'addRuleSet'};
    const targets={vlans:'vlans','self-ips':'self-ips',routes:'routes',monitors:'health-monitors',nodes:'node-configs','domain-routing':'domain-route-configs','virtual-servers':'servers',pools:'pool-configs',persistence:'persistence-profiles','server-tls':'server-tls-profiles','cookie-profiles':'cookie-profiles','http-profiles':'http-profiles','river-rules':'river-rule-configs'};
    function save(name, theme) {
        window.hideConfigurationHelp();
        const html=document.documentElement.cloneNode(true);
        if(theme)html.dataset.theme=theme;
        html.querySelectorAll('script').forEach(script=>script.remove());
        html.querySelector('link[rel=stylesheet]').href='file://'+path.resolve(__dirname,'../web/style.css');
        html.querySelector('link[rel=icon]').remove();
        for(const logo of html.querySelectorAll('img.brand-icon'))logo.src='file://'+path.resolve(__dirname,'../web/favicon.svg');
        const live=[...document.querySelectorAll('input,textarea,select')];
        html.querySelectorAll('input,textarea,select').forEach((control,i)=>{
            const original=live[i];
            if(control.tagName==='SELECT')for(const option of control.options)option.toggleAttribute('selected',option.value===(theme&&control.hasAttribute('data-appearance')?theme:original.value));
            else if(control.tagName==='TEXTAREA')control.textContent=original.value;
            else if(control.type==='checkbox')control.toggleAttribute('checked',original.checked);
            else if(!['file','password'].includes(control.type))control.setAttribute('value',original.value);
            else control.removeAttribute('value');
        });
        fs.writeFileSync(path.join(directory,name+'.html'),'<!doctype html>\n'+html.outerHTML);
    }
    for(const route of routes) {
        window.navigate(route,false);
        if(route==='ha')await window.refreshHaGroup();
        if(route==='administrators')await window.refreshAdministrators();
        if(route==='interfaces')await window.showInterfaces();
        if(route==='certificate-detail')document.querySelector('#certificate-list button')?.click();
        if(route==='certificate-request-detail')document.querySelector('#device-certificate-request-list button, #certificate-request-list button')?.click();
        save(route);
        if(['overview','virtual-servers','river-rules','statistics','settings','ha','administrators'].includes(route))save(route+'-dark','dark');
        if(!creators[route])continue;
        const target=document.getElementById(targets[route]);
        if(!target.children.length)window.createObject(route,window[creators[route]]);
        window.openObject(target.firstElementChild,route,false);
        save(route+'-editor');
        if(['virtual-servers','pools','monitors','river-rules'].includes(route))save(route+'-editor-dark','dark');
        if(route==='monitors'){const kind=target.firstElementChild.querySelector('[name=kind]'),previous=kind.value;for(const protocol of ['tcp','https','icmp','udp','dns','tls']){kind.value=protocol;kind.onchange();save('monitor-'+protocol);}kind.value=previous;kind.onchange();}
    }
    const originalFetch=window.fetch;
    window.fetch=async(url,options)=>url==='/api/v1/status'?{ok:true,text:async()=>JSON.stringify({virtual_servers:[],pools:[],ha:{role:'standalone',hostname:'lb-test',configuration_sync:'standalone'}})}:originalFetch(url,options);
    try{window.navigate('overview',false);await window.refresh();save('overview-empty');}finally{window.fetch=originalFetch;}
    const login=fs.readFileSync(path.resolve(__dirname,'../web/login.html'),'utf8')
        .replace('href="/style.css"','href="file://'+path.resolve(__dirname,'../web/style.css')+'"')
        .replace(/<script\b[^>]*>.*?<\/script>/g,'');
    fs.writeFileSync(path.join(directory,'login.html'),login);
    console.log('UI snapshots:', directory);
};
