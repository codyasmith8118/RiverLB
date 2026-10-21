// Browser-only preferences must never stage traffic changes or depend on storage access.
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '..');
const script = fs.readFileSync(path.join(root, 'web/appearance.js'), 'utf8');
function fixture({dark = false, saved, blocked = false, page = 'index.html'} = {}) {
    const dom = new JSDOM(fs.readFileSync(path.join(root, 'web', page), 'utf8'), {
        url: 'http://localhost:9090', runScripts: 'outside-only'
    });
    const w = dom.window, media = {matches: dark}; let change;
    media.addEventListener = (name, fn) => { assert.equal(name, 'change'); change = fn; };
    w.matchMedia = () => media;
    if (saved !== undefined) w.localStorage.setItem('riverlb.appearance', saved);
    if (blocked) Object.defineProperty(w, 'localStorage', {get() { throw new Error('Storage blocked'); }});
    w.eval(script); w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
    return {dom, w, media, system(value) {media.matches = value; change();}};
}
const f = fixture({dark: true});
assert.equal(f.w.document.documentElement.dataset.theme, 'dark');
assert.equal(f.w.document.querySelector('[data-appearance]').value, 'system');
assert.equal(f.w.document.querySelectorAll('.navigation-icon').length, f.w.document.querySelectorAll('#main-navigation a').length);
assert.ok([...f.w.document.querySelectorAll('.navigation-icon, .brand-icon')].every(icon => icon.getAttribute('aria-hidden') === 'true' && icon.getAttribute('focusable') === 'false'));
assert.equal(f.w.document.querySelector('#main-navigation a').textContent, 'Overview');
let staged = 0; f.w.document.querySelector('#configuration').addEventListener('change', () => staged++);
const select = f.w.document.querySelector('[data-appearance]');
select.value = 'light'; select.dispatchEvent(new f.w.Event('change', {bubbles: true}));
assert.equal(f.w.document.documentElement.dataset.theme, 'light');
assert.equal(f.w.localStorage.getItem('riverlb.appearance'), 'light');
assert.equal(staged, 0);
f.system(true); assert.equal(f.w.document.documentElement.dataset.theme, 'light');
select.value = 'system'; select.dispatchEvent(new f.w.Event('change', {bubbles: true}));
f.system(false); assert.equal(f.w.document.documentElement.dataset.theme, 'light');
f.system(true); assert.equal(f.w.document.documentElement.dataset.theme, 'dark');
f.w.dispatchEvent(new f.w.StorageEvent('storage', {key: 'riverlb.appearance', newValue: 'light'}));
assert.equal(select.value, 'light'); assert.equal(f.w.document.documentElement.dataset.theme, 'light');
f.w.dispatchEvent(new f.w.StorageEvent('storage', {key: 'riverlb.appearance', newValue: null}));
assert.equal(select.value, 'system'); assert.equal(f.w.document.documentElement.dataset.theme, 'dark');
f.dom.window.close();
for (const options of [{saved: 'dark'}, {saved: 'invalid', dark: true}, {blocked: true, dark: true}, {saved: 'dark', page: 'login.html'}]) {
    const test = fixture(options); assert.equal(test.w.document.documentElement.dataset.theme, 'dark');
    const control = test.w.document.querySelector('[data-appearance]');
    control.value = 'light'; control.dispatchEvent(new test.w.Event('change'));
    assert.equal(test.w.document.documentElement.dataset.theme, 'light'); test.dom.window.close();
}
console.log('PASS appearance: preferences, system changes, cross-tab changes, blocked storage, accessible icons, sign-in and draft isolation');
