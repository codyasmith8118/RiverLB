/* Appearance is local to this browser and never changes appliance configuration. */
(() => {
    'use strict';
    const key = 'riverlb.appearance', choices = ['system', 'light', 'dark'];
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    let choice = 'system';
    try { const saved = localStorage.getItem(key); if (choices.includes(saved)) choice = saved; } catch { /* Storage can be disabled. */ }
    function apply() {
        document.documentElement.dataset.theme = choice === 'system' ? (media?.matches ? 'dark' : 'light') : choice;
        document.querySelectorAll('[data-appearance]').forEach(select => { select.value = choice; });
    }
    apply();
    media?.addEventListener?.('change', () => { if (choice === 'system') apply(); });
    window.addEventListener('storage', event => {
        if (event.key !== key && event.key !== null) return;
        choice = choices.includes(event.newValue) ? event.newValue : 'system'; apply();
    });
    const paths = {
        overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
        'virtual-servers': 'M4 5h16v6H4z M4 15h16v4H4z M7 8h.01 M7 17h.01',
        pools: 'M4 4h6v6H4z M14 4h6v6h-6z M9 15h6v6H9z M7 10v3h10v-3 M12 13v2',
        nodes: 'M12 8a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M3 22v-3a9 9 0 0 1 18 0v3 M8 17h8',
        'domain-routing': 'M3 12h18 M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 3a20 20 0 0 1 0 18 20 20 0 0 1 0-18',
        monitors: 'M2 12h5l3-8 4 16 3-8h5',
        profiles: 'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
        'river-rules': 'm8 5-6 7 6 7 M16 5l6 7-6 7 M14 3l-4 18',
        interfaces: 'M5 3h14v8H5z M8 11v4 M16 11v4 M3 20h18 M12 15v5',
        vlans: 'm12 2 10 5-10 5L2 7z M2 12l10 5 10-5 M2 17l10 5 10-5',
        'self-ips': 'M12 21s7-6 7-12A7 7 0 0 0 5 9c0 6 7 12 7 12 M12 6a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
        routes: 'M4 20V8a4 4 0 0 1 4-4h12 M15 1l5 3-5 3 M4 16h12a4 4 0 0 0 4-4v-1',
        ha: 'M2 5h8v14H2z M14 5h8v14h-8z M10 9h4 M10 15h4',
        'ha-sync': 'M20 8a8 8 0 0 0-14-3L3 8 M3 3v5h5 M4 16a8 8 0 0 0 14 3l3-3 M16 16h5v5',
        certificates: 'M6 2h9l4 4v16H6z M14 2v5h5 M10 12h5 M10 16h5',
        settings: 'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
        administrators: 'M9 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M2 21v-2a7 7 0 0 1 14 0v2 M17 5a4 4 0 0 1 0 8 M19 16a6 6 0 0 1 3 5',
        statistics: 'M3 3v18h19 M7 17v-5 M12 17V8 M17 17V4',
        'system-health': 'M3 4h18v13H3z M8 21h8 M12 17v4 M6 10h3l2-3 2 6 2-3h3',
        alerts: 'M5 17h14l-2-3V9a5 5 0 0 0-10 0v5z M10 21h4',
        backups: 'M3 4h18v5H3z M5 9v12h14V9 M9 13h6',
        'audit-events': 'M5 3h14v19H5z M9 2h6v4H9z M9 10h6 M9 14h6 M9 18h4',
        security: 'm12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6z m-4 10 3 3 5-6',
        updates: 'M12 3v12 M7 10l5 5 5-5 M3 16v5h18v-5',
        'configuration-files': 'M5 2h10l4 4v16H5z M14 2v5h5 M8 12h8 M8 16h6'
    };
    function decorate() {
        document.querySelectorAll('[data-appearance]').forEach(select => {
            select.addEventListener('change', () => {
                choice = choices.includes(select.value) ? select.value : 'system';
                try { localStorage.setItem(key, choice); } catch { /* The selection still works for this page. */ }
                apply();
            });
        });
        const ns = 'http://www.w3.org/2000/svg';
        document.querySelectorAll('.brand').forEach(brand => {
            const icon = document.createElement('img');
            icon.src = '/favicon.svg'; icon.alt = ''; icon.width = 34; icon.height = 34;
            icon.setAttribute('aria-hidden', 'true');
            icon.setAttribute('focusable', 'false'); icon.classList.add('brand-icon');
            brand.prepend(icon);
        });
        document.querySelectorAll('#main-navigation a[data-route]').forEach(link => {
            const route = link.dataset.route;
            const path = paths[route] || paths[route.includes('certificate') ? 'certificates' : route === 'renewals' ? 'ha-sync' : 'profiles'];
            const icon = document.createElementNS(ns, 'svg');
            icon.setAttribute('viewBox', '0 0 24 24'); icon.setAttribute('aria-hidden', 'true');
            icon.setAttribute('focusable', 'false'); icon.classList.add('navigation-icon');
            const line = document.createElementNS(ns, 'path'); line.setAttribute('d', path);
            icon.append(line); link.prepend(icon);
        });
        apply();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', decorate, {once: true});
    else decorate();
})();
