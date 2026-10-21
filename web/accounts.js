(() => {
    const el = (tag, text) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node; };
    const request = async (path, method = 'GET', body) => {
        const response = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-RiverLB-Request': 'configure', 'X-RiverLB-Activity': 'interactive' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const result = await response.json();
        if (!response.ok) throw Error(result.error || 'Security operation failed');
        return result;
    };
    let generation = 0;
    function input(parent, label, value = '', type = 'text', help = 'This account setting applies immediately after its action succeeds.') {
        const wrapper = el('label'), control = el('input');
        control.type = type; control.value = value; control.autocomplete = type === 'password' ? 'current-password' : 'off';
        wrapper.dataset.configHelp = help; control.setAttribute('aria-description', help);
        wrapper.append(el('span', label), control); parent.append(wrapper); return control;
    }
    function card(root, title, text) {
        const section = el('section'); section.className = 'editor'; section.append(el('h3', title), el('p', text)); root.append(section); return section;
    }
    function feedback(root, text) {
        let message = root.querySelector(':scope > .feedback');
        if (!message) { message = el('p'); message.className = 'feedback'; message.setAttribute('role', 'status'); root.append(message); }
        message.textContent = text;
    }
    function actions(parent) {
        let row = parent.querySelector(':scope > .actions');
        if (!row) { row = el('div'); row.className = 'actions'; parent.append(row); }
        return row;
    }
    function button(parent, label, run, current, secondary = false) {
        const control = el('button', label); control.type = 'button'; if (secondary) control.className = 'secondary';
        control.onclick = async () => {
            control.disabled = true;
            try { await run(); } catch (error) { if (current === generation) feedback(parent, error.message); }
            finally { if (current === generation && control.isConnected) control.disabled = false; }
        };
        actions(parent).append(control); return control;
    }
    function clearSecrets(root) {
        for (const control of root.querySelectorAll('input')) control.value = '';
        root.replaceChildren();
    }
    async function render(page) {
        const current = ++generation, root = document.getElementById('security-controls');
        if (!root) return;
        clearSecrets(root);
        if (page !== 'security') return;
        const active = () => current === generation;
        try {
            const [me, mfa] = await Promise.all([request('/api/v1/auth/me'), request('/api/v1/security/mfa')]);
            if (!active()) return;
            const auth = card(root, 'Your authenticator', mfa.enabled ? 'MFA is enabled.' : 'MFA is not enabled.');
            const password = input(auth, 'Current password', '', 'password', 'Confirm your current password before changing your authenticator. This action applies immediately.');
            const code = input(auth, 'Authenticator or recovery code', '', 'text', 'Enter a six-digit authenticator code or an unused recovery code. Each code can be used once.');
            if (mfa.enabled) {
                button(auth, 'Disable MFA', async () => {
                    const proof = { current_password: password.value, code: code.value };
                    password.value = ''; code.value = '';
                    await request('/api/v1/security/mfa/disable', 'POST', proof);
                    if (active()) location.assign('/login');
                }, current, true);
            } else {
                const enrollmentPanel = el('div'); auth.append(enrollmentPanel);
                button(auth, 'Set up authenticator', async () => {
                    const proof = { current_password: password.value }; password.value = '';
                    const enrollment = await request('/api/v1/security/mfa/enroll', 'POST', proof);
                    if (!active()) return;
                    enrollmentPanel.replaceChildren(el('p', 'Enter this secret into your authenticator app: ' + enrollment.secret), el('p', enrollment.uri));
                    button(enrollmentPanel, 'Confirm authenticator', async () => {
                        const supplied = code.value; code.value = '';
                        const result = await request('/api/v1/security/mfa/confirm', 'POST', { code: supplied });
                        if (!active()) return;
                        auth.replaceChildren(el('h3', 'Save your recovery codes'), el('p', result.message), el('pre', result.recovery_codes.join('\n')));
                        const link = el('a', 'Sign in again'); link.href = '/login'; actions(auth).append(link);
                    }, current);
                }, current);
            }
            if (me.role !== 'administrator') return;
            const settings = await request('/api/v1/security/settings');
            if (!active()) return;
            const policy = card(root, 'Management security', 'Source networks apply to connecting IPs. Include your current address to preserve access. Changes apply immediately.');
            const idle = input(policy, 'Idle session timeout (seconds)', settings.idle_timeout_secs, 'number', 'End inactive management sessions after 60–28800 seconds. Background statistics polling does not extend sessions.'); idle.min = 60; idle.max = 28800;
            const allow = input(policy, 'Allowed source IPs/CIDRs (comma separated)', settings.source_allowlist.join(', '), 'text', 'Restrict management to these source addresses or networks. An empty list allows all sources. Forwarded client-IP headers are not trusted.');
            const proof = input(policy, 'Current password', '', 'password', 'Confirm your password to save management security policy immediately.');
            const mfaCode = input(policy, 'Authenticator or recovery code (if enabled)', '', 'text', 'Provide an unused authenticator or recovery code when MFA is enabled.');
            button(policy, 'Save security policy', async () => {
                const change = { settings: { idle_timeout_secs: Number(idle.value), source_allowlist: allow.value.split(',').map(value => value.trim()).filter(Boolean) }, current_password: proof.value, code: mfaCode.value || null };
                proof.value = ''; mfaCode.value = '';
                await request('/api/v1/security/settings', 'PUT', change);
                if (active()) feedback(policy, 'Security policy saved.');
            }, current);
            const tokens = card(root, 'API tokens', 'Tokens are shown once. Monitoring tokens read metrics independently of human sessions. Revocation applies immediately.');
            const list = el('div'); tokens.append(list);
            const name = input(tokens, 'Token name', '', 'text', 'Use a recognizable name for this integration. Token creation applies immediately.'); name.maxLength = 128;
            const scope = el('select');
            for (const value of ['monitoring', 'read', 'configure']) { const option = el('option', value); option.value = value; scope.append(option); }
            const label = el('label'); label.dataset.configHelp = 'Monitoring permits health and metric reads. Read permits nonsensitive configuration reads. Configure additionally permits configuration changes; account and security operations remain excluded.'; scope.setAttribute('aria-description', label.dataset.configHelp);
            label.append(el('span', 'Scope'), scope); tokens.append(label);
            const days = input(tokens, 'Lifetime (days)', 30, 'number', 'Expire this token automatically. Choose a lifetime from one day to one year.'); days.min = 1; days.max = 365;
            const secret = input(tokens, 'Current password', '', 'password', 'Confirm your password to create an API token immediately.');
            const otp = input(tokens, 'Authenticator or recovery code (if enabled)', '', 'text', 'Provide an unused authenticator or recovery code when MFA is enabled.');
            const displayed = el('div'); displayed.dataset.tokenSecret = ''; tokens.append(displayed);
            async function refresh() {
                const inventory = await request('/api/v1/security/tokens');
                if (!active()) return;
                list.replaceChildren();
                if (!inventory.length) list.append(el('p', 'No API tokens.'));
                for (const token of inventory) {
                    const row = el('div'); row.className = 'object-row'; row.append(el('span', token.name + ' · ' + token.scope + ' · Expires ' + new Date(token.expires * 1000).toLocaleString()));
                    button(row, 'Revoke', async () => { await request('/api/v1/security/tokens/' + encodeURIComponent(token.id), 'DELETE', {}); if (active()) await refresh(); }, current, true);
                    list.append(row);
                }
            }
            button(tokens, 'Create token', async () => {
                const change = { name: name.value, scope: scope.value, lifetime_secs: Number(days.value) * 86400, current_password: secret.value, code: otp.value || null };
                secret.value = ''; otp.value = '';
                const token = await request('/api/v1/security/tokens', 'POST', change);
                if (!active()) return;
                displayed.replaceChildren(el('p', 'Copy this token now. It will not be shown again.'), el('pre', token.token));
                await refresh();
            }, current);
            await refresh();
        } catch (error) { if (active()) feedback(root, error.message); }
    }
    request('/api/v1/auth/me').then(me => {
        document.body.dataset.accountRole = me.role;
        if (me.role !== 'administrator') {
            const configuration = document.getElementById('configuration');
            if (configuration) {
                const protect = () => {
                    for (const field of configuration.querySelectorAll('input,select,textarea')) field.disabled = true;
                    for (const control of configuration.querySelectorAll('button')) if (/^(Create|Delete|Clone|Save|Generate|Import|Validate|Preview|Clear)/.test(control.textContent.trim())) control.disabled = true;
                };
                protect(); new MutationObserver(protect).observe(configuration, { childList: true, subtree: true });
            }
        }
        const badge = document.getElementById('account-identity'); if (badge) badge.textContent = me.username + ' · ' + me.role.replaceAll('_', ' ');
    }).catch(() => {});
    window.addEventListener('riverlb:page', event => render(event.detail.page));
    render(document.querySelector('[data-page]:not([hidden])')?.dataset.page);
    let lastActivity = 0;
    for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, () => {
        if (Date.now() - lastActivity < 30000) return;
        lastActivity = Date.now(); request('/api/v1/auth/me').catch(() => {});
    }, { passive: true });
})();
