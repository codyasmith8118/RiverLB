document.getElementById('login').onsubmit = async event => {
    event.preventDefault();
    const form = event.currentTarget, button = form.querySelector('button');
    button.disabled = true;
    try {
        const response = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-RiverLB-Request': 'configure' }, body: JSON.stringify({ username: form.elements.username.value, password: form.elements.password.value, code: form.elements.code.value || null }) });
        const result = await response.json();
        if (!response.ok) throw Error(result.error || 'Sign in failed');
        window.location.assign('/');
    } catch (error) { document.getElementById('login-error').textContent = error.message; }
    finally { form.elements.password.value = ''; form.elements.code.value = ''; button.disabled = false; }
};
