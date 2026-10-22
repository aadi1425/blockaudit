/* BlockAudit — login page */
'use strict';
document.addEventListener('DOMContentLoaded', async () => {
  const { ui, auth } = window.BA;
  if (window.top !== window.self) { window.top.location = window.self.location; return; }

  const form = ui.$('#login-form');
  const btn = ui.$('#login-btn');
  const err = ui.$('#login-error');
  btn.disabled = true;

  ui.overlay.show('Proof of Work', 'Preparing the audit chain');
  await window.BA.init(); // mines the genesis block on first visit
  ui.overlay.hide();
  btn.disabled = false;
  ui.showFlash();

  // Already signed in? Go straight to the right dashboard.
  const s = await auth.session();
  if (s && !s.invalid) {
    location.replace(s.role === 'admin' ? 'admin/overview.html' : 'user/request.html');
    return;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Checking…';

    const res = await auth.login(ui.$('#username').value, ui.$('#password').value, (state) => {
      if (state === true) ui.overlay.show('Recording attempt', 'Mining the failed sign-in into the chain');
      else if (state === false) ui.overlay.hide();
      else ui.overlay.nonce(state);
    });

    if (res.ok) {
      location.replace(res.role === 'admin' ? 'admin/overview.html' : 'user/request.html');
      return;
    }
    ui.$('#password').value = '';
    err.textContent = res.reason;
    btn.disabled = false;
    btn.textContent = 'Sign in';
    ui.$('#password').focus();
  });
});
