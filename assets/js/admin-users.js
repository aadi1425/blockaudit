/* BlockAudit — admin: all users
 * One row per account: role, access list, requests, granted, denied,
 * failed logins, admin-page attempts, last activity and public key.
 */
'use strict';
document.addEventListener('DOMContentLoaded', async () => {
  const BA = window.BA;
  const { ui } = BA;
  const el = ui.el;

  const s = await BA.auth.guard('admin');
  if (!s) return;
  ui.topbar(s, ui.adminNav);
  ui.setSeal(s.integrity, true);
  BA.auth.reveal();
  ui.showFlash();

  const render = () => {
    const rows = BA.userSummary();
    const wrap = ui.clear(ui.$('#us-table'));
    wrap.append(el('table', {}, [
      el('thead', {}, [el('tr', {}, ['User', 'Role', 'Cleared for', 'Requests', 'Granted', 'Denied',
        'Failed logins', 'Admin page attempts', 'Last activity', 'Public key (x)'].map((h) => el('th', { text: h })))]),
      el('tbody', {}, rows.map((u) => el('tr', {}, [
        el('td', {}, [el('strong', { text: u.user })]),
        el('td', {}, [el('span', { class: `role role-${u.role}`, text: u.role.toUpperCase() })]),
        el('td', { class: 'wrap', text: u.role === 'admin' ? 'Monitors only, cannot request' : (u.cleared.join(', ') || 'Nothing') }),
        el('td', { class: 'mono', text: String(u.requests) }),
        el('td', { class: 'mono us-good', text: String(u.granted) }),
        el('td', { class: 'mono us-bad', text: String(u.denied) }),
        el('td', { class: 'mono', text: String(u.failedLogins) }),
        el('td', { class: 'mono', text: String(u.pageAttempts) }),
        el('td', { text: u.last ? ui.fmtTime(u.last) : '—' }),
        el('td', { class: 'mono muted', title: u.pubX || '', text: u.pubX ? `${u.pubX.slice(0, 16)}…` : 'No signing key' }),
      ]))),
    ]));

    const unknown = BA.unknownLogins();
    const uw = ui.clear(ui.$('#us-unknown'));
    if (!unknown.length) {
      uw.append(el('p', { class: 'empty', text: 'No sign-in attempts with usernames that do not exist.' }));
      return;
    }
    uw.append(el('table', {}, [
      el('thead', {}, [el('tr', {}, ['Username typed', 'Attempts', 'Last attempt'].map((h) => el('th', { text: h })))]),
      el('tbody', {}, unknown.map((u) => el('tr', {}, [
        el('td', { class: 'mono', text: u.name }),
        el('td', { class: 'mono', text: String(u.count) }),
        el('td', { text: ui.fmtTime(u.last) }),
      ]))),
    ]));
  };

  window.addEventListener('storage', (e) => {
    if (e.key === BA.KEYS.chain || e.key === null) render();
  });
  render();
});
