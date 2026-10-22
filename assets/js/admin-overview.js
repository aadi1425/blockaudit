/* BlockAudit — admin: overview */
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

  const chain = BA.getChain();
  const meta = BA.getMeta();
  const st = BA.statsFor(null);
  ui.$('#st-blocks').textContent = chain.length;
  ui.$('#st-approved').textContent = st.approved;
  ui.$('#st-rejected').textContent = st.rejected;
  const chainEl = ui.$('#st-chain');
  chainEl.textContent = s.integrity.valid ? 'VALID' : 'INVALID';
  chainEl.parentElement.classList.add(s.integrity.valid ? 'stat-green' : 'stat-red');

  // Alert for unauthorised attempts the admin has not seen yet
  const seen = BA.store.get('ba_admin_seen', 0);
  const fresh = chain.filter((b) => b.index > seen && b.status === 'REJECTED');
  if (fresh.length) {
    ui.alert('danger', `${fresh.length} unauthorised attempt${fresh.length > 1 ? 's' : ''} since your last visit. Latest: ${fresh[fresh.length - 1].requester} → ${fresh[fresh.length - 1].resource}`, 10000);
  }
  BA.store.set('ba_admin_seen', chain.length ? chain[chain.length - 1].index : 0);
  if (!s.integrity.valid) ui.alert('danger', `Chain integrity broken at block #${s.integrity.issues[0].index}.`, 10000);

  const rows = chain.filter((b) => b.index > 0).reverse().slice(0, 12);
  const wrap = ui.$('#activity');
  if (!rows.length) {
    wrap.append(el('p', { class: 'empty', text: 'No activity yet. Requests appear here as soon as users make them.' }));
    return;
  }
  wrap.append(el('table', {}, [
    el('thead', {}, [el('tr', {}, ['Block', 'Time', 'User', 'Resource', 'Result', 'Reason'].map((h) => el('th', { text: h })))]),
    el('tbody', {}, rows.map((b) => {
      const ok = b.status === 'APPROVED';
      const m = meta[b.index] || {};
      return el('tr', {}, [
        el('td', { class: 'mono', text: `#${b.index}` }),
        el('td', { text: ui.fmtTime(b.timestamp) }),
        el('td', { text: b.requester }),
        el('td', { text: b.resource }),
        el('td', {}, [el('span', { class: `badge badge-${ok ? 'approved' : 'rejected'}`, text: b.status })]),
        el('td', { class: 'wrap muted', text: ok ? '—' : (m.reason || '') }),
      ]);
    })),
  ]));
});
