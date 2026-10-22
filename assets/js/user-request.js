/* BlockAudit — user: request access */
'use strict';
document.addEventListener('DOMContentLoaded', async () => {
  const BA = window.BA;
  const { ui } = BA;
  const el = ui.el;

  const s = await BA.auth.guard('user');
  if (!s) return;
  ui.topbar(s, ui.userNav);
  ui.setSeal(s.integrity, false);
  ui.integrityNotice(s.integrity);
  BA.auth.reveal();
  ui.showFlash();

  ui.$('#greeting').textContent = `Welcome, ${s.user}`;
  let selected = null;

  function refresh() {
    const st = BA.statsFor(s.user);
    ui.$('#st-total').textContent = st.total;
    ui.$('#st-approved').textContent = st.approved;
    ui.$('#st-rejected').textContent = st.rejected;
    ui.clear(ui.$('#recent')).append(ui.userHistory(s.user, 5));
  }

  // Resource cards
  const grid = ui.$('#resources');
  BA.RESOURCES.forEach((r) => {
    const card = el('button', { class: 'resource', type: 'button', 'aria-pressed': 'false', 'data-id': r.id }, [
      el('span', { class: 'resource-icon', 'aria-hidden': 'true', text: r.icon }),
      el('span', { class: 'resource-name', text: r.name }),
      el('span', { class: 'resource-desc', text: r.desc }),
    ]);
    card.addEventListener('click', () => {
      grid.querySelectorAll('.resource').forEach((c) => c.setAttribute('aria-pressed', 'false'));
      card.setAttribute('aria-pressed', 'true');
      selected = r;
      ui.$('#submit').disabled = false;
      ui.$('#selected-note').textContent = `Selected: ${r.name}`;
    });
    grid.append(card);
  });

  ui.$('#submit').addEventListener('click', async () => {
    if (!selected) return;
    const r = selected;
    const btn = ui.$('#submit');
    btn.disabled = true;

    // 1. Consensus
    const c = BA.consensus(s.user, r.id);
    const status = c.approved ? 'APPROVED' : 'REJECTED';
    BA.log('info', `Request: ${s.user} → ${r.name}`);
    c.votes.forEach((v) => BA.log(
      v.faulty ? 'warn' : 'info',
      `  ${v.node} (${v.role}) voted ${v.vote ? 'YES' : 'NO'}${v.faulty ? ' [random fault triggered]' : ''}`
    ));
    BA.log(c.approved ? 'success' : 'error', `  Consensus ${c.yes}/3 → ${status}`);

    // 2. Sign it with the user's key, then mine it, approved or not
    ui.overlay.show('Proof of Work', 'Signing your request and recording it on the audit chain');
    const reason = c.approved ? '' : BA.denyReason(s.user, r.id);
    const block = await BA.addBlock(s.user, r.name, status, {
      kind: 'resource', resourceId: r.id, votes: c.votes, yes: c.yes,
      faultTriggered: c.faultTriggered, deviated: c.deviated, reason,
    }, (n) => ui.overlay.nonce(n), BA.auth.signRecord);
    ui.overlay.hide();
    if (!c.approved) BA.log('error', `SECURITY: unauthorised request by ${s.user} for ${r.name} recorded in block #${block.index}`);

    // 3. Result (no hashes, no votes)
    const granted = c.approved;
    const done = el('button', { class: 'btn btn-block', type: 'button', text: 'Done' });
    const close = ui.modal([
      el('div', { class: granted ? 'result-granted' : 'result-denied' }, [
        el('div', { class: 'result-icon', 'aria-hidden': 'true', text: granted ? '✅' : '🚫' }),
        el('h2', { class: 'result-title', text: granted ? 'Access granted' : 'Access denied' }),
        el('dl', { class: 'facts' }, [
          el('dt', { text: 'Resource' }), el('dd', { text: r.name }),
          el('dt', { text: 'Status' }), el('dd', { text: granted ? 'Approved' : 'Rejected' }),
          el('dt', { text: 'Block' }), el('dd', { class: 'mono', text: `#${block.index}` }),
          el('dt', { text: 'Time' }), el('dd', { text: ui.fmtTime(block.timestamp) }),
          el('dt', { text: 'Consensus' }), el('dd', { text: `${granted ? 'Approved' : 'Rejected'} by majority vote of 3 nodes` }),
          el('dt', { text: 'Signature' }), el('dd', { text: block.signature ? 'Signed with your private key (ECDSA)' : 'Not signed' }),
        ]),
        granted ? null : el('div', { class: 'why' }, [el('strong', { text: 'Why was I denied?' }), reason]),
        done,
      ]),
    ], refresh);
    done.addEventListener('click', close);

    // reset picker
    grid.querySelectorAll('.resource').forEach((x) => x.setAttribute('aria-pressed', 'false'));
    selected = null;
    ui.$('#selected-note').textContent = 'No resource selected';
    refresh();
  });

  refresh();
});
