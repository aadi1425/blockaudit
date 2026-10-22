/* BlockAudit — user: public ledger
 * Every user can see and verify every block's hashes and links.
 * Names and resources are shown only on the user's own blocks.
 * Votes stay admin-only.
 */
'use strict';
document.addEventListener('DOMContentLoaded', async () => {
  const BA = window.BA;
  const { ui } = BA;
  const el = ui.el;

  const s = await BA.auth.guard('user');
  if (!s) return;
  ui.topbar(s, ui.userNav);
  ui.setSeal(s.integrity, false);
  BA.auth.reveal();
  ui.showFlash();

  let checked = []; // BA.checkBlock results

  // Recompute every hash and verify every signature in this browser, block by block.
  const check = async () => {
    const chain = BA.getChain();
    const out = [];
    for (let i = 0; i < chain.length; i++) out.push(await BA.checkBlock(chain[i], chain[i - 1]));
    return out;
  };

  const hashRow = (label, value, cls) =>
    el('div', { class: 'cx-row lg-row' }, [
      el('span', { class: 'cx-key', text: label }),
      el('span', { class: `cx-hash mono ${cls || ''}`, text: String(value) }),
    ]);

  const checkChip = (ok, label) =>
    el('span', { class: `cx-check ${ok ? 'ok' : 'fail'}` }, [ok ? '✓ ' : '✗ ', label]);

  const card = (c) => {
    const { b } = c;
    const genesis = b.index === 0 && b.requester === 'SYSTEM';
    const mine = b.requester === s.user;
    const ok = b.status === 'APPROVED';
    const reason = mine && !ok ? (BA.getMeta()[b.index] || {}).reason : null;

    return el('article', { class: `cx-card${c.ok ? '' : ' tampered'}${mine ? ' lg-mine' : ''}`, 'aria-label': `Block ${b.index}` }, [
      el('header', { class: 'cx-head' }, [
        el('span', { class: 'cx-index mono', text: `#${b.index}` }),
        genesis ? el('span', { class: 'badge badge-genesis', text: 'GENESIS' })
          : el('span', { class: `badge badge-${ok ? 'approved' : 'rejected'}`, text: ok ? 'Granted' : 'Denied' }),
        el('span', { class: `badge ${c.ok ? 'badge-valid' : 'badge-tampered'}`, text: c.ok ? 'VALID' : 'TAMPERED' }),
        mine ? el('span', { class: 'badge badge-you', text: 'YOU' }) : null,
        el('span', { class: 'cx-time muted', text: ui.fmtTime(b.timestamp) }),
      ]),
      el('dl', { class: 'cx-facts' }, [
        el('dt', { text: 'Requester' }),
        el('dd', { class: mine || genesis ? '' : 'lg-hidden', text: genesis ? 'SYSTEM' : mine ? String(b.requester) : 'Another user' }),
        el('dt', { text: 'Resource' }),
        el('dd', { class: mine || genesis ? '' : 'lg-hidden', text: genesis ? 'GENESIS' : mine ? String(b.resource) : 'Hidden resource' }),
        el('dt', { text: 'Nonce' }), el('dd', { class: 'mono', text: String(b.nonce) }),
        reason ? el('dt', { text: 'Reason' }) : null,
        reason ? el('dd', { text: reason }) : null,
      ]),
      hashRow('Hash', b.hash),
      hashRow('Previous hash', b.previousHash),
      el('div', { class: 'cx-checks' }, [
        checkChip(c.hashOk, 'Hash matches data'),
        checkChip(c.powOk, `Starts with ${BA.PREFIX}`),
        checkChip(c.linkOk, genesis ? 'Genesis link' : `Linked to #${b.index - 1}`),
        ui.sigChip(c, mine),
      ]),
      !c.sigOk ? el('div', { class: 'cx-diff' }, [el('p', { text: ui.sigProblem(c) })]) : null,
      !c.hashOk ? el('div', { class: 'cx-diff' }, [
        el('p', { text: 'This block was changed after it was mined. The hash your browser just computed does not match the one stored.' }),
        hashRow('Stored hash', b.hash, 'bad'),
        hashRow('Your browser computed', c.actual, 'good'),
      ]) : null,
      !c.linkOk ? el('div', { class: 'cx-diff' }, [
        el('p', { text: genesis ? 'Genesis previous hash is not all zeros.' : `This block does not point to block #${b.index - 1}.` }),
      ]) : null,
    ]);
  };

  const render = () => {
    const filter = ui.$('#lg-filter').value;
    let rows = checked.filter((c) =>
      filter === 'mine' ? c.b.requester === s.user : filter === 'bad' ? !c.ok : true);
    if (ui.$('#lg-order').value === 'desc') rows = rows.slice().reverse();
    ui.$('#lg-count').textContent = `Showing ${rows.length} of ${checked.length} blocks`;
    const list = ui.clear(ui.$('#lg-list'));
    if (!rows.length) {
      list.append(el('p', { class: 'empty', text: 'No blocks match this filter.' }));
      return;
    }
    rows.forEach((c, i) => {
      if (i > 0) list.append(el('div', { class: 'cx-link', 'aria-hidden': 'true', text: '⛓' }));
      list.append(card(c));
    });
  };

  const run = async () => {
    const btn = ui.$('#verify');
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    checked = await check();
    const bad = checked.filter((c) => !c.ok);
    const valid = !bad.length && checked.length > 0;
    ui.setSeal({ valid, issues: bad.map((c) => ({ index: c.b.index })), length: checked.length }, false);

    ui.$('#lg-blocks').textContent = checked.length;
    ui.$('#lg-mine').textContent = checked.filter((c) => c.b.requester === s.user).length;
    ui.$('#lg-checked').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const box = ui.$('#lg-status-box');
    box.classList.toggle('stat-green', valid);
    box.classList.toggle('stat-red', !valid);
    ui.$('#lg-status').textContent = valid ? 'VALID' : 'BROKEN';

    const sum = ui.$('#lg-summary');
    sum.className = `cx-summary ${valid ? 'ok' : 'bad'}`;
    sum.textContent = valid
      ? `Your browser recomputed all ${checked.length} SHA-256 hashes and checked every signature. Every block matches its data and points to the one before it. Nobody has edited the ledger.`
      : `Your browser found ${bad.length} changed block${bad.length > 1 ? 's' : ''}: #${bad.map((c) => c.b.index).join(', #')}. The administrator has been alerted.`;

    render();
    btn.disabled = false;
    btn.textContent = 'Verify chain';
    return valid;
  };

  ui.$('#verify').addEventListener('click', async () => {
    const valid = await run();
    BA.log(valid ? 'info' : 'error', `${s.user} verified the public ledger: ${valid ? 'VALID' : 'TAMPERING FOUND'}`);
  });
  ['#lg-filter', '#lg-order'].forEach((id) => ui.$(id).addEventListener('change', render));

  // Live: when another tab mines or edits the chain, verify again.
  let wait;
  window.addEventListener('storage', (e) => {
    if (e.key !== BA.KEYS.chain && e.key !== null) return;
    clearTimeout(wait);
    wait = setTimeout(run, 300);
  });

  await run();
});
