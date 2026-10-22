/* BlockAudit — admin: chain explorer
 * Lists every block with its full hash, previous hash and nonce,
 * recomputes each SHA-256 hash live and shows which check failed.
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

  let checked = []; // BA.checkBlock results plus m (meta)

  // Recompute every hash, check every link and signature, one block at a time.
  const check = async () => {
    const chain = BA.getChain();
    const meta = BA.getMeta();
    const out = [];
    for (let i = 0; i < chain.length; i++) {
      const c = await BA.checkBlock(chain[i], chain[i - 1]);
      c.m = meta[c.b.index] || {};
      out.push(c);
    }
    return out;
  };

  const copy = async (text, what) => {
    try {
      await navigator.clipboard.writeText(text);
      ui.alert('success', `${what} copied.`, 2500);
    } catch (e) {
      ui.alert('warn', 'The browser blocked copying. Select the text and copy it by hand.', 4000);
    }
  };

  const hashRow = (label, value, cls) =>
    el('div', { class: 'cx-row' }, [
      el('span', { class: 'cx-key', text: label }),
      el('span', { class: `cx-hash mono ${cls || ''}`, text: value }),
      el('button', {
        class: 'btn btn-ghost btn-sm cx-copy', type: 'button', text: 'Copy',
        'aria-label': `Copy ${label}`, onclick: () => copy(value, label),
      }),
    ]);

  const checkChip = (ok, label) =>
    el('span', { class: `cx-check ${ok ? 'ok' : 'fail'}` }, [ok ? '✓ ' : '✗ ', label]);

  const votesView = (m) => {
    if (!Array.isArray(m.votes) || !m.votes.length) {
      const why = m.kind === 'login' ? 'Failed login, rejected before consensus.'
        : m.kind === 'page' ? 'Admin page attempt, rejected before consensus.'
        : 'No consensus round for this block.';
      return el('p', { class: 'muted cx-novote', text: why });
    }
    return el('div', { class: 'cx-votes' }, [
      ...m.votes.map((v) => el('span', { class: `cx-vote ${v.vote ? 'yes' : 'no'}${v.faulty ? ' faulty' : ''}` }, [
        `${v.node}: ${v.vote ? 'YES' : 'NO'}`,
        v.faulty ? el('span', { class: 'cx-fault', text: ' · random vote' }) : null,
      ])),
      el('span', { class: 'muted', text: `${m.yes}/3 YES` }),
    ]);
  };

  const card = (c) => {
    const { b, m } = c;
    const ok = b.status === 'APPROVED';
    const genesis = b.index === 0 && b.requester === 'SYSTEM';
    const problems = [];
    if (!c.hashOk) problems.push(el('div', { class: 'cx-diff' }, [
      el('p', { text: 'The block data was changed after mining. Its stored hash no longer matches.' }),
      hashRow('Stored hash', b.hash, 'bad'),
      hashRow('Recomputed hash', c.actual, 'good'),
    ]));
    if (!c.linkOk) problems.push(el('div', { class: 'cx-diff' }, [
      el('p', { text: genesis ? 'Genesis previous hash is not all zeros.' : `This block does not point to block #${b.index - 1}.` }),
      hashRow('Stored previous hash', b.previousHash, 'bad'),
      hashRow(genesis ? 'Expected' : `Hash of #${b.index - 1}`, c.parent, 'good'),
    ]));
    if (c.hashOk && !c.powOk) problems.push(el('div', { class: 'cx-diff' }, [
      el('p', { text: `The hash does not start with ${BA.PREFIX}, so no Proof of Work was done.` }),
    ]));
    if (!c.sigOk) problems.push(el('div', { class: 'cx-diff' }, [el('p', { text: ui.sigProblem(c) })]));

    return el('article', { class: `cx-card${c.ok ? '' : ' tampered'}`, 'aria-label': `Block ${b.index}` }, [
      el('header', { class: 'cx-head' }, [
        el('span', { class: 'cx-index mono', text: `#${b.index}` }),
        genesis ? el('span', { class: 'badge badge-genesis', text: 'GENESIS' })
          : el('span', { class: `badge badge-${ok ? 'approved' : 'rejected'}`, text: b.status }),
        el('span', { class: `badge ${c.ok ? 'badge-valid' : 'badge-tampered'}`, text: c.ok ? 'VALID' : 'TAMPERED' }),
        el('span', { class: 'cx-time muted', text: ui.fmtTime(b.timestamp) }),
      ]),
      el('dl', { class: 'cx-facts' }, [
        el('dt', { text: 'Requester' }), el('dd', { text: String(b.requester) }),
        el('dt', { text: 'Resource' }), el('dd', { text: String(b.resource) }),
        el('dt', { text: 'Nonce' }), el('dd', { class: 'mono', text: String(b.nonce) }),
        !ok && m.reason ? el('dt', { text: 'Reason' }) : null,
        !ok && m.reason ? el('dd', { text: m.reason }) : null,
      ]),
      hashRow('Hash', String(b.hash)),
      hashRow('Previous hash', String(b.previousHash)),
      b.signature !== undefined ? hashRow('Signature', String(b.signature)) : null,
      el('div', { class: 'cx-checks' }, [
        checkChip(c.hashOk, 'Hash matches data'),
        checkChip(c.powOk, `Starts with ${BA.PREFIX}`),
        checkChip(c.linkOk, genesis ? 'Genesis link' : `Linked to #${b.index - 1}`),
        ui.sigChip(c, true),
      ]),
      genesis ? null : votesView(m),
      ...problems,
    ]);
  };

  const render = () => {
    const filter = ui.$('#cx-filter').value;
    const q = ui.$('#cx-search').value.trim().toLowerCase();
    const order = ui.$('#cx-order').value;
    let rows = checked.filter((c) => {
      if (filter === 'bad' && c.ok) return false;
      if ((filter === 'APPROVED' || filter === 'REJECTED') && c.b.status !== filter) return false;
      if (q && !`${c.b.requester} ${c.b.resource}`.toLowerCase().includes(q)) return false;
      return true;
    });
    if (order === 'desc') rows = rows.slice().reverse();
    ui.$('#cx-count').textContent = `Showing ${rows.length} of ${checked.length} blocks`;
    const list = ui.clear(ui.$('#cx-list'));
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
    const btn = ui.$('#recheck');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    checked = await check();
    const bad = checked.filter((c) => !c.ok);
    const result = {
      valid: !bad.length && checked.length > 0,
      issues: bad.map((c) => ({ index: c.b.index })),
      length: checked.length,
    };
    ui.setSeal(result, true);

    ui.$('#cx-blocks').textContent = checked.length;
    ui.$('#cx-diff').textContent = BA.PREFIX;
    ui.$('#cx-checked').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const box = ui.$('#cx-status-box');
    box.classList.toggle('stat-green', result.valid);
    box.classList.toggle('stat-red', !result.valid);
    ui.$('#cx-status').textContent = result.valid ? 'VALID' : 'BROKEN';

    const sum = ui.clear(ui.$('#cx-summary'));
    sum.className = `cx-summary ${result.valid ? 'ok' : 'bad'}`;
    const signed = checked.filter((c) => c.sig === 'signed').length;
    sum.textContent = result.valid
      ? `All ${checked.length} hashes recomputed with SHA-256. Every block matches its data and points to the one before it. ${signed} signature${signed === 1 ? '' : 's'} verified.`
      : `${bad.length} block${bad.length > 1 ? 's' : ''} failed: #${bad.map((c) => c.b.index).join(', #')}. The first break is at block #${bad[0].b.index}.`;

    render();
    btn.disabled = false;
    btn.textContent = 'Re-check chain';
  };

  ui.$('#recheck').addEventListener('click', () => {
    BA.log('info', 'Admin re-checked the chain from the explorer');
    run();
  });
  // CSV export of the full audit log (admin only, this page is guarded).
  ui.$('#export-csv').addEventListener('click', () => {
    const rows = [['Block', 'Time (UTC)', 'Requester', 'Resource', 'Result', 'Reason', 'Node votes YES',
      'Random vote', 'Signature check', 'Chain check', 'Nonce', 'Hash', 'Previous hash', 'Signature']];
    checked.forEach((c) => {
      const { b, m } = c;
      rows.push([b.index, b.timestamp, b.requester, b.resource, b.status, m.reason || '',
        Array.isArray(m.votes) ? `${m.yes}/3` : '', m.faultTriggered ? 'yes' : '', BA.SIG_LABEL[c.sig],
        c.ok ? 'VALID' : 'TAMPERED', b.nonce, b.hash, b.previousHash, b.signature || '']);
    });
    const day = new Date().toISOString().slice(0, 10);
    ui.downloadCsv(`blockaudit-audit-log-${day}.csv`, rows);
    BA.log('info', `Admin exported the audit log as CSV (${checked.length} blocks)`);
    ui.alert('success', `Audit log exported: ${checked.length} blocks.`, 3000);
  });

  ['#cx-filter', '#cx-order'].forEach((id) => ui.$(id).addEventListener('change', render));
  ui.$('#cx-search').addEventListener('input', render);

  // Live: when another tab mines or edits the chain, check again.
  let wait;
  window.addEventListener('storage', (e) => {
    if (e.key !== BA.KEYS.chain && e.key !== BA.KEYS.meta && e.key !== null) return;
    clearTimeout(wait);
    wait = setTimeout(run, 300);
  });

  await run();
});
