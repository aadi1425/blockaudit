/* BlockAudit — admin: tamper test
 * Plays the attacker: edit a record, optionally re-mine the chain, then validate.
 * Shows the original and the edited record side by side. Reset restores the
 * untouched copy (ba_chain_clean).
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

  const FIELDS = ['requester', 'resource', 'status'];
  const blockSel = ui.$('#tp-block');
  const fieldSel = ui.$('#tp-field');
  const valueIn = ui.$('#tp-value');

  const clean = () => BA.store.get(BA.KEYS.clean, null);
  const selected = () => Number(blockSel.value);

  const fillBlocks = () => {
    const keep = blockSel.value;
    ui.clear(blockSel);
    BA.getChain().filter((b) => b.index > 0).forEach((b) => {
      blockSel.append(el('option', { value: String(b.index), text: `#${b.index} · ${b.requester} → ${b.resource} (${b.status})` }));
    });
    if (keep && blockSel.querySelector(`option[value="${CSS.escape(keep)}"]`)) blockSel.value = keep;
  };

  // Suggest a value so a demo needs only one click.
  const suggest = () => {
    const b = BA.getChain().find((x) => x.index === selected());
    if (!b) return;
    const f = fieldSel.value;
    valueIn.value = f === 'status' ? (b.status === 'APPROVED' ? 'REJECTED' : 'APPROVED')
      : f === 'requester' ? 'Hacker' : 'Nothing to see here';
  };

  const checkChip = (ok, label) =>
    el('span', { class: `cx-check ${ok ? 'ok' : 'fail'}` }, [ok ? '✓ ' : '✗ ', label]);

  const hashRow = (label, value, cls) =>
    el('div', { class: 'cx-row lg-row' }, [
      el('span', { class: 'cx-key', text: label }),
      el('span', { class: `cx-hash mono ${cls || ''}`, text: String(value) }),
    ]);

  // Original vs now, for the selected block.
  const compare = (orig, now) => {
    const rows = [...FIELDS, 'nonce', 'previousHash', 'hash'].map((f) => {
      const a = orig ? String(orig[f]) : '—';
      const b = String(now[f]);
      const changed = orig && a !== b;
      return el('tr', {}, [
        el('th', { scope: 'row', text: f }),
        el('td', { class: `mono wrap tp-cell${changed ? ' tp-old' : ''}`, text: a }),
        el('td', { class: `mono wrap tp-cell${changed ? ' tp-new' : ''}`, text: b }),
      ]);
    });
    return el('div', { class: 'table-wrap' }, [el('table', { class: 'tp-compare' }, [
      el('thead', {}, [el('tr', {}, [el('th', { text: 'Field' }), el('th', { text: 'Original (untouched copy)' }), el('th', { text: 'Now (live chain)' })])]),
      el('tbody', {}, rows),
    ])]);
  };

  const render = async () => {
    const chain = BA.getChain();
    const result = await BA.validate(chain);
    ui.setSeal(result, true);
    const cc = clean();
    const differs = !!cc && JSON.stringify(cc) !== JSON.stringify(chain);

    const box = ui.$('#tp-status-box');
    box.classList.toggle('stat-green', result.valid);
    box.classList.toggle('stat-red', !result.valid);
    ui.$('#tp-status').textContent = result.valid ? 'VALID' : 'BROKEN';
    ui.$('#tp-issues').textContent = result.issues.length;
    ui.$('#tp-edited').textContent = differs ? 'Yes' : 'No';

    const sum = ui.$('#tp-summary');
    if (!result.valid) {
      const first = result.issues[0];
      const why = { hash: 'its stored hash no longer matches its data', pow: 'its hash has no Proof of Work',
        link: 'it no longer points to the block before it', sig: 'its digital signature does not match the record' }[first.type];
      sum.className = 'cx-summary bad';
      sum.textContent = `CAUGHT. Block #${first.index} failed because ${why}. ${result.issues.length} problem${result.issues.length > 1 ? 's' : ''} found in total.`;
    } else if (differs) {
      sum.className = 'cx-summary warn';
      sum.textContent = 'NOT CAUGHT. The chain differs from the untouched copy but every check passes. The edited block was made before signatures, so re-mining hid the change. Signed blocks cannot be hidden this way; only more independent nodes (Part 3) stop it fully.';
    } else {
      sum.className = 'cx-summary ok';
      sum.textContent = `Chain is clean: all ${chain.length} blocks match the untouched copy and pass every check.`;
    }

    const i = selected();
    const now = chain.find((b) => b.index === i);
    const detail = ui.clear(ui.$('#tp-detail'));
    if (!now) return;
    const pos = chain.indexOf(now);
    const c = await BA.checkBlock(now, chain[pos - 1]);
    const orig = cc ? cc.find((b) => b.index === i) : null;
    detail.append(
      el('h2', { text: `Block #${i}` }),
      compare(orig, now),
      hashRow('Stored hash', now.hash, c.hashOk ? 'good' : 'bad'),
      hashRow('Recomputed hash', c.actual, c.hashOk ? 'good' : 'bad'),
      el('div', { class: 'cx-checks' }, [
        checkChip(c.hashOk, 'Hash matches data'),
        checkChip(c.powOk, `Starts with ${BA.PREFIX}`),
        checkChip(c.linkOk, `Linked to #${i - 1}`),
        ui.sigChip(c, true),
      ]),
      !c.sigOk ? el('div', { class: 'cx-diff' }, [el('p', { text: ui.sigProblem(c) })]) : null,
    );
  };

  const busy = (on) => ['#tp-apply', '#tp-remine', '#tp-validate', '#tp-reset'].forEach((id) => { ui.$(id).disabled = on; });

  ui.$('#tp-apply').addEventListener('click', async () => {
    const value = valueIn.value.trim().slice(0, 40);
    const field = fieldSel.value;
    if (!FIELDS.includes(field) || !value) { ui.alert('warn', 'Type a new value first.', 3000); return; }
    const chain = BA.getChain();
    const b = chain.find((x) => x.index === selected());
    if (!b) return;
    const before = b[field];
    b[field] = value;
    BA.store.set(BA.KEYS.chain, chain);
    BA.log('warn', `TAMPER TEST: admin changed block #${b.index} ${field} from "${before}" to "${value}"`);
    fillBlocks();
    await render();
    ui.alert('warn', `Block #${b.index} edited. Press Validate, or re-mine first to try to hide it.`, 4000);
  });

  ui.$('#tp-remine').addEventListener('click', async () => {
    const chain = BA.getChain();
    const start = chain.findIndex((x) => x.index === selected());
    if (start < 1) return;
    busy(true);
    ui.overlay.show('Attacker re-mining', `Re-mining block #${chain[start].index} and every block after it`);
    const t0 = performance.now();
    for (let j = start; j < chain.length; j++) {
      chain[j].previousHash = chain[j - 1].hash;
      ui.$('#mining-sub').textContent = `Re-mining block #${chain[j].index} of #${chain[chain.length - 1].index}`;
      await BA.mine(chain[j], (n) => ui.overlay.nonce(n));
    }
    BA.store.set(BA.KEYS.chain, chain);
    ui.overlay.hide();
    const sec = ((performance.now() - t0) / 1000).toFixed(1);
    BA.log('warn', `TAMPER TEST: admin re-mined blocks #${chain[start].index}–#${chain[chain.length - 1].index} in ${sec}s`);
    busy(false);
    fillBlocks();
    await render();
    ui.alert('info', `Re-mined ${chain.length - start} block${chain.length - start > 1 ? 's' : ''} in ${sec} s. Now press Validate.`, 4000);
  });

  ui.$('#tp-validate').addEventListener('click', async () => {
    const r = await BA.validate();
    BA.log(r.valid ? 'info' : 'error', r.valid
      ? 'TAMPER TEST: validation passed'
      : `INTEGRITY: tamper test validation failed, first issue at block #${r.issues[0].index} (${r.issues[0].type})`);
    await render();
  });

  ui.$('#tp-reset').addEventListener('click', async () => {
    const cc = clean();
    if (!cc || !cc.length) { ui.alert('danger', 'No untouched copy is saved in this browser, so the chain cannot be reset here.', 5000); return; }
    BA.store.set(BA.KEYS.chain, cc);
    BA.log('info', `TAMPER TEST: chain reset from the untouched copy (${cc.length} blocks)`);
    fillBlocks();
    await render();
    ui.alert('success', 'Chain restored from the untouched copy.', 3000);
  });

  blockSel.addEventListener('change', () => { suggest(); render(); });
  fieldSel.addEventListener('change', suggest);

  ui.$('#tp-clean').textContent = clean() ? 'Saved' : 'Missing';
  fillBlocks();
  // Start on the newest signed block if there is one, so the first demo shows a signature catch.
  const chain = BA.getChain();
  const signed = chain.filter((b) => b.signature !== undefined);
  if (signed.length) blockSel.value = String(signed[signed.length - 1].index);
  else if (chain.length > 1) blockSel.value = String(chain[1].index);
  suggest();
  await render();
});
