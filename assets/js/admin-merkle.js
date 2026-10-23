/* BlockAudit — admin: Merkle tree
 * Draws BA.merkle() as an SVG tree with a line from every node to its parent.
 * Nodes that differ from the untouched copy (ba_chain_clean) are red.
 * Click a record to see its Merkle proof: the sibling hashes that lead to the root.
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

  // Same pattern as ui.el, for SVG elements.
  const NS = 'http://www.w3.org/2000/svg';
  const svgEl = (tag, attrs, children) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const c of [].concat(children || [])) if (c) n.append(c);
    return n;
  };

  const SIZE = {
    side: { leafW: 236, nodeW: 112, h: 38, gap: 30, rowH: 46 },
    top: { leafW: 148, nodeW: 112, h: 38, colW: 158, rowH: 84 },
  };
  let layout = 'side';
  let data = null;   // { live, ref, blocks }
  let picked = null; // leaf position of the record whose proof is shown

  const short = (h) => `${h.slice(0, 10)}…`;
  const cut = (t, n) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);

  // Where each node sits across the tree: leaves 0..L-1, a parent between its children.
  const positions = (levels) => {
    const pos = [levels[0].map((_, i) => i)];
    for (let k = 1; k < levels.length; k++) {
      pos.push(levels[k].map((_, j) => {
        const a = pos[k - 1][2 * j];
        const b = pos[k - 1][2 * j + 1];
        return b === undefined ? a : (a + b) / 2;
      }));
    }
    return pos;
  };

  // The nodes a proof for leaf i touches: its path to the root, and each sibling on the way.
  const proofSets = (levels, i) => {
    const path = new Set();
    const sib = new Set();
    let j = i;
    for (let k = 0; k < levels.length; k++) {
      path.add(`${k}:${j}`);
      if (k < levels.length - 1) sib.add(`${k}:${(j ^ 1) < levels[k].length ? j ^ 1 : j}`);
      j = Math.floor(j / 2);
    }
    return { path, sib };
  };

  const draw = () => {
    const wrap = ui.clear(ui.$('#mk-tree'));
    const { live, ref, blocks } = data;
    const L = live.levels;
    const S = SIZE[layout];
    const top = L.length - 1;
    const pos = positions(L);
    const sets = picked === null ? null : proofSets(L, picked);

    const box = (k, j) => {
      const w = k === 0 ? S.leafW : S.nodeW;
      if (layout === 'side') {
        const x = k === 0 ? 0 : S.leafW + S.gap + (k - 1) * (S.nodeW + S.gap);
        return { x, y: pos[k][j] * S.rowH, w, h: S.h };
      }
      return { x: pos[k][j] * S.colW + (S.colW - w) / 2, y: (top - k) * S.rowH, w, h: S.h };
    };
    const W = layout === 'side' ? S.leafW + top * (S.nodeW + S.gap) : L[0].length * S.colW;
    const H = layout === 'side' ? (L[0].length - 1) * S.rowH + S.h : top * S.rowH + S.h;
    const pad = 4;

    const edges = svgEl('g', { class: 'mk-edges' });
    const nodes = svgEl('g', {});
    let changed = 0;

    for (let k = 0; k < L.length; k++) {
      L[k].forEach((n, j) => {
        const key = `${k}:${j}`;
        const b = box(k, j);
        const other = ref && ref.levels[k] && ref.levels[k][j];
        const bad = !!ref && (!other || other.hash !== n.hash);
        if (bad) changed++;

        if (k < top) {
          const pj = Math.floor(j / 2);
          const p = box(k + 1, pj);
          const on = sets && sets.path.has(key) && sets.path.has(`${k + 1}:${pj}`);
          const d = layout === 'side'
            ? `M${b.x + b.w} ${b.y + b.h / 2}H${p.x - S.gap / 2}V${p.y + p.h / 2}H${p.x}`
            : `M${b.x + b.w / 2} ${b.y}V${p.y + p.h + (b.y - p.y - p.h) / 2}H${p.x + p.w / 2}V${p.y + p.h}`;
          edges.append(svgEl('path', { d, class: `mk-edge${bad ? ' bad' : ''}${on ? ' on' : ''}` }));
        }

        const kind = k === top ? 'root' : k === 0 ? 'leaf' : 'branch';
        const cls = ['mk-n', kind];
        if (bad) cls.push('bad');
        if (sets && sets.path.has(key)) cls.push('path');
        else if (sets && sets.sib.has(key)) cls.push('sib');
        if (n.duplicated) cls.push('dup');
        const g = svgEl('g', { class: cls.join(' '), transform: `translate(${b.x} ${b.y})` }, [
          svgEl('title', { text: `${kind === 'leaf' ? `Block #${n.index}: ${n.label}` : kind === 'root' ? 'Merkle root' : `Level ${k}`}\n${n.hash}` }),
          svgEl('rect', { width: b.w, height: b.h, rx: 6 }),
        ]);

        if (k === 0) {
          const blk = blocks[n.index] || {};
          const ok = blk.status === 'APPROVED';
          g.append(
            svgEl('text', { x: 10, y: 15, class: 'mk-t1', text: cut(`#${n.index} · ${blk.requester} → ${blk.resource}`, layout === 'side' ? 32 : 19) }),
            svgEl('text', { x: 10, y: 30 }, [
              svgEl('tspan', { class: 'mk-hash', text: short(n.hash) }),
              svgEl('tspan', { class: ok ? 'mk-ok' : 'mk-no', dx: 8, text: ok ? 'APPROVED' : 'REJECTED' }),
            ]),
          );
          g.setAttribute('tabindex', '0');
          g.setAttribute('role', 'button');
          g.setAttribute('aria-label', `Show the Merkle proof for block ${n.index}`);
          g.addEventListener('click', () => pick(j));
          g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(j); } });
        } else {
          g.append(
            svgEl('text', { x: 10, y: 15, class: 'mk-t1', text: k === top ? 'MERKLE ROOT' : `LEVEL ${k}${n.duplicated ? ' · COPY' : ''}` }),
            svgEl('text', { x: 10, y: 30, class: 'mk-hash', text: short(n.hash) }),
          );
        }
        nodes.append(g);
      });
    }

    wrap.append(svgEl('svg', {
      class: `mk-svg mk-${layout}`, width: W + pad * 2, height: H + pad * 2,
      viewBox: `${-pad} ${-pad} ${W + pad * 2} ${H + pad * 2}`,
      role: 'img', 'aria-label': `Merkle tree of ${L[0].length} records`,
    }, [edges, nodes]));
    const r = box(top, 0);
    return { changed, rootX: r.x + r.w / 2 + pad };
  };

  // Rebuilds the root from one leaf and its siblings, step by step.
  const showProof = async () => {
    const panel = ui.clear(ui.$('#mk-proof'));
    if (picked === null) {
      panel.append(el('p', { class: 'mk-proof-hint', text: 'Click any record in the tree to see its Merkle proof: the few hashes that prove it is part of the tree.' }));
      return;
    }
    const L = data.live.levels;
    const leaf = L[0][picked];
    const blk = data.blocks[leaf.index] || {};
    let h = leaf.hash;
    let j = picked;
    const steps = [];
    for (let k = 0; k < L.length - 1; k++) {
      const dup = (j ^ 1) >= L[k].length;
      const sib = L[k][dup ? j : j ^ 1];
      const left = j % 2 === 0;
      const next = await BA.sha256(left ? h + sib.hash : sib.hash + h);
      steps.push({ k, dup, side: left ? 'right' : 'left', sib: sib.hash, next });
      h = next;
      j = Math.floor(j / 2);
    }
    const ok = h === data.live.root;
    // Compare the leaf with the untouched copy: a changed record no longer proves the original root.
    const refLeaf = data.ref && data.ref.levels[0][picked];
    const changedLeaf = !!data.ref && (!refLeaf || refLeaf.hash !== leaf.hash);
    const close = el('button', { class: 'btn btn-ghost btn-sm', type: 'button', text: 'Close', onclick: () => pick(picked) });
    panel.append(
      el('div', { class: 'mk-proof-head' }, [
        el('div', {}, [
          el('h2', { text: `Merkle proof for block #${leaf.index}` }),
          el('p', { class: 'muted', text: `${blk.requester} → ${blk.resource} (${blk.status})` }),
        ]),
        close,
      ]),
      el('ol', { class: 'mk-steps' }, [
        el('li', {}, ['Leaf: SHA-256 of the record ', el('code', { class: 'mono', text: short(leaf.hash) })]),
        ...steps.map((st) => el('li', {}, [
          st.dup ? 'Joined with a copy of itself (odd number of nodes) '
            : `Joined with the sibling on the ${st.side} `,
          el('code', { class: 'mono mk-sib', text: short(st.sib) }),
          ' → ',
          el('code', { class: 'mono', text: short(st.next) }),
        ])),
      ]),
      el('p', { class: `mk-verdict ${ok ? 'ok' : 'bad'}`, text: ok
        ? `✓ The rebuilt root matches the current Merkle root. ${steps.length} sibling hashes were enough to prove this record is in the tree, without reading the other ${L[0].length - 1} records.`
        : '✗ The rebuilt root does not match the Merkle root.' }),
      changedLeaf ? el('p', { class: 'mk-verdict bad', text:
        `✗ This record was changed: its leaf hash differs from the untouched copy. The proof leads to a different root (${short(data.live.root)}) than the original (${short(data.ref.root)}), so anyone holding the original root would reject it.` }) : '',
    );
  };

  function pick(j) {
    picked = picked === j ? null : j;
    draw();
    showProof();
  }

  const render = async () => {
    const chain = BA.getChain();
    const live = await BA.merkle(chain);
    const cleanChain = BA.store.get(BA.KEYS.clean, null);
    const ref = cleanChain ? await BA.merkle(cleanChain) : null;
    const blocks = {};
    chain.forEach((b) => { blocks[b.index] = b; });

    if (!live.root) {
      ui.$('#mk-root').textContent = '—';
      ui.clear(ui.$('#mk-tree')).append(el('p', { class: 'empty', text: 'No records yet. The tree grows as users make requests.' }));
      ui.clear(ui.$('#mk-proof'));
      return;
    }
    data = { live, ref, blocks };
    if (picked !== null && picked >= live.levels[0].length) picked = null;
    const { changed, rootX } = draw();
    showProof();

    ui.$('#mk-leaves').textContent = live.levels[0].length;
    ui.$('#mk-levels').textContent = live.levels.length;
    ui.$('#mk-changed').textContent = ref ? changed : '—';
    ui.$('#mk-root').textContent = live.root;
    const match = ref ? ref.root === live.root : null;
    const box = ui.$('#mk-match-box');
    box.classList.toggle('stat-green', match === true);
    box.classList.toggle('stat-red', match === false);
    ui.$('#mk-match').textContent = match === null ? 'No copy' : match ? 'MATCH' : 'CHANGED';

    // Top-down trees are wide: start with the root in the middle of the view.
    const scroller = ui.$('#mk-tree');
    scroller.scrollLeft = layout === 'top' ? Math.max(0, rootX - scroller.clientWidth / 2) : 0;
  };

  document.querySelectorAll('.mk-seg button').forEach((btn) => btn.addEventListener('click', () => {
    layout = btn.dataset.layout;
    document.querySelectorAll('.mk-seg button').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
    render();
  }));
  ui.$('#mk-refresh').addEventListener('click', render);
  window.addEventListener('storage', (e) => {
    if (e.key === BA.KEYS.chain || e.key === BA.KEYS.clean || e.key === null) render();
  });
  await render();
});
