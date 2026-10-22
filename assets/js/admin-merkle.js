/* BlockAudit — admin: Merkle tree
 * Draws BA.merkle() with the root on top and the records as leaves.
 * The same tree is built from the untouched copy; nodes that differ are red.
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

  const short = (h) => `${h.slice(0, 10)}…`;

  const render = async () => {
    const live = await BA.merkle(BA.getChain());
    const cleanChain = BA.store.get(BA.KEYS.clean, null);
    const ref = cleanChain ? await BA.merkle(cleanChain) : null;
    const tree = ui.clear(ui.$('#mk-tree'));

    if (!live.root) {
      ui.$('#mk-root').textContent = '—';
      tree.append(el('p', { class: 'empty', text: 'No records yet. The tree grows as users make requests.' }));
      return;
    }

    const cols = live.levels[0].length; // one grid column per leaf
    tree.style.gridTemplateColumns = `repeat(${cols}, var(--mk-col))`;
    let changed = 0;

    // Root level first, leaves last. A node at level k covers 2^k leaf columns.
    for (let k = live.levels.length - 1; k >= 0; k--) {
      const span = 2 ** k;
      live.levels[k].forEach((n, j) => {
        const other = ref && ref.levels[k] && ref.levels[k][j];
        const diff = !!ref && (!other || other.hash !== n.hash);
        if (diff) changed++;
        const isRoot = k === live.levels.length - 1;
        const node = el('div', {
          class: `mk-node${isRoot ? ' mk-rootnode' : ''}${k === 0 ? ' mk-leaf' : ''}${diff ? ' bad' : ''}`,
          title: n.hash,
        }, [
          el('span', { class: 'mk-kind', text: isRoot ? 'ROOT' : k === 0 ? `Leaf · #${n.index}` : `Level ${k}${n.duplicated ? ' · dup' : ''}` }),
          el('span', { class: 'mono mk-hash', text: short(n.hash) }),
          k === 0 ? el('span', { class: 'mk-label', text: n.label }) : null,
        ]);
        const start = j * span;
        node.style.gridColumn = `${start + 1} / span ${Math.max(1, Math.min(span, cols - start))}`;
        node.style.gridRow = String(live.levels.length - k);
        tree.append(node);
      });
    }

    ui.$('#mk-leaves').textContent = cols;
    ui.$('#mk-levels').textContent = live.levels.length;
    ui.$('#mk-changed').textContent = ref ? changed : '—';
    ui.$('#mk-root').textContent = live.root;
    const match = ref ? ref.root === live.root : null;
    const box = ui.$('#mk-match-box');
    box.classList.toggle('stat-green', match === true);
    box.classList.toggle('stat-red', match === false);
    ui.$('#mk-match').textContent = match === null ? 'No copy' : match ? 'MATCH' : 'CHANGED';

    // Start with the root in view: it sits above the middle of the leaves.
    const scroller = ui.$('.mk-scroll');
    scroller.scrollLeft = (scroller.scrollWidth - scroller.clientWidth) / 2;
  };

  ui.$('#mk-refresh').addEventListener('click', render);
  window.addEventListener('storage', (e) => {
    if (e.key === BA.KEYS.chain || e.key === BA.KEYS.clean || e.key === null) render();
  });
  await render();
});
