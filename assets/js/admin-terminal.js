/* BlockAudit — admin: terminal
 * Renders the backend log (ba_terminal) with colours by level.
 * Updates live when another tab writes to the log.
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

  const LEVELS = ['info', 'success', 'warn', 'error'];
  const term = ui.$('#terminal');
  const stamp = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '??:??:??'
      : `${d.toLocaleDateString([], { day: '2-digit', month: 'short' })} ${d.toLocaleTimeString([], { hour12: false })}`;
  };

  const render = () => {
    const level = ui.$('#tm-level').value;
    const q = ui.$('#tm-search').value.trim().toLowerCase();
    const all = BA.store.get(BA.KEYS.log, []);
    const rows = all.filter((l) =>
      (level === 'all' || l.level === level) && (!q || String(l.msg).toLowerCase().includes(q)));
    ui.$('#tm-count').textContent = `Showing ${rows.length} of ${all.length} lines (the log keeps the last 800)`;
    ui.clear(term);
    if (!rows.length) {
      term.append(el('div', { class: 'tm-line tm-info', text: '$ no matching lines' }));
      return;
    }
    rows.forEach((l) => {
      const lv = LEVELS.includes(l.level) ? l.level : 'info';
      term.append(el('div', { class: `tm-line tm-${lv}` }, [
        el('span', { class: 'tm-time', text: stamp(l.t) }),
        el('span', { class: 'tm-level', text: lv.toUpperCase().padEnd(7) }),
        el('span', { class: 'tm-msg', text: String(l.msg) }),
      ]));
    });
    if (ui.$('#tm-follow').checked) term.scrollTop = term.scrollHeight;
  };

  ui.$('#tm-level').addEventListener('change', render);
  ui.$('#tm-search').addEventListener('input', render);
  ui.$('#tm-follow').addEventListener('change', render);
  window.addEventListener('storage', (e) => {
    if (e.key === BA.KEYS.log || e.key === null) render();
  });
  render();
});
