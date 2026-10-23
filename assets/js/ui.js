/* BlockAudit — shared UI helpers.
 * Everything is built with createElement + textContent, never innerHTML,
 * so user-typed text can never become HTML (XSS-safe).
 */
'use strict';
(function () {
  const BA = (window.BA = window.BA || {});
  const UI = (BA.ui = {});

  // el('div', {class:'x', text:'hi', onclick: fn}, [children])
  UI.el = (tag, attrs, children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of [].concat(children || [])) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  };
  const el = UI.el;

  UI.$ = (sel, root) => (root || document).querySelector(sel);
  UI.clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); return node; };

  UI.fmtTime = (iso) => new Date(iso).toLocaleString([], {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  UI.fmtClock = (ms) => {
    const s = Math.max(0, Math.floor(ms / 1000));
    return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  };

  /* ---------- CSV download ---------- */
  // rows: array of arrays. Cells that start with = + - @ get a leading ' so a
  // spreadsheet never runs them as formulas (CSV injection).
  UI.downloadCsv = (filename, rows) => {
    const cell = (v) => {
      let s = v === null || v === undefined ? '' : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const text = '﻿' + rows.map((r) => r.map(cell).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
    const a = el('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  // Signature check as a small chip. Grey for blocks that are not meant to be signed.
  UI.sigChip = (c, showName) => {
    if (c.sig === 'genesis') return null;
    const cls = c.sig === 'signed' ? 'ok' : c.sigOk ? 'na' : 'fail';
    const mark = c.sig === 'signed' ? '✓ ' : c.sigOk ? '· ' : '✗ ';
    const text = c.sig === 'signed' && showName ? `Signed by ${c.b.requester}` : BA.SIG_LABEL[c.sig];
    return el('span', { class: `cx-check ${cls}` }, [mark, text]);
  };

  // Plain-English explanation of a failed signature check.
  UI.sigProblem = (c) => c.sig === 'missing'
    ? 'This record should carry its requester\'s signature but has none. The signature was removed or the record was forged.'
    : 'The signature does not match this record. The requester, resource or result was changed after it was signed. Re-mining cannot fix this without the user\'s private key.';

  /* ---------- mining overlay ---------- */
  UI.overlay = {
    show(title, sub) {
      let o = UI.$('#mining');
      if (!o) {
        o = el('div', { id: 'mining', class: 'overlay', role: 'status', 'aria-live': 'polite' }, [
          el('div', { class: 'overlay-card' }, [
            el('div', { class: 'spinner', 'aria-hidden': 'true' }),
            el('p', { class: 'overlay-title', id: 'mining-title' }),
            el('p', { class: 'overlay-sub', id: 'mining-sub' }),
            el('p', { class: 'overlay-nonce' }, ['Nonce ', el('span', { id: 'mining-nonce', text: '0' })]),
          ]),
        ]);
        document.body.append(o);
      }
      UI.$('#mining-title').textContent = title || 'Proof of Work';
      UI.$('#mining-sub').textContent = sub || 'Finding a hash that starts with 000';
      UI.$('#mining-nonce').textContent = '0';
      o.classList.add('open');
    },
    nonce(n) { const x = UI.$('#mining-nonce'); if (x) x.textContent = n.toLocaleString(); },
    hide() { const o = UI.$('#mining'); if (o) o.classList.remove('open'); },
  };

  /* ---------- alert banner (top-right) ---------- */
  UI.alert = (type, text, ms) => {
    let wrap = UI.$('#alerts');
    if (!wrap) {
      wrap = el('div', { id: 'alerts', class: 'alerts', 'aria-live': 'assertive' });
      document.body.append(wrap);
    }
    const close = el('button', { class: 'alert-close', type: 'button', 'aria-label': 'Dismiss', text: '×' });
    const a = el('div', { class: `alert alert-${type}`, role: 'alert' }, [el('span', { text }), close]);
    close.addEventListener('click', () => a.remove());
    wrap.append(a);
    setTimeout(() => a.remove(), ms || 7000);
  };

  // A message that survives a redirect (shown on the next page).
  UI.flash = (type, text) => {
    try { sessionStorage.setItem('ba_flash', JSON.stringify({ type, text })); } catch (e) { /* ignore */ }
  };
  UI.showFlash = () => {
    try {
      const f = JSON.parse(sessionStorage.getItem('ba_flash') || 'null');
      sessionStorage.removeItem('ba_flash');
      if (f) UI.alert(f.type, f.text);
    } catch (e) { /* ignore */ }
  };

  /* ---------- modal ---------- */
  UI.modal = (content, onClose) => {
    const box = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, content);
    const back = el('div', { class: 'modal-back' }, [box]);
    const close = () => { back.remove(); document.removeEventListener('keydown', esc); if (onClose) onClose(); };
    const esc = (e) => { if (e.key === 'Escape') close(); };
    back.addEventListener('click', (e) => { if (e.target === back) close(); });
    document.addEventListener('keydown', esc);
    document.body.append(back);
    const f = box.querySelector('button');
    if (f) f.focus();
    return close;
  };

  /* ---------- topbar ---------- */
  // nav: [{href, label}]
  UI.topbar = (session, nav) => {
    const root = document.body.dataset.root || '';
    const here = location.pathname.split('/').pop();
    const links = nav.map((n) =>
      el('a', {
        href: root + n.href,
        class: 'nav-link',
        'aria-current': n.href.endsWith(here) ? 'page' : null,
        text: n.label,
      })
    );
    const logout = el('button', { class: 'btn btn-ghost btn-sm', type: 'button', id: 'logout', text: 'Log out' });
    const bar = el('header', { class: nav.length > 4 ? 'topbar topbar-wide' : 'topbar' }, [
      el('a', { class: 'brand', href: root + nav[0].href }, [
        el('img', { class: 'brand-crest', src: root + 'assets/img/nfsu-crest.png', alt: 'NFSU', width: '104', height: '133' }),
        el('span', { text: 'BlockAudit' }),
      ]),
      el('nav', { class: 'nav', 'aria-label': 'Main' }, links),
      el('div', { class: 'topbar-right' }, [
        el('span', { class: 'seal', id: 'seal', title: 'Chain integrity' }, [
          el('span', { class: 'seal-dot' }),
          el('span', { class: 'seal-text', text: 'Checking chain' }),
        ]),
        el('span', { class: `role role-${session.role}`, text: session.role.toUpperCase() }),
        el('span', { class: 'timer', id: 'timer', title: 'Session time', text: '00:00' }),
        el('span', { class: 'who' }, [
          el('span', { class: 'avatar', 'aria-hidden': 'true', text: session.user[0] }),
          el('span', { class: 'who-name', text: session.user }),
        ]),
        logout,
      ]),
    ]);
    document.body.prepend(bar);
    logout.addEventListener('click', () => BA.auth.logout('You have been logged out.'));
  };

  // A user's own requests as a table (no hashes, no votes).
  UI.userHistory = (user, limit) => {
    const meta = BA.getMeta();
    let rows = BA.getChain().filter((b) => b.index > 0 && b.requester === user).reverse();
    if (limit) rows = rows.slice(0, limit);
    if (!rows.length) {
      return el('p', { class: 'empty', text: 'No requests yet. Pick a resource above to make your first one.' });
    }
    return el('table', {}, [
      el('thead', {}, [el('tr', {}, ['Time', 'Resource', 'Result', 'Block', 'Reason'].map((h) => el('th', { text: h })))]),
      el('tbody', {}, rows.map((b) => {
        const ok = b.status === 'APPROVED';
        const m = meta[b.index] || {};
        return el('tr', {}, [
          el('td', { text: UI.fmtTime(b.timestamp) }),
          el('td', { text: b.resource }),
          el('td', {}, [el('span', { class: `badge badge-${ok ? 'approved' : 'rejected'}`, text: ok ? 'Granted' : 'Denied' })]),
          el('td', { class: 'mono', text: `#${b.index}` }),
          el('td', { class: 'wrap muted', text: ok ? '—' : (m.reason || 'Not authorised.') }),
        ]);
      })),
    ]);
  };

  UI.userNav = [
    { href: 'user/request.html', label: 'Request access' },
    { href: 'user/history.html', label: 'My history' },
    { href: 'user/ledger.html', label: 'Public ledger' },
  ];

  // Admin pages are added here as they are built.
  UI.adminNav = [
    { href: 'admin/overview.html', label: 'Overview' },
    { href: 'admin/chain.html', label: 'Chain explorer' },
    { href: 'admin/tamper.html', label: 'Tamper test' },
    { href: 'admin/consensus.html', label: 'Consensus' },
    { href: 'admin/merkle.html', label: 'Merkle tree' },
    { href: 'admin/terminal.html', label: 'Terminal' },
    { href: 'admin/users.html', label: 'Users' },
    { href: 'admin/report.html', label: 'Report' },
  ];

  UI.integrityNotice = (result) => {
    const slot = UI.$('#integrity-notice');
    if (!slot || result.valid) return;
    slot.append(el('div', { class: 'notice', role: 'alert', text:
      'An integrity check on the audit records failed. The administrator has been notified and your history may be under review.' }));
  };

  // Small integrity indicator in the topbar.
  // Admins see the detail; users only see "Verified" or a generic warning.
  UI.setSeal = (result, isAdmin) => {
    const seal = UI.$('#seal');
    if (!seal) return;
    seal.classList.toggle('bad', !result.valid);
    seal.querySelector('.seal-text').textContent = result.valid
      ? (isAdmin ? `Chain valid, ${result.length} blocks` : 'Records verified')
      : (isAdmin ? `Chain broken at #${result.issues[0].index}` : 'Integrity alert');
  };
})();
