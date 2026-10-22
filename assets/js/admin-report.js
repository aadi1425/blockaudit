/* BlockAudit — admin: printable audit report
 * One page with the chain status, per-user summary and the full audit log,
 * styled for paper by the @media print rules in style.css.
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

  const chain = BA.getChain();
  const meta = BA.getMeta();
  const checked = [];
  for (let i = 0; i < chain.length; i++) checked.push(await BA.checkBlock(chain[i], chain[i - 1]));
  const valid = checked.length > 0 && checked.every((c) => c.ok);
  const st = BA.statsFor(null);
  const merkle = await BA.merkle(chain);
  const now = new Date();

  ui.$('#rp-sub').textContent = `BlockAudit: IAM on Blockchain · generated ${now.toLocaleString()} by ${s.user}`;
  const fact = (k, v, cls) => [el('dt', { text: k }), el('dd', { class: cls || '', text: v })];
  ui.$('#rp-facts').append(
    ...fact('Chain status', valid ? 'VALID: every hash, link and signature checks out' : `BROKEN at block #${checked.find((c) => !c.ok).b.index}`, valid ? 'rp-good' : 'rp-bad'),
    ...fact('Blocks', `${chain.length} (genesis + ${st.total} records)`),
    ...fact('Approved / rejected', `${st.approved} / ${st.rejected}`),
    ...fact('Signatures verified', String(checked.filter((c) => c.sig === 'signed').length)),
    ...fact('Proof of Work', `SHA-256, hash must start with ${BA.PREFIX}`),
    ...fact('Consensus', '3 nodes, 2 of 3 YES approves'),
    ...fact('Merkle root', merkle.root || '—', 'mono rp-wrap'),
    ...fact('Latest block hash', chain.length ? chain[chain.length - 1].hash : '—', 'mono rp-wrap'),
  );

  ui.$('#rp-users').append(el('table', {}, [
    el('thead', {}, [el('tr', {}, ['User', 'Role', 'Requests', 'Granted', 'Denied', 'Failed logins', 'Admin page attempts']
      .map((h) => el('th', { text: h })))]),
    el('tbody', {}, BA.userSummary().map((u) => el('tr', {}, [
      el('td', { text: u.user }), el('td', { text: u.role }),
      el('td', { text: String(u.requests) }), el('td', { text: String(u.granted) }), el('td', { text: String(u.denied) }),
      el('td', { text: String(u.failedLogins) }), el('td', { text: String(u.pageAttempts) }),
    ]))),
  ]));

  ui.$('#rp-log').append(el('table', { class: 'rp-log' }, [
    el('thead', {}, [el('tr', {}, ['Block', 'Time', 'User', 'Resource', 'Result', 'Reason', 'Signature', 'Check']
      .map((h) => el('th', { text: h })))]),
    el('tbody', {}, checked.filter((c) => c.b.index > 0).map((c) => {
      const { b } = c;
      const m = meta[b.index] || {};
      return el('tr', {}, [
        el('td', { class: 'mono', text: `#${b.index}` }),
        el('td', { text: ui.fmtTime(b.timestamp) }),
        el('td', { text: String(b.requester) }),
        el('td', { text: String(b.resource) }),
        el('td', { text: b.status }),
        el('td', { class: 'wrap', text: b.status === 'APPROVED' ? '—' : (m.reason || '') }),
        el('td', { text: BA.SIG_LABEL[c.sig] }),
        el('td', { class: c.ok ? 'rp-good' : 'rp-bad', text: c.ok ? 'VALID' : 'TAMPERED' }),
      ]);
    })),
  ]));

  ui.$('#rp-foot').textContent = 'Hashes, links and signatures were recomputed in this browser when the report was generated. ' +
    'Demo system: logins are checked in the browser; a real deployment would check them on a server.';

  ui.$('#rp-print').addEventListener('click', () => {
    BA.log('info', 'Admin printed the audit report');
    window.print();
  });
});
