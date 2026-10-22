/* BlockAudit — admin: consensus logs
 * Every resource request with the 3 node votes. Node 3's random votes are marked,
 * and a round is "outvoted" when Node 3 disagreed with the access list but lost.
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

  const render = () => {
    const meta = BA.getMeta();
    const rounds = BA.getChain()
      .filter((b) => b.index > 0 && Array.isArray((meta[b.index] || {}).votes))
      .map((b) => ({ b, m: meta[b.index] }))
      .reverse();

    const faults = rounds.filter((r) => r.m.faultTriggered);
    const outvoted = rounds.filter((r) => r.m.deviated);
    ui.$('#cs-rounds').textContent = rounds.length;
    ui.$('#cs-approved').textContent = rounds.filter((r) => r.b.status === 'APPROVED').length;
    ui.$('#cs-faults').textContent = faults.length;
    ui.$('#cs-outvoted').textContent = outvoted.length;
    ui.$('#cs-count').textContent = `${rounds.length} round${rounds.length === 1 ? '' : 's'}, newest first`;

    const sum = ui.$('#cs-summary');
    sum.className = 'cx-summary ok';
    sum.textContent = rounds.length
      ? `Node 3 voted at random in ${faults.length} of ${rounds.length} rounds (${Math.round((faults.length / rounds.length) * 100)}%, expected about 20%). ` +
        `It voted against the access list ${outvoted.length} time${outvoted.length === 1 ? '' : 's'} and was outvoted every time, because the two honest nodes always agree. ` +
        'One faulty node out of three cannot change a result.'
      : 'No consensus rounds yet. Each access request a user makes appears here.';

    const wrap = ui.clear(ui.$('#cs-table'));
    if (!rounds.length) {
      wrap.append(el('p', { class: 'empty', text: 'No requests yet.' }));
      return;
    }
    const vote = (v) => el('td', {}, [el('span', {
      class: `cx-vote ${v.vote ? 'yes' : 'no'}${v.faulty ? ' faulty' : ''}`,
      title: v.faulty ? 'Random vote (fault triggered)' : `${v.role} node`,
      text: `${v.vote ? 'YES' : 'NO'}${v.faulty ? ' *' : ''}`,
    })]);
    wrap.append(el('table', {}, [
      el('thead', {}, [el('tr', {}, ['Block', 'Time', 'User', 'Resource', 'Node 1', 'Node 2', 'Node 3', 'YES', 'Result', 'Note']
        .map((h) => el('th', { text: h })))]),
      el('tbody', {}, rounds.map(({ b, m }) => {
        const ok = b.status === 'APPROVED';
        const note = m.deviated ? 'Node 3 voted wrong at random, outvoted 2 to 1'
          : m.faultTriggered ? 'Node 3 voted at random, matched by chance' : '';
        return el('tr', { class: m.deviated ? 'cs-deviated' : null }, [
          el('td', { class: 'mono', text: `#${b.index}` }),
          el('td', { text: ui.fmtTime(b.timestamp) }),
          el('td', { text: b.requester }),
          el('td', { text: b.resource }),
          ...m.votes.map(vote),
          el('td', { class: 'mono', text: `${m.yes}/3` }),
          el('td', {}, [el('span', { class: `badge badge-${ok ? 'approved' : 'rejected'}`, text: b.status })]),
          el('td', { class: 'wrap muted', text: note || '—' }),
        ]);
      })),
    ]));
  };

  window.addEventListener('storage', (e) => {
    if (e.key === BA.KEYS.chain || e.key === BA.KEYS.meta || e.key === null) render();
  });
  render();
});
