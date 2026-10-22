/* BlockAudit — user: my history */
'use strict';
document.addEventListener('DOMContentLoaded', async () => {
  const BA = window.BA;
  const { ui } = BA;
  const s = await BA.auth.guard('user');
  if (!s) return;
  ui.topbar(s, ui.userNav);
  ui.setSeal(s.integrity, false);
  ui.integrityNotice(s.integrity);
  BA.auth.reveal();
  ui.showFlash();
  ui.$('#history').append(ui.userHistory(s.user));
});
