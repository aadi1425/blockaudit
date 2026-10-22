/* BlockAudit — authentication and security layer
 *  - Passwords stored only as salted PBKDF2-SHA256 hashes (100,000 rounds)
 *  - Login lockout after 5 failures (60 s)
 *  - Session token signed with HMAC-SHA256, checked on every page
 *  - Role is re-checked against the user directory, never trusted from the token alone
 *  - Idle timeout (10 min) and hard session limit (30 min)
 *  - Failed logins and forbidden page visits are mined as REJECTED blocks
 */
'use strict';
(function () {
  const BA = (window.BA = window.BA || {});
  const enc = new TextEncoder();

  const ITERATIONS = 100000;
  const MAX_FAILS = 5;
  const LOCK_MS = 60 * 1000;
  const IDLE_MS = 10 * 60 * 1000;
  const SESSION_MS = 30 * 60 * 1000;

  // No plaintext passwords anywhere in the code.
  const CREDS = {
    Arjun: { salt: '2a9d163d05c4ff11d04987972d9ce5d0', hash: '77647c088157a6cc90078b9ec063b8d958279d6597ef22351554b6231f0951b7' },
    Kavya: { salt: 'bd6097e6b021aa1bdbc266fc53a3bc7a', hash: '89acca73f4cba6735762a693d5bd5c4aa6db1f0feb1b1a5d833e63b781800bf8' },
    Rohan: { salt: '9007a6e70d4ed7ca39dcd97a849e4f25', hash: '4e3c1cc8c1aee820ce33f2adef8ac21713ebc4b4baf930243da257859a49c014' },
    Aadi: { salt: '6ab2cf1b3a2f8773388e8492cde128ef', hash: 'b6f90f6b8e0e866f7c6314d78db1bf40567a4be5656dd4eeb9cddcf57103ea23' },
  };
  const DUMMY_SALT = '00000000000000000000000000000000';

  async function pbkdf2(password, saltHex) {
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: BA.bytes(saltHex), iterations: ITERATIONS },
      key,
      256
    );
    return BA.hex(bits);
  }

  // Compares every character so timing does not leak where a mismatch is.
  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /* ---------- session signing key ---------- */
  async function hmacKey() {
    let raw = BA.store.get('ba_signing_key', null);
    if (!raw) { raw = BA.randomHex(32); BA.store.set('ba_signing_key', raw); }
    return crypto.subtle.importKey('raw', BA.bytes(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }
  async function sign(text) {
    return BA.hex(await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(text)));
  }
  const b64 = (s) => btoa(unescape(encodeURIComponent(s)));
  const unb64 = (s) => decodeURIComponent(escape(atob(s)));

  const ss = {
    get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch (e) { /* ignore */ } },
  };

  /* ---------- lockout ---------- */
  const locks = () => BA.store.get('ba_lockout', {});
  function lockState(name) {
    const l = locks()[name.toLowerCase()];
    if (l && l.until > Date.now()) return Math.ceil((l.until - Date.now()) / 1000);
    return 0;
  }
  function recordFail(name) {
    const all = locks();
    const k = name.toLowerCase();
    const l = all[k] && all[k].until > Date.now() ? all[k] : { fails: all[k] ? all[k].fails : 0, until: 0 };
    l.fails = (l.fails || 0) + 1;
    if (l.fails >= MAX_FAILS) { l.until = Date.now() + LOCK_MS; l.fails = 0; }
    all[k] = l;
    BA.store.set('ba_lockout', all);
    return { left: l.until ? 0 : MAX_FAILS - l.fails, locked: !!l.until };
  }
  function clearFails(name) {
    const all = locks();
    delete all[name.toLowerCase()];
    BA.store.set('ba_lockout', all);
  }

  const canonical = (name) =>
    Object.keys(CREDS).find((u) => u.toLowerCase() === name.toLowerCase()) || null;

  /* ---------- public API ---------- */
  const auth = (BA.auth = {});

  // Returns { ok, user, role } or { ok:false, reason, lockedFor }
  auth.login = async (rawName, password, onMining) => {
    const typed = String(rawName || '').trim();
    if (!/^[A-Za-z0-9_.-]{1,24}$/.test(typed) || !password || password.length > 128) {
      return { ok: false, reason: 'Enter a valid username and password.' };
    }
    const locked = lockState(typed);
    if (locked) {
      BA.log('warn', `Login blocked: account "${typed}" is locked (${locked}s left)`);
      return { ok: false, reason: `Too many failed attempts. Try again in ${locked} seconds.`, lockedFor: locked };
    }

    const user = canonical(typed);
    const cred = user ? CREDS[user] : { salt: DUMMY_SALT, hash: '0'.repeat(64) };
    const attempt = await pbkdf2(password, cred.salt); // same work for unknown users
    const ok = !!user && safeEqual(attempt, cred.hash);

    if (!ok) {
      const f = recordFail(typed);
      const why = user ? 'wrong password' : 'unknown username';
      BA.log('error', `SECURITY: failed login for "${typed}" (${why})`);
      if (onMining) onMining(true);
      await BA.addBlock(typed, 'Login Portal', 'REJECTED', {
        kind: 'login',
        reason: user ? 'Wrong password.' : 'This username does not exist.',
      }, onMining ? (n) => onMining(n) : null);
      if (onMining) onMining(false);
      if (f.locked) {
        BA.log('warn', `SECURITY: "${typed}" locked for ${LOCK_MS / 1000}s after ${MAX_FAILS} failures`);
        return { ok: false, reason: `Too many failed attempts. Account locked for ${LOCK_MS / 1000} seconds.` };
      }
      return {
        ok: false,
        reason: `Wrong username or password. ${f.left} attempt${f.left === 1 ? '' : 's'} left before lockout.`,
      };
    }

    clearFails(user);
    const now = Date.now();
    const payload = { u: user, r: BA.USERS[user].role, iat: now, exp: now + SESSION_MS, sid: BA.randomHex(8) };
    const body = b64(JSON.stringify(payload));
    ss.set('ba_session', `${body}.${await sign(body)}`);
    ss.set('ba_last', String(now));
    BA.log('success', `Session started: ${user} (${payload.r}), session ${payload.sid}`);
    return { ok: true, user, role: payload.r };
  };

  // Verifies signature, expiry, idle time and role. Returns session or null.
  auth.session = async () => {
    const tok = ss.get('ba_session');
    if (!tok || tok.indexOf('.') < 0) return null;
    const [body, sig] = tok.split('.');
    if (!safeEqual(await sign(body), sig || '')) {
      BA.log('error', 'SECURITY: session token signature invalid, possible forgery. Session destroyed.');
      ss.del('ba_session');
      return { invalid: 'This session was altered and has been ended. Sign in again.' };
    }
    let p;
    try { p = JSON.parse(unb64(body)); } catch (e) { return null; }
    const dirRole = BA.USERS[p.u] && BA.USERS[p.u].role;
    if (!dirRole || dirRole !== p.r) return null;
    const now = Date.now();
    if (now > p.exp) return { invalid: 'Your session reached its 30-minute limit. Sign in again.' };
    const last = Number(ss.get('ba_last') || 0);
    if (now - last > IDLE_MS) return { invalid: 'You were signed out after 10 minutes of inactivity.' };
    return { user: p.u, role: p.r, iat: p.iat, exp: p.exp, sid: p.sid };
  };

  auth.logout = (message, type) => {
    const tok = ss.get('ba_session');
    if (tok) {
      try {
        const p = JSON.parse(unb64(tok.split('.')[0]));
        BA.log('info', `Session ended: ${p.u} (${message || 'logout'})`);
      } catch (e) { /* ignore */ }
    }
    ss.del('ba_session');
    ss.del('ba_last');
    if (message) BA.ui.flash(type || 'info', message);
    location.replace((document.body.dataset.root || '') + 'index.html');
  };

  function watchActivity(session) {
    let lastWrite = 0;
    const touch = () => {
      const now = Date.now();
      if (now - lastWrite > 5000) { ss.set('ba_last', String(now)); lastWrite = now; }
    };
    ['click', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach((e) =>
      window.addEventListener(e, touch, { passive: true })
    );
    setInterval(() => {
      const now = Date.now();
      const t = BA.ui.$('#timer');
      if (t) t.textContent = BA.ui.fmtClock(now - session.iat);
      if (now > session.exp) auth.logout('Your session reached its 30-minute limit. Sign in again.', 'warn');
      else if (now - Number(ss.get('ba_last') || 0) > IDLE_MS) {
        auth.logout('You were signed out after 10 minutes of inactivity.', 'warn');
      }
    }, 1000);
  }

  // Call at the top of every protected page: BA.auth.guard('user' | 'admin')
  auth.guard = async (required) => {
    if (window.top !== window.self) { window.top.location = window.self.location; return null; }
    const root = document.body.dataset.root || '';
    await BA.init();
    const s = await auth.session();

    if (!s || s.invalid) {
      BA.ui.flash('warn', (s && s.invalid) || 'Sign in to continue.');
      ss.del('ba_session');
      location.replace(root + 'index.html');
      return null;
    }

    const page = location.pathname.split('/').pop() || 'page';
    if (required === 'admin' && s.role !== 'admin') {
      const reason = 'Standard accounts cannot open the admin console.';
      BA.log('error', `SECURITY: ${s.user} tried to open admin page "${page}". Blocked.`);
      await BA.addBlock(s.user, `Admin Console (${page})`, 'REJECTED', { kind: 'page', reason });
      BA.ui.flash('danger', 'Access to the admin area was denied. This attempt has been recorded.');
      location.replace(root + 'user/request.html');
      return null;
    }
    if (required === 'user' && s.role === 'admin') {
      location.replace(root + 'admin/overview.html');
      return null;
    }

    const integrity = await BA.validate();
    if (!integrity.valid) {
      BA.log('error', `INTEGRITY: chain check failed on page load (${page}), first issue at block #${integrity.issues[0].index}`);
    }
    watchActivity(s);
    s.integrity = integrity;
    return s;
  };

  // Makes the protected page visible once checks pass.
  auth.reveal = () => document.body.removeAttribute('data-guard');
})();
