/* BlockAudit — core engine
 * Real SHA-256 (SubtleCrypto), Proof of Work, 3-node consensus,
 * chain validation, Merkle tree, and the backend terminal log.
 */
'use strict';
(function () {
  const BA = (window.BA = window.BA || {});
  const enc = new TextEncoder();

  BA.DIFFICULTY = 3;
  BA.PREFIX = '0'.repeat(BA.DIFFICULTY);
  BA.KEYS = {
    chain: 'ba_chain',      // live chain (can be tampered in the admin test)
    clean: 'ba_chain_clean', // untouched copy, used by "Reset Chain"
    meta: 'ba_meta',        // consensus votes + reasons, keyed by block index
    log: 'ba_terminal',     // backend terminal log
  };

  /* ---------- storage (always guarded) ---------- */
  BA.store = {
    get(k, fallback) {
      try {
        const v = localStorage.getItem(k);
        return v === null ? fallback : JSON.parse(v);
      } catch (e) { return fallback; }
    },
    set(k, v) {
      try { localStorage.setItem(k, JSON.stringify(v)); return true; }
      catch (e) { return false; }
    },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } },
  };

  /* ---------- crypto helpers ---------- */
  BA.hex = (buf) =>
    Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  BA.bytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  BA.sha256 = async (text) => BA.hex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  BA.randomHex = (n) => BA.hex(crypto.getRandomValues(new Uint8Array(n)));

  /* ---------- directory: people and resources ---------- */
  BA.USERS = {
    Arjun: { role: 'user' },
    Kavya: { role: 'user' },
    Rohan: { role: 'user' },
    Aadi: { role: 'admin' },
  };

  BA.RESOURCES = [
    { id: 'atlas', name: 'Project Atlas', desc: 'Confidential project blueprint', icon: '📐' },
    { id: 'finance', name: 'Finance Ledger', desc: 'Quarterly financial records', icon: '💰' },
    { id: 'hr', name: 'HR Vault', desc: 'Employee personal data', icon: '👤' },
    { id: 'ops', name: 'Ops Manual', desc: 'Internal operations handbook', icon: '⚙️' },
    { id: 'intel', name: 'Classified Intel', desc: 'Top secret intelligence file', icon: '🔒' },
  ];
  BA.resourceById = (id) => BA.RESOURCES.find((r) => r.id === id);

  // Access control list: who is cleared for what.
  // Classified Intel is on nobody's list, so it is always denied.
  BA.ACL = {
    Arjun: ['atlas', 'ops'],
    Kavya: ['finance', 'hr', 'ops'],
    Rohan: ['atlas', 'finance', 'ops'],
  };

  /* ---------- digital signatures (ECDSA P-256) ---------- */
  // Public keys of the users. Each private key is derived from the user's password at
  // login (auth.js), so only someone who knows the password can sign as that user.
  BA.PUBKEYS = {
    Arjun: { x: 'fbcb126201aaadd787eadb289ddca7ad201259ca25da6cfe9c4b6bd3d2baa0e4', y: 'febdf713db8b8fae93192e059676a1bd78c00da08bee316d8dae4470d5d330da' },
    Kavya: { x: 'faba1698545a9904273ba20e077c86df871f10b91d8611a692484e6436277daf', y: '3879fbfafcab28327bf46d3d465d335342f23ec712877abfb634c2c88e3b9311' },
    Rohan: { x: '313287c77f85605c53e3397cf0f0f9f06a4fae9f175c7c5c2215ec99ac22998f', y: '65393d933e6859531753a1b917a1b892701f921af749b048e7af53f1ecdf4e12' },
  };
  // Blocks #1–#18 (the starter chain) were mined before signatures existed.
  // From this block on, every record must carry a valid signature, except failed
  // logins, which have no signed-in user to sign them.
  BA.SIGNED_FROM = 19;

  BA.b64url = (hex) => btoa(String.fromCharCode(...BA.bytes(hex)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // The exact text a user signs: who, what, the decision and when.
  BA.recordText = (b) =>
    ['BlockAudit record v1', b.requester, b.resource, b.status, b.timestamp].join('|');

  const pubKeys = {};
  const publicKey = (user) => {
    if (!Object.prototype.hasOwnProperty.call(BA.PUBKEYS, user)) return null;
    if (!pubKeys[user]) {
      const k = BA.PUBKEYS[user];
      pubKeys[user] = crypto.subtle.importKey(
        'jwk', { kty: 'EC', crv: 'P-256', x: BA.b64url(k.x), y: BA.b64url(k.y), ext: true },
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
      );
    }
    return pubKeys[user];
  };

  // 'signed' | 'invalid' | 'missing' | 'legacy' (before signatures) | 'system' (failed login) | 'genesis'
  BA.checkSignature = async (b) => {
    if (b.index === 0) return 'genesis';
    if (b.signature === undefined) {
      if (b.index < BA.SIGNED_FROM) return 'legacy';
      if (b.resource === 'Login Portal' && b.status === 'REJECTED') return 'system';
      return 'missing';
    }
    const key = publicKey(b.requester);
    if (!key || !/^[0-9a-f]{128}$/.test(String(b.signature))) return 'invalid';
    try {
      const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, await key, BA.bytes(b.signature), enc.encode(BA.recordText(b))
      );
      return ok ? 'signed' : 'invalid';
    } catch (e) { return 'invalid'; }
  };

  // Short labels for the signature check, used on every page.
  BA.SIG_LABEL = {
    signed: 'Signature valid',
    invalid: 'Signature INVALID',
    missing: 'Signature missing',
    legacy: 'Before signatures',
    system: 'Failed login, not signed',
    genesis: 'Genesis',
  };

  /* ---------- terminal log ---------- */
  BA.log = (level, msg) => {
    const log = BA.store.get(BA.KEYS.log, []);
    log.push({ t: new Date().toISOString(), level, msg });
    if (log.length > 800) log.splice(0, log.length - 800);
    BA.store.set(BA.KEYS.log, log);
  };

  /* ---------- blocks ---------- */
  // The signature, when a block has one, is part of the hashed data too.
  BA.blockData = (b) => {
    const parts = [b.index, b.timestamp, b.requester, b.resource, b.status, b.previousHash, b.nonce];
    if (b.signature !== undefined) parts.push(b.signature);
    return parts.join('|');
  };
  BA.hashBlock = (b) => BA.sha256(BA.blockData(b));

  // Proof of Work: raise the nonce until the hash starts with "000".
  BA.mine = async (block, onProgress) => {
    const t0 = performance.now();
    block.nonce = 0;
    let h = await BA.hashBlock(block);
    while (!h.startsWith(BA.PREFIX)) {
      block.nonce++;
      h = await BA.hashBlock(block);
      if (block.nonce % 64 === 0) {
        if (onProgress) onProgress(block.nonce);
        await new Promise((r) => setTimeout(r, 0)); // let the UI repaint
      }
    }
    block.hash = h;
    if (onProgress) onProgress(block.nonce);
    return Math.round(performance.now() - t0);
  };

  BA.getChain = () => BA.store.get(BA.KEYS.chain, []);
  BA.getMeta = () => BA.store.get(BA.KEYS.meta, {});

  // Starter chain shipped with the site (assets/data/seed.json), found from this script's URL.
  const SEED_URL = document.currentScript
    ? new URL('../data/seed.json', document.currentScript.src).href
    : null;

  // Loads the starter chain into an empty browser. Used only if every block still verifies.
  BA.loadSeed = async () => {
    if (!SEED_URL) return false;
    try {
      const res = await fetch(SEED_URL, { cache: 'no-cache' });
      if (!res.ok) return false;
      const seed = await res.json();
      if (!Array.isArray(seed.chain) || !seed.chain.length) return false;
      const check = await BA.validate(seed.chain);
      if (!check.valid) return false;
      BA.store.set(BA.KEYS.chain, seed.chain);
      BA.store.set(BA.KEYS.clean, seed.chain.map((b) => Object.assign({}, b)));
      BA.store.set(BA.KEYS.meta, seed.meta && typeof seed.meta === 'object' ? seed.meta : {});
      BA.store.set(BA.KEYS.log, Array.isArray(seed.terminal) ? seed.terminal : []);
      BA.log('info', `Starter chain loaded: ${seed.chain.length} blocks, all hashes verified`);
      return true;
    } catch (e) { return false; }
  };

  // Loads the starter chain, or mines the genesis block, the first time the site is opened.
  BA.init = async () => {
    const chain = BA.getChain();
    if (Array.isArray(chain) && chain.length) return;
    if (await BA.loadSeed()) return;
    const g = {
      index: 0,
      timestamp: new Date().toISOString(),
      requester: 'SYSTEM',
      resource: 'GENESIS',
      status: 'APPROVED',
      previousHash: '0'.repeat(64),
      nonce: 0,
      hash: '',
    };
    const ms = await BA.mine(g);
    BA.store.set(BA.KEYS.chain, [g]);
    BA.store.set(BA.KEYS.clean, [g]);
    BA.store.set(BA.KEYS.meta, {});
    BA.log('info', 'Blockchain initialised');
    BA.log('success', `Genesis block #0 mined in ${ms} ms, nonce ${g.nonce}, hash ${g.hash}`);
  };

  // Every request, approved or rejected, becomes a block.
  // meta = { kind, votes, yes, reason, faultTriggered }
  // sign = async (text) => hex signature, from BA.auth.signRecord (left out for failed logins)
  BA.addBlock = async (requester, resource, status, meta, onProgress, sign) => {
    const chain = BA.getChain();
    const clean = BA.store.get(BA.KEYS.clean, chain.slice());
    const prev = chain[chain.length - 1];
    const b = {
      index: prev.index + 1,
      timestamp: new Date().toISOString(),
      requester,
      resource,
      status,
      previousHash: prev.hash,
      nonce: 0,
      hash: '',
    };
    if (sign) {
      const sig = await sign(BA.recordText(b));
      if (sig) {
        b.signature = sig;
        BA.log('info', `Record signed by ${requester} (ECDSA P-256), signature ${sig.slice(0, 16)}…`);
      }
    }
    BA.log('info', `Mining block #${b.index} for ${requester} (difficulty ${BA.DIFFICULTY})`);
    const ms = await BA.mine(b, onProgress);
    chain.push(b);
    clean.push(Object.assign({}, b));
    BA.store.set(BA.KEYS.chain, chain);
    BA.store.set(BA.KEYS.clean, clean);
    const allMeta = BA.getMeta();
    allMeta[b.index] = meta || {};
    BA.store.set(BA.KEYS.meta, allMeta);
    BA.log(
      status === 'APPROVED' ? 'success' : 'error',
      `Block #${b.index} mined in ${ms} ms, nonce ${b.nonce}, ${status}, hash ${b.hash}`
    );
    return b;
  };

  /* ---------- validation: recompute every hash, check every link and signature ---------- */
  // One block against its parent. Used by validate() and by every page that lists blocks.
  BA.checkBlock = async (b, prev) => {
    const actual = await BA.hashBlock(b);
    const parent = prev ? prev.hash : '0'.repeat(64);
    const sig = await BA.checkSignature(b);
    const hashOk = actual === b.hash;
    const powOk = String(b.hash).startsWith(BA.PREFIX);
    const linkOk = b.previousHash === parent;
    const sigOk = sig !== 'invalid' && sig !== 'missing';
    return { b, actual, parent, hashOk, powOk, linkOk, sig, sigOk, ok: hashOk && powOk && linkOk && sigOk };
  };

  BA.validate = async (chain) => {
    chain = chain || BA.getChain();
    const issues = [];
    for (let i = 0; i < chain.length; i++) {
      const c = await BA.checkBlock(chain[i], chain[i - 1]);
      const b = c.b;
      if (!c.hashOk) {
        issues.push({ index: b.index, type: 'hash', stored: b.hash, actual: c.actual });
      } else if (!c.powOk) {
        issues.push({ index: b.index, type: 'pow', stored: b.hash, actual: c.actual });
      }
      if (!c.linkOk) {
        issues.push({ index: b.index, type: 'link', stored: b.previousHash, actual: c.parent });
      }
      if (!c.sigOk) issues.push({ index: b.index, type: 'sig', sig: c.sig });
    }
    if (!chain.length) issues.push({ index: 0, type: 'empty' });
    return { valid: issues.length === 0, issues, length: chain.length };
  };

  /* ---------- consensus: 3 nodes, majority wins ---------- */
  BA.consensus = (requester, resourceId) => {
    const allowed = (BA.ACL[requester] || []).includes(resourceId);
    const faultTriggered = Math.random() < 0.2;
    const node3 = faultTriggered ? Math.random() < 0.5 : allowed;
    const votes = [
      { node: 'Node 1', role: 'honest', vote: allowed },
      { node: 'Node 2', role: 'honest', vote: allowed },
      { node: 'Node 3', role: 'fault-prone', vote: node3, faulty: faultTriggered },
    ];
    const yes = votes.filter((v) => v.vote).length;
    return { votes, yes, approved: yes >= 2, allowed, faultTriggered, deviated: node3 !== allowed };
  };

  // Plain-English reason shown to users for a denied request.
  BA.denyReason = (requester, resourceId) => {
    if (resourceId === 'intel') {
      return 'Classified Intel needs top-secret clearance. No standard account holds it.';
    }
    const r = BA.resourceById(resourceId);
    return `${requester} is not on the access list for ${r ? r.name : 'this resource'}. Ask your manager to grant access.`;
  };

  /* ---------- Merkle tree ---------- */
  BA.merkle = async (chain) => {
    chain = chain || BA.getChain();
    const records = chain.filter((b) => b.index > 0);
    if (!records.length) return { levels: [], root: null };
    let level = [];
    for (const b of records) {
      const label = `${b.requester}→${b.resource}→${b.status}`;
      level.push({ hash: await BA.sha256(label), label, index: b.index });
    }
    const levels = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1] || level[i]; // odd count: duplicate the last node
        next.push({ hash: await BA.sha256(left.hash + right.hash), duplicated: !level[i + 1] });
      }
      levels.push(next);
      level = next;
    }
    return { levels, root: level[0].hash };
  };

  /* ---------- stats ---------- */
  BA.statsFor = (user) => {
    const blocks = BA.getChain().filter((b) => b.index > 0 && (!user || b.requester === user));
    return {
      total: blocks.length,
      approved: blocks.filter((b) => b.status === 'APPROVED').length,
      rejected: blocks.filter((b) => b.status === 'REJECTED').length,
      last: blocks.length ? blocks[blocks.length - 1].timestamp : null,
    };
  };

  // Per-account activity for the admin Users page and the printable report.
  BA.userSummary = () => {
    const records = BA.getChain().filter((b) => b.index > 0);
    const isResource = (b) => BA.RESOURCES.some((r) => r.name === b.resource);
    return Object.keys(BA.USERS).map((user) => {
      const own = records.filter((b) => b.requester === user);
      const requests = own.filter(isResource);
      const failed = records.filter((b) => b.resource === 'Login Portal' && String(b.requester).toLowerCase() === user.toLowerCase());
      const pages = own.filter((b) => String(b.resource).startsWith('Admin Console'));
      const times = [...requests, ...failed, ...pages].map((b) => b.timestamp).sort();
      return {
        user,
        role: BA.USERS[user].role,
        cleared: (BA.ACL[user] || []).map((id) => BA.resourceById(id).name),
        requests: requests.length,
        granted: requests.filter((b) => b.status === 'APPROVED').length,
        denied: requests.filter((b) => b.status === 'REJECTED').length,
        failedLogins: failed.length,
        pageAttempts: pages.length,
        last: times.length ? times[times.length - 1] : null,
        pubX: BA.PUBKEYS[user] ? BA.PUBKEYS[user].x : null,
      };
    });
  };

  // Failed logins with usernames that are not in the directory, grouped by name.
  BA.unknownLogins = () => {
    const known = Object.keys(BA.USERS).map((u) => u.toLowerCase());
    const out = {};
    BA.getChain()
      .filter((b) => b.resource === 'Login Portal' && !known.includes(String(b.requester).toLowerCase()))
      .forEach((b) => {
        const k = String(b.requester);
        out[k] = out[k] || { name: k, count: 0, last: b.timestamp };
        out[k].count++;
        out[k].last = b.timestamp;
      });
    return Object.values(out);
  };
})();
