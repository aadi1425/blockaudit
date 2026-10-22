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

  /* ---------- terminal log ---------- */
  BA.log = (level, msg) => {
    const log = BA.store.get(BA.KEYS.log, []);
    log.push({ t: new Date().toISOString(), level, msg });
    if (log.length > 800) log.splice(0, log.length - 800);
    BA.store.set(BA.KEYS.log, log);
  };

  /* ---------- blocks ---------- */
  BA.blockData = (b) =>
    [b.index, b.timestamp, b.requester, b.resource, b.status, b.previousHash, b.nonce].join('|');
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

  // Mines the genesis block the first time the site is opened.
  BA.init = async () => {
    const chain = BA.getChain();
    if (Array.isArray(chain) && chain.length) return;
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
  BA.addBlock = async (requester, resource, status, meta, onProgress) => {
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

  /* ---------- validation: recompute every hash, check every link ---------- */
  BA.validate = async (chain) => {
    chain = chain || BA.getChain();
    const issues = [];
    for (let i = 0; i < chain.length; i++) {
      const b = chain[i];
      const actual = await BA.hashBlock(b);
      if (actual !== b.hash) {
        issues.push({ index: b.index, type: 'hash', stored: b.hash, actual });
      } else if (!b.hash.startsWith(BA.PREFIX)) {
        issues.push({ index: b.index, type: 'pow', stored: b.hash, actual });
      }
      if (i > 0 && b.previousHash !== chain[i - 1].hash) {
        issues.push({ index: b.index, type: 'link', stored: b.previousHash, actual: chain[i - 1].hash });
      }
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
})();
