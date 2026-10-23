# CLAUDE.md — BlockAudit project guide for Claude Code

Read this whole file before changing anything. It is the single source of truth
for this project. **After every change you make, update Section 9 (Progress log)
and Section 8 (Roadmap checkboxes).**

---

## 1. Who you are working with

- Owner: **Aadi**, MSc Cybersecurity student at **NFSU Goa**.
- Aadi does **not** write code. He tests in the browser and reports what he sees.
  - Explain changes in plain, short language. No jargon walls.
  - He often writes in Gujarati/Hindi mixed with English. Reply in the same style if he does.
  - Before a big change, say in 2–3 lines what you will change and which files.
  - After a change, give him exact test steps (who to log in as, what to click, what he should see).
- Never connect this project to Aadi's past internship or work experience in any text,
  README, report draft or comment.

## 2. The project

- **Title:** BlockAudit: A Blockchain-Based Resource Access Integrity and Tamper-Evident
  Audit Trail System with Consensus Validation
- **Short title:** BlockAudit — IAM on Blockchain
- **Course:** Blockchain Technology, 25-mark mini project.
- **Idea:** an Identity & Access Management site. Users request company resources.
  Every request — approved OR rejected — is mined into a SHA-256 Proof-of-Work blockchain.
  Nobody can delete or edit a record without the hash chain exposing it.
  Normal users only see "Access Granted / Denied". The admin sees everything.

### The two official objectives (do not reword them in the UI or docs)
1. To design and implement a blockchain-based access logging system using SHA-256 hashing
   and Proof of Work that creates a tamper-evident audit trail of all resource access
   requests — authorized and unauthorized.
2. To demonstrate integrity violation detection by simulating unauthorized resource access
   and an attempt to conceal it through record tampering, and proving that the blockchain's
   hash pointer chain exposes any such manipulation automatically.

## 3. Accounts, resources, access rules

| Username | Password    | Role  |
|----------|-------------|-------|
| Arjun    | `arjun@99`  | user  |
| Kavya    | `kavya@99`  | user  |
| Rohan    | `rohan@99`  | user  |
| Aadi     | `admin@999` | admin (monitors only, cannot request resources) |

Usernames are case-sensitive. Passwords are stored as PBKDF2 hashes in `auth.js` (`CREDS`),
never as plain text. These are demo accounts.

Resources (`BA.RESOURCES` in `core.js`): Project Atlas 📐 (`atlas`), Finance Ledger 💰
(`finance`), HR Vault 👤 (`hr`), Ops Manual ⚙️ (`ops`), Classified Intel 🔒 (`intel`).

ACL (`BA.ACL` in `core.js`):
- Arjun → atlas, ops
- Kavya → finance, hr, ops
- Rohan → atlas, finance, ops
- Classified Intel → nobody (always denied)

Also mined as REJECTED blocks: failed logins (resource `Login Portal`) and a user opening
an admin page (resource `Admin Console (<page>)`).

## 4. How to run

The site MUST be served over http. Double-clicking `index.html` (file://) does not work —
the Content-Security-Policy blocks the scripts.

- VS Code: right-click `index.html` → **Open with Live Server** → `http://127.0.0.1:5500/index.html`
- Python: `python -m http.server 8000` → `http://localhost:8000`
- Docker: `docker build -t blockaudit . && docker run -d -p 8080:80 --name blockaudit blockaudit` → `http://localhost:8080`
- Live: GitHub Pages at `https://aadi1425.github.io/blockaudit` (repo `aadi1425/blockaudit`, branch `main`, root folder)

Reset all data: browser DevTools → Application → clear Local Storage and Session Storage → refresh.
The starter chain from `assets/data/seed.json` loads again (if that file is missing or fails
validation, a fresh genesis block is mined instead).

## 5. Architecture

Plain HTML + CSS + vanilla JavaScript. **No frameworks, no build step, no npm, no server code.**

```
blockaudit/
├── index.html              login page
├── user/request.html       user: pick resource, submit, result popup
├── user/history.html       user: own history only
├── user/ledger.html        user: public ledger — every block's hashes + live verify; names only on own blocks
├── admin/overview.html     admin: stats, recent activity, alerts
├── admin/chain.html        admin: chain explorer (every block, full hashes, signature, live re-check, CSV export)
├── admin/tamper.html       admin: tamper test (edit, re-mine like an attacker, validate, reset from ba_chain_clean)
├── admin/consensus.html    admin: every consensus round, Node 3 random votes marked
├── admin/merkle.html       admin: Merkle tree as SVG (sideways or top-down), click a record for its Merkle proof, nodes that differ from ba_chain_clean in red
├── admin/terminal.html     admin: ba_terminal log, coloured by level, filter, follow
├── admin/users.html        admin: per-account activity, access list, public key
├── admin/report.html       admin: printable audit report (@media print in style.css)
├── assets/css/style.css    all styles (one file)
├── assets/data/seed.json   starter chain { chain, meta, terminal } loaded into an empty browser
├── assets/img/nfsu-logo-dark.png, nfsu-crest.png   NFSU logo (login + report) and crest (topbar): transparent, light lettering
├── assets/img/nfsu-logo.png    original NFSU logo (navy on white), used only when printing the report
├── assets/js/core.js       BA core: storage, SHA-256, mining, chain, validation, consensus, ACL, Merkle, log
├── assets/js/auth.js       login, PBKDF2, lockout, signed sessions, guard(), reveal(), timeouts
├── assets/js/ui.js         BA.ui helpers: el(), topbar, nav lists, modal, alerts, overlay, seal
├── assets/js/login.js      index.html logic
├── assets/js/user-request.js, user-history.js, user-ledger.js
├── assets/js/admin-overview.js, admin-chain.js, admin-tamper.js, admin-consensus.js,
│   admin-merkle.js, admin-terminal.js, admin-users.js, admin-report.js
├── Dockerfile, nginx.conf, .dockerignore   server security headers (Docker only)
├── README.md
└── CLAUDE.md               this file
```

### Data (localStorage keys, from `BA.KEYS`)
- `ba_chain` — live chain (array of blocks). Can be tampered for the demo.
- `ba_chain_clean` — untouched copy, used to reset after a tamper test.
- `ba_meta` — per-block extras keyed by block index: `{ kind, resourceId, votes, yes, reason, faultTriggered }`
- `ba_terminal` — backend log lines `{ t, level, msg }` (max 800)
- `ba_admin_seen` — last block index the admin has seen (for alerts)
- Session lives in **sessionStorage** (`ba_session`, `ba_last`, `ba_flash`, and `ba_sigkey` =
  the signed-in user's private signing key as a JWK; cleared on logout).

### Digital signatures (ECDSA P-256)
- Private key d = PBKDF2(password, `SIG_SALTS[user]` in `auth.js`, 100k) mod (n−1) + 1, made at login.
  Public point d·G is computed with BigInt in `auth.js` and must equal `BA.PUBKEYS[user]` in `core.js`.
- Signed text: `BA.recordText(b)` = `BlockAudit record v1|requester|resource|status|timestamp`.
  Signature (hex r||s, 128 chars) is stored as `b.signature` and is appended to `BA.blockData(b)`.
- `BA.checkSignature(b)` → `signed | invalid | missing | legacy | system | genesis`.
  From `BA.SIGNED_FROM` (19) on, every block must be signed except failed logins (`system`).
  Blocks below 19 are the starter chain, made before signatures (`legacy`).
- Admin-page attempts by users are signed with the user's session key.
- Aadi (admin) has no signing key; he never makes requests.

### Block format
`{ index, timestamp, requester, resource, status, previousHash, nonce, hash, signature? }`
- `status`: `APPROVED` or `REJECTED` (genesis uses `APPROVED`, requester `SYSTEM`, resource `GENESIS`).
- Hash = SHA-256 of `BA.blockData(b)` = `[index, timestamp, requester, resource, status, previousHash, nonce].join('|')`,
  plus `|signature` when the block has one (older blocks hash exactly as before).
- Proof of Work: nonce rises until hash starts with `BA.PREFIX` (`000`, `BA.DIFFICULTY = 3`).
- Genesis `previousHash` = 64 zeros.

### Key core.js functions
`BA.sha256(text)`, `BA.hashBlock(b)`, `BA.mine(block, onProgress)`, `BA.getChain()`, `BA.getMeta()`,
`BA.init()` (loads the starter chain via `BA.loadSeed()`, else mines genesis — once), `BA.addBlock(requester, resource, status, meta, onProgress)`,
`BA.checkBlock(b, prev)` → `{ b, actual, parent, hashOk, powOk, linkOk, sig, sigOk, ok }` (used by every page),
`BA.validate(chain)` → `{ valid, issues:[{index,type:'hash'|'pow'|'link'|'sig'|'empty',stored,actual}], length }`,
`BA.checkSignature(b)`, `BA.userSummary()`, `BA.unknownLogins()`, `BA.ui.downloadCsv()`, `BA.ui.sigChip()`,
`BA.consensus(requester, resourceId)` → `{ votes, yes, approved, allowed, faultTriggered, deviated }`,
`BA.denyReason()`, `BA.merkle(chain)` → `{ levels, root }`, `BA.statsFor(user|null)`, `BA.log(level, msg)`.

Consensus: Node 1 and Node 2 honest (follow the ACL); Node 3 has a 20% chance of a random vote.
2 of 3 YES = APPROVED.

## 6. Rules you must follow (security + style)

1. **Never use `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`.**
   Build DOM with `BA.ui.el(tag, attrs, children)`; text goes in via `text:` / textContent.
2. No inline `<script>` and no inline event handlers (`onclick="..."`) — the CSP forbids them.
   All JS goes in `assets/js/*.js` loaded with `defer`.
3. Every protected page uses this exact pattern:
   ```js
   document.addEventListener('DOMContentLoaded', async () => {
     const BA = window.BA; const { ui } = BA; const el = ui.el;
     const s = await BA.auth.guard('admin');   // or 'user'
     if (!s) return;
     ui.topbar(s, ui.adminNav);                // or ui.userNav
     ui.setSeal(s.integrity, true);            // false on user pages
     BA.auth.reveal();
     ui.showFlash();
     // ... page code ...
   });
   ```
   and the HTML `<body data-root="../" data-guard>` plus the same `<head>` block as
   `admin/overview.html` (CSP meta, referrer, robots, fonts, style.css, core/ui/auth scripts).
4. New admin page = new `admin/<name>.html` + `assets/js/admin-<name>.js` + one line in
   `UI.adminNav` in `ui.js`. Copy `admin/chain.html` as the template.
5. Users must never see votes, other users' names/resources/reasons, or admin pages.
   Exception (decided 2026-10-02): the Public ledger shows every user every block's index,
   time, Granted/Denied, hash, previous hash, nonce and VALID/TAMPERED, so any user can
   verify the chain. Other users' blocks read "Another user" / "Hidden resource".
   Honest limit: this hiding is in the UI only — the full chain is still in localStorage.
6. Keep the design: dark enterprise theme. Use the CSS variables in `:root` of `style.css`
   (`--bg #060910`, `--blue #2563eb`, `--green #10b981`, `--red #ef4444`, `--yellow #f59e0b`,
   fonts Inter + JetBrains Mono). Add new CSS **above** the `/* ---------- responsive ---------- */`
   marker. Make it work on a phone width (~380px).
7. All hashes must be real SHA-256 from `BA.sha256`. Never fake a hash or a result.
8. Every storage read/write goes through `BA.store` (it is wrapped in try/catch).
9. Do not change passwords, the ACL, the objectives or the block format unless Aadi asks.
10. Wrap user-typed input with length limits (`maxlength`) and treat it as text only.
11. Keep it honest: login checks run in the browser. The blockchain is the tamper-evident part.
    A real deployment would check logins on a server. Say this in docs where relevant.

## 7. Testing checklist (run after every change)

1. Serve the site (Section 4). Open DevTools Console — there must be **no red errors**
   (Google Fonts warnings offline are fine).
2. Rohan / `rohan@99`: request **Ops Manual** → Granted; **HR Vault** → Denied with reason.
3. Kavya / `kavya@99`: request **Classified Intel** → Denied ("needs top-secret clearance").
4. As Rohan, change URL to `admin/overview.html` → bounced back, attempt recorded.
5. Wrong password 5× for any user → locked 60 s.
6. Aadi / `admin@999`: Overview counts match; Chain explorer lists every block with VALID checks.
7. Tamper test: in DevTools Console run
   `const c=JSON.parse(localStorage.ba_chain);c[1].requester='Hacker';localStorage.ba_chain=JSON.stringify(c)`
   then refresh → seal shows "Chain broken at #1", Chain explorer shows a red TAMPERED card
   with stored vs recomputed hash.
8. Check the page at phone width (DevTools device toolbar).

Git after a working change:
```
git add .
git commit -m "<what changed>"
git push
```

## 8. Roadmap

### Part 1 — Run, test, publish (Aadi is doing this)
- [x] Login, lockout, signed sessions, page guards, timeouts
- [x] User pages: request access, my history
- [x] Admin overview
- [x] Docker + nginx security headers
- [x] Aadi runs it in VS Code with Live Server and passes the Section 7 tests
- [ ] Report screenshots taken
- [x] Pushed to GitHub, GitHub Pages live at https://aadi1425.github.io/blockaudit
- [x] Starter chain: Live Server test activity ships in `assets/data/seed.json` so every visitor starts with it

### Part 2 — Remaining admin pages
- [x] Chain explorer (`admin/chain.html`) — full hash, prev hash, nonce, votes, live re-check, filter, order, copy
- [x] Public ledger for users (`user/ledger.html`) — everyone verifies, names only on own blocks
- [x] Digital signatures — each user signs requests (WebCrypto ECDSA) so nobody can forge one
- [x] Tamper test page — pick a block, change requester, Validate, Reset (restore from `ba_chain_clean`);
      show stored vs recomputed hash side by side; plus "Re-mine" to play the smarter attacker
- [x] Consensus logs — every request with the 3 node votes, faulty node marked
- [x] Merkle tree — real tree shape from `BA.merkle()`, root at top, leaf labels
- [x] Terminal — render `ba_terminal` with colours by level, auto-scroll
- [x] All users — table: user, role, requests, approved, rejected, last activity
- [x] CSV export of the audit log (admin only) — button on Chain explorer
- [x] Print-friendly report view — admin/report.html
- [ ] Aadi tests all of Part 2 with Live Server

### Part 3 — Live Nakamoto network across browser tabs (decided, not started)
- Each browser tab = one node with its own chain copy (move node chain to per-tab storage;
  keep sessions working).
- Nodes talk over the **BroadcastChannel** API (same origin, no server).
- User requests go into a shared mempool; nodes race to mine; first valid block wins.
- Forks resolve by the chain with the **most cumulative work**; show reorganisations.
- Every node validates incoming blocks (hash, PoW, link, ACL) and rejects bad ones.
- Admin **Network** page: nodes online, each node's tip, forks, reorgs.
- Demos: **51% attack** (attacker tab mines a private chain with a speed setting, then releases it)
  and **Byzantine node** (a tab broadcasts a fake APPROVED block; honest nodes reject it).
- Honest limits for the report: one browser on one machine, simulated hash power.
  Difficulty may need to rise to `0000` so forks stay readable.
- This replaces the simulated 3-vote consensus with real nodes, and closes the
  "Nakamoto Consensus" gap in the syllabus mapping.

### Report track (Aadi writes it; you may help with drafts if asked)
- Rules: exactly 2 objectives, minimum 10 pages, methodology diagram covering everything,
  results explained (why they look that way), minimum 15 references incl. research papers,
  prompt engineering documented in an appendix, abstract at the END (under 150 words).
- Known gaps: Sybil-attack prevention is mapped in the syllabus table but not implemented —
  either add a light version or word it as "discussed". Digital signatures are now implemented.

## 9. Progress log (newest at top — add a line after every change)

- 2026-10-23 — Logo blends in: made `nfsu-logo-dark.png` / `nfsu-crest.png` (white background
  transparent, navy lettering light, red tagline light red, shield keeps its colours); white cards
  removed. Report shows the dark version on screen and the original only in print (`.rp-logo-print`).
  Fixed stray "null" text: native `Element.append(null)` writes the word "null" (unlike `ui.el`,
  which skips nulls) — in the Merkle proof panel and the Tamper test block detail. Use `''` there.
  Headless-Chrome tested at 1440/390 px and print; no "null", no JS/CSP errors.

- 2026-10-23 — NFSU logo added: full logo above the title on the login page and at the top of
  admin/report.html (prints too); crest replaces the 🔐 mark in the topbar on every page (`UI.topbar`).
  Logo is navy on white, so `.login-logo` / `.brand-crest` / `.rp-logo` give it a white card.
  Source: Aadi's `Pictures\nfsu.png` (378×133). Headless-Chrome tested at 1440 and 390 px and print:
  all images load, no JS/CSP errors.

- 2026-10-23 — Added `PROGRESS_REPORT.md`: plain-language summary of everything done so far
  (timeline, results table, limits, future work, suggested slide outline) for Aadi's PPT.
  Not committed yet.
- 2026-10-23 — Made a 5-slide summary deck (Claude Slides artifact) with headless-Chrome screenshots.
  Found: Merkle proof box shows a stray "null" line under the green result (admin-merkle.js) — to fix.

- 2026-10-22 — Merkle tree redrawn as an SVG diagram: lines from every node to its parent,
  Sideways (default, fits the page) / Top-down toggle, legend, record name + result on each leaf.
  Clicking a record shows its Merkle proof: the sibling hashes, each step recomputed with SHA-256,
  and whether the rebuilt root matches; a changed record also says it no longer proves the
  original root. Headless-Chrome screenshots checked at 1366 and 390 px, no JS errors.

- 2026-10-22 — Part 2 built. Digital signatures: ECDSA P-256 keys derived from passwords
  (`SIG_SALTS` in auth.js, `BA.PUBKEYS` in core.js), every request and admin-page attempt
  signed, signature included in the block hash, `BA.checkBlock()` shared by validate/explorer/ledger.
  New admin pages: tamper, consensus, merkle, terminal, users, report; CSV export on Chain explorer
  (cells starting = + - @ get a leading '). Admin nav has 8 links → `.topbar-wide` puts them on
  their own row. Headless-Chrome tested: seed still VALID (all 'legacy'); all 3 user keys match;
  signed request VALID; requester / status edit + re-mine → caught as sig invalid; signature
  stripped + re-mine → sig missing; legacy block edit + re-mine → NOT caught (shown honestly on the
  tamper page); failed login unsigned and VALID; user opening admin page → bounced, signed block;
  all 8 admin pages render with no JS errors; screenshots at 1366, 1024 and 390 px checked.

- 2026-10-22 — Starter chain: copied the 19 blocks, votes and terminal log from Aadi's Live Server
  browser into `assets/data/seed.json`. `BA.loadSeed()` in `core.js` fetches it when the browser
  has no chain, runs `BA.validate()` on it and only then stores chain, clean copy, meta and log;
  otherwise genesis is mined as before. Signing key, lockouts and sessions are not copied.
  Tested on a fresh origin (localhost:8000): 19 blocks VALID, no console errors, reload keeps data.
  Each visitor's browser then grows its own copy — new blocks are not shared between visitors.

- 2026-10-02 — README: added "Pages" and "Honest limits" sections.
- 2026-10-02 — Added Public ledger for users: `user/ledger.html`, `assets/js/user-ledger.js`,
  "Public ledger" in `UI.userNav`, `.lg-*` styles. Every block shows hash, previous hash,
  nonce, 3 checks, VALID/TAMPERED; own blocks show name/resource/reason + YOU badge, others
  show "Another user" / "Hidden resource". Verify chain button recomputes all hashes in the
  user's browser and logs the result. Rule 5 updated. Headless-Chrome tested as Rohan with
  block #2 edited: BROKEN, red card with stored vs computed hash, Kavya's name not shown.
  Known weakness noted for the report: at difficulty 000 an attacker can re-mine every block
  after an edit and the chain validates again — fixed only by multiple nodes (Part 3).

- 2026-10-02 — Built Chain explorer (the 10-01 entry below was planned but the files were
  never saved): `admin/chain.html`, `assets/js/admin-chain.js`, nav entry in `ui.js`,
  `.cx-*` styles in `style.css`. Per block: full hash + previous hash with Copy, nonce,
  3 checks (hash matches data / starts with 000 / linked to parent), node votes with the
  random-vote node marked, stored vs recomputed hash on a TAMPERED card. Filter, search,
  order, Re-check button, auto re-check when another tab changes the chain.
  Headless-Chrome tested with block #1 requester changed to "Hacker": status BROKEN,
  seal "Chain broken at #1", red card with both hashes. Aadi still to test with Live Server.
- 2026-10-02 — Added `CLAUDE.md` (this file) for Claude Code.
- 2026-09-30 — Part 1 built: multi-page site, PBKDF2 login, lockout, signed sessions,
  per-user ACL, user pages, admin overview, Docker + nginx headers. Browser-tested.
