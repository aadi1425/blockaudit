# BlockAudit — Progress Report (for the PPT)

**Last updated:** 23 October 2026
**Project:** BlockAudit: A Blockchain-Based Resource Access Integrity and Tamper-Evident
Audit Trail System with Consensus Validation
**Short title:** BlockAudit — IAM on Blockchain
**Student:** Aadi, MSc Cybersecurity, NFSU Goa
**Course:** Blockchain Technology — 25-mark mini project
**Live site:** https://aadi1425.github.io/blockaudit/
**Code:** https://github.com/aadi1425/blockaudit

---

## 1. Problem and idea (slide: "Why BlockAudit?")

- In normal systems, access logs sit in a database. An insider (or attacker) with database
  access can quietly delete or edit a log line to hide what they did.
- BlockAudit is an **Identity & Access Management (IAM)** website where every access request —
  **approved or rejected** — is written into a **SHA-256 Proof-of-Work blockchain**.
- If anyone edits or deletes a record, the hash chain breaks and the system shows exactly
  which block was changed.
- Normal users only see "Access Granted / Denied". The admin (auditor) sees everything.

## 2. The two objectives (use exactly this wording)

1. To design and implement a blockchain-based access logging system using SHA-256 hashing
   and Proof of Work that creates a tamper-evident audit trail of all resource access
   requests — authorized and unauthorized.
2. To demonstrate integrity violation detection by simulating unauthorized resource access
   and an attempt to conceal it through record tampering, and proving that the blockchain's
   hash pointer chain exposes any such manipulation automatically.

**Status: both objectives achieved and demonstrated on the live site.**

## 3. Technology used (slide: "Tech stack")

| Part | What we used |
|------|--------------|
| Front end | Plain HTML + CSS + vanilla JavaScript (no frameworks, no build step) |
| Hashing | SHA-256 via the browser's WebCrypto API |
| Proof of Work | Nonce search until the hash starts with `000` (difficulty 3) |
| Passwords | PBKDF2 hashes (never stored as plain text) |
| Digital signatures | ECDSA P-256 (WebCrypto), keys derived from the password |
| Sessions | HMAC-signed sessions, idle 10 min / max 30 min timeouts |
| Storage | Browser localStorage (chain) + sessionStorage (login session) |
| Hosting | GitHub Pages (live), Docker + nginx (with security headers), VS Code Live Server |
| Size | ~3,260 lines of code across 15 JS files, 12 HTML pages, 1 CSS file |

## 4. Users, resources and access rules (slide: "Who can access what")

| User | Role | Allowed resources |
|------|------|-------------------|
| Arjun | User | Project Atlas, Ops Manual |
| Kavya | User | Finance Ledger, HR Vault, Ops Manual |
| Rohan | User | Project Atlas, Finance Ledger, Ops Manual |
| Aadi | Admin | Monitors only — cannot request resources |

- **Classified Intel** → nobody is allowed (always denied).
- Also written to the chain as REJECTED blocks: **failed logins** and a **normal user trying
  to open an admin page**.

## 5. How one request works (slide: methodology / flow diagram)

1. User logs in (PBKDF2 password check, 5 wrong tries → locked 60 s).
2. User picks a resource and submits.
3. **Consensus:** 3 nodes vote. Node 1 and Node 2 are honest (follow the access list).
   Node 3 is "faulty" — 20% chance of a random vote. **2 of 3 YES = APPROVED.**
4. The record (`who | what | result | time`) is **digitally signed** with the user's private key.
5. The block is **mined**: nonce goes up until SHA-256 hash starts with `000`.
6. Block is linked to the previous block's hash and added to the chain.
7. Every page re-checks the whole chain on load: hash matches data, starts with `000`,
   linked to parent, signature valid. Any failure → red **"Chain broken at #N"** seal.

**Block format:** `index, timestamp, requester, resource, status, previousHash, nonce, hash, signature`

## 6. Everything completed — timeline

### 30 Sept 2026 — Part 1 built
- Multi-page website: login page, user pages, admin overview.
- PBKDF2 password hashes, 5-try lockout, signed sessions, page guards, idle/session timeouts.
- Per-user access control list (ACL).
- Docker + nginx with security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy,
  Permissions-Policy, hidden server version).

### 2 Oct 2026 — Explorer + public ledger
- **Chain explorer (admin):** every block in full — hash, previous hash, nonce, node votes,
  3 live checks, filter/search/order, Copy buttons. A tampered block shows a red card with
  **stored hash vs recomputed hash** side by side.
- **Public ledger (users):** every user can see every block's hashes and verify the chain
  themselves. Other users' names/resources are hidden ("Another user" / "Hidden resource").
- README: added "Pages" and "Honest limits" sections.
- Session timeouts checked against NIST / PCI-DSS / OWASP guidance
  (idle 10 min ✔, session 30 min ✔, lockout 60 s is shorter than PCI's 30 min → a demo value).
- Self-critique written: this is a **permissioned blockchain with an auditor role**, not a
  fully decentralised one; an attacker who re-mines every block after an edit could pass
  validation → fixes planned: digital signatures (done) + multi-node network (Part 3).

### 22 Oct 2026 — Testing + GitHub + Part 2
- **Full testing with VS Code Live Server — all passed:**
  - Logged in as each user; blocks mined; Granted/Denied matched the access list.
  - Admin view checked.
  - Tamper test: edited a block → chain showed BROKEN at that block (then restored).
  - Typing an admin URL as a normal user → bounced back, attempt recorded on the chain.
  - 5 wrong passwords → account locked for 60 s.
  - Works at phone width.
- **GitHub:** code pushed to github.com/aadi1425/blockaudit (public).
- **GitHub Pages LIVE** at https://aadi1425.github.io/blockaudit/
- **Starter chain:** the 19 blocks from testing are shipped in `assets/data/seed.json`,
  so every new visitor starts with real data (checked for validity before loading).
  Starter chain stats: **19 blocks — 7 APPROVED, 12 REJECTED** (7 failed logins,
  2 Classified Intel denials, 1 admin-page attempt by a user, etc.); 1 block where the
  faulty Node 3 voted randomly.
- **Part 2 built (all of it):**
  - **Digital signatures (ECDSA P-256):** each user signs every request; the signature is
    part of the block hash. Changing who / what / the result breaks the signature — even if
    the attacker re-mines the whole chain.
  - **Tamper test page:** pick a block, change it, "Re-mine" like a smart attacker, Validate,
    Reset. Shows CAUGHT or NOT CAUGHT honestly.
  - **Consensus page:** every request with the 3 node votes; faulty-node votes marked.
  - **Merkle tree page:** real SVG tree diagram (sideways or top-down). Click any record →
    its **Merkle proof** (sibling hashes, each step recomputed, root matches or not).
    Changed records show in red.
  - **Terminal page:** backend log, coloured by level, filter, auto-follow.
  - **Users page:** per-account activity, access list, public key.
  - **Report page:** printable audit report (Print / Save as PDF).
  - **CSV export** of the audit log on the Chain explorer (protected against
    spreadsheet formula injection).
  - Tested in headless Chrome: all 8 admin pages load with no errors; signed request VALID;
    edit + re-mine of a signed block → caught (signature invalid); signature removed →
    caught (signature missing); screenshots checked at desktop, laptop and phone sizes.

### 23 Oct 2026 — Part 2 published
- Part 2 + new Merkle tree pushed to GitHub; **all Part 2 pages verified live** on GitHub Pages.

## 7. Results to show (slide: "Results")

| Test | Result |
|------|--------|
| Allowed request (e.g. Rohan → Ops Manual) | Granted, block mined, VALID |
| Not-allowed request (e.g. Rohan → HR Vault) | Denied with reason, still recorded |
| Classified Intel request | Always denied ("needs top-secret clearance") |
| User opens admin URL | Bounced back + REJECTED block recorded |
| 5 wrong passwords | Locked 60 s, each failure recorded |
| Edit a block (no re-mine) | **CAUGHT** — hash mismatch, "Chain broken at #N" |
| Edit a signed block + re-mine whole chain | **CAUGHT** — signature invalid |
| Remove signature + re-mine | **CAUGHT** — signature missing |
| Edit an old unsigned block (#1–18) + re-mine | **NOT CAUGHT** — shown honestly; fixed by Part 3 |
| Merkle proof for a record | Root rebuilt and matches |

**Why it works:** each block's hash includes the previous block's hash, so changing one
block changes its hash and breaks the link to the next one. Proof of Work makes re-mining
cost effort, and signatures make re-mining useless for signed blocks because the attacker
does not have the user's private key.

## 8. Honest limits (slide: "Limitations")

- Logins are checked in the browser; a real system would check them on a server.
- The Public ledger hides other users' names on screen only; the full chain is in localStorage.
- Each browser keeps its own chain copy after the starter chain — new blocks are not shared
  between visitors.
- Single chain copy: someone with DevTools could re-mine old unsigned blocks (#1–18) or
  delete the newest blocks. Multi-node network (Part 3) closes this.
- Signing key comes from a demo password; a real system would use a hardware key / wallet.
- Lockout of 60 s is a demo value (PCI-DSS suggests 30 min).
- Sybil-attack prevention is discussed, not implemented.

## 9. What is left (slide: "Future work")

1. **Report screenshots** — Tamper CAUGHT / NOT CAUGHT, a chain card with signature,
   Merkle proof, Consensus page, Report PDF. (Use `python -m http.server 8000` for an
   error-free console screenshot.)
2. **Part 3 — Live Nakamoto network across browser tabs:**
   each tab = one node with its own chain; nodes talk via BroadcastChannel; shared mempool;
   nodes race to mine; forks resolved by most cumulative work; admin Network page;
   demos of a **51% attack** and a **Byzantine node** sending a fake block.
3. **Written report:** 2 objectives, 10+ pages, methodology diagram, results explained,
   15+ references (incl. research papers), prompt-engineering appendix, abstract at the end
   (under 150 words).

## 10. Suggested PPT outline (about 12–14 slides)

1. Title slide (title, name, course, NFSU Goa)
2. Problem: logs can be edited by insiders
3. Objectives (the 2 official ones)
4. Proposed solution: IAM + blockchain audit trail
5. Tech stack
6. Users, resources and access rules
7. Methodology / flow diagram (login → consensus → sign → mine → link → validate)
8. Block structure + SHA-256 + Proof of Work
9. Digital signatures + consensus (3 nodes, faulty node)
10. Screenshots: user request + public ledger
11. Screenshots: admin chain explorer, Merkle tree + proof
12. Tamper test demo: CAUGHT vs NOT CAUGHT
13. Results table + security features
14. Limitations + future work (Part 3 network)
15. Conclusion + live demo link / QR code
