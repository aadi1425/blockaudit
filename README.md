# BlockAudit

Blockchain-based access audit system (IAM) with SHA-256 Proof of Work.

## Run in VS Code
1. Open this folder in VS Code.
2. Install the "Live Server" extension.
3. Right-click `index.html` → Open with Live Server.

Do not double-click `index.html`; the security policy blocks scripts on `file://`.

## Run with Docker
```bash
docker build -t blockaudit .
docker run -d -p 8080:80 --name blockaudit blockaudit
```
Open http://localhost:8080. To stop: `docker stop blockaudit && docker rm blockaudit`

## Demo accounts
| User  | Password  | Role  |
|-------|-----------|-------|
| Arjun | arjun@99  | User  |
| Kavya | kavya@99  | User  |
| Rohan | rohan@99  | User  |
| Aadi  | admin@999 | Admin |

## Pages
- Users: Request access, My history, **Public ledger** — every block's hash and checks,
  verifiable by anyone; names and resources shown only on your own blocks.
- Admin: Overview, **Chain explorer** — every block in full, node votes, signature, live re-check,
  stored vs recomputed hash for tampered blocks, **CSV export**.
- Admin: **Tamper test** (edit a record, re-mine like an attacker, validate, reset),
  **Consensus** (every vote, faulty node marked), **Merkle tree** (root on top, changed path in red),
  **Terminal** (backend log), **Users** (per-account activity and keys), **Report** (print / save as PDF).

## Digital signatures
Each user has an ECDSA P-256 key pair. The private key is derived from the password at login
(PBKDF2, separate salt) and kept only in that tab's session; the public keys are published in
`core.js`. Every access record (`requester|resource|status|timestamp`) is signed before it is
mined, and the signature is part of the block hash. Changing who, what or the result breaks the
signature, even if the attacker re-mines the whole chain.

## Honest limits
- Logins are checked in the browser; a real deployment would check them on a server.
- The Public ledger hides other users' names on screen only; the full chain is in localStorage.
- Every visitor starts from the same starter chain (`assets/data/seed.json`, checked before use);
  after that each browser keeps its own copy, so new blocks are not shared between visitors.
- One chain copy in one browser: someone with DevTools could edit a block and re-mine
  every block after it (difficulty `000` is fast). Signatures stop this for signed blocks, but
  blocks #1–#18 (made before signatures) and failed-login blocks are unsigned, and an attacker can
  still delete the newest blocks. Multiple nodes (planned) close these gaps.
- The signing key is derived from a demo password and kept in sessionStorage while signed in;
  a real system would keep it in a hardware key or wallet.

## Security
- Browser: PBKDF2 password hashes, 5-try lockout (60 s), HMAC-signed sessions,
  page guards, idle/session timeouts, CSP, no innerHTML, chain + signature check on every page,
  ECDSA-signed records, CSV export protected against formula injection.
- Server (Docker/nginx): CSP with frame-ancestors, X-Frame-Options, nosniff,
  Referrer-Policy, Permissions-Policy, hidden server version.
