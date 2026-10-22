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
- Admin: Overview, **Chain explorer** — every block in full, node votes, live re-check,
  stored vs recomputed hash for tampered blocks.

## Honest limits
- Logins are checked in the browser; a real deployment would check them on a server.
- The Public ledger hides other users' names on screen only; the full chain is in localStorage.
- Every visitor starts from the same starter chain (`assets/data/seed.json`, checked before use);
  after that each browser keeps its own copy, so new blocks are not shared between visitors.
- One chain copy in one browser: someone with DevTools could edit a block and re-mine
  every block after it (difficulty `000` is fast). Multiple nodes (planned) close this gap.

## Security
- Browser: PBKDF2 password hashes, 5-try lockout (60 s), HMAC-signed sessions,
  page guards, idle/session timeouts, CSP, no innerHTML, chain integrity check on every page.
- Server (Docker/nginx): CSP with frame-ancestors, X-Frame-Options, nosniff,
  Referrer-Policy, Permissions-Policy, hidden server version.
