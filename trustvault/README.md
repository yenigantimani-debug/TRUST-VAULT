# TrustVault — Secure sharing, smarter access, verifiable accountability

Multi-tenant document sharing with **admin / owner / viewer** roles, per-document **read/edit** grants,
and a **hash-chained audit log**. Flask + SQLite, zero JavaScript, strict CSP.

**Live:** _add your URL here_ · **Repo:** _add your GitHub URL here_

## Roles
| Role | Can do |
|---|---|
| **admin** | Everything: dashboard, all documents, user management (role/disable), activity logs |
| **owner** | Upload, edit, delete own documents; grant/revoke read or edit to other users; read what is shared with them |
| **viewer** | Read/download documents shared with them. Cannot upload or hold edit rights |

Any other attempt to manage access returns **403** and is written to the audit log.
Self-registration offers only owner/viewer; the single seeded admin is `admin` with the `ADMIN_PASSWORD` env var
(a random password is printed to the server log if unset).

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
ADMIN_PASSWORD='choose-a-strong-one' TV_INSECURE_COOKIES=1 python run.py   # http://127.0.0.1:5000
python -m unittest discover -s tests -v                                     # 20 security tests
```
(`TV_INSECURE_COOKIES=1` lets the session cookie work over plain http on localhost; never set it in production.)

## Deploy (Render, free, no card)
1. Push to GitHub. 2. Render → New → **Blueprint** → select the repo (`render.yaml` is picked up).
3. Open the service's *Environment* tab to read the generated `ADMIN_PASSWORD`. 

## Layout
`app.py` (routes, access control, audit) · `templates/` · `static/style.css` · `tests/test_security.py` · `THREATS.md` · `PROMPTS.md`

## Limitations
Free-tier storage is ephemeral; see "Known gaps" in `THREATS.md`.
