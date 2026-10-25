# TrustVault Secure Prototype (Flask)

This replaces the client-only demo authentication with server-verified accounts, server-enforced roles, CSRF checks, audit logs, SQLite metadata, and AES-256-GCM encryption for uploaded file bytes.

## Requirements
- Python 3.10+
- pip

## 1. Create an environment and install packages

Windows PowerShell:
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Windows Command Prompt:
```bat
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Set secret keys

Generate two independent keys; do not commit them to Git or share them.

Python can generate them:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the first output as `TRUSTVAULT_SECRET_KEY` and the second as `TRUSTVAULT_ENCRYPTION_KEY`.

PowerShell (replace values with your generated outputs):
```powershell
$env:TRUSTVAULT_SECRET_KEY="FIRST_64_HEX_CHARACTERS"
$env:TRUSTVAULT_ENCRYPTION_KEY="SECOND_64_HEX_CHARACTERS"
```

Command Prompt:
```bat
set TRUSTVAULT_SECRET_KEY=FIRST_64_HEX_CHARACTERS
set TRUSTVAULT_ENCRYPTION_KEY=SECOND_64_HEX_CHARACTERS
```

Linux/macOS:
```bash
export TRUSTVAULT_SECRET_KEY="FIRST_64_HEX_CHARACTERS"
export TRUSTVAULT_ENCRYPTION_KEY="SECOND_64_HEX_CHARACTERS"
```

The encryption key must be preserved securely. If it is lost, encrypted uploads cannot be recovered. Do not store production keys in source code or in the same backup as encrypted files.

## 3. Create the first administrator

With the virtual environment active and the two environment variables set:

Windows:
```powershell
flask --app app create-admin
```

Linux/macOS:
```bash
flask --app app create-admin
```

Follow the prompts. Public sign-ups always create Viewer accounts. A user cannot grant themselves Admin privileges through the UI.

## 4. Start the application

```bash
flask --app app run
```
Open http://127.0.0.1:5000

For production, install dependencies and run the included Gunicorn command (`gunicorn app:app`). `Procfile` and `render.yaml` provide a Render starting point. Configure `TRUSTVAULT_SECRET_KEY` and `TRUSTVAULT_ENCRYPTION_KEY` in the host's environment settings; the encryption key must be exactly 64 hexadecimal characters (32 bytes). Set `TRUSTVAULT_HTTPS=1` only behind HTTPS. Create the first admin through `flask --app app create-admin` in a secure one-off shell or local environment connected to the intended database.

**Persistence warning:** this starter uses a local SQLite database and local encrypted-upload directory. A free web host may erase these on redeploy/restart. Do not upload confidential files to a deployment until persistent storage or a managed database/object-storage design is configured and verified. A live demo URL is not proof that file persistence or production security is configured.

For local development only. Before internet deployment, use HTTPS and a production WSGI server, set `TRUSTVAULT_HTTPS=1`, configure rate limiting, backups, monitoring, secure secret storage, and a hardened deployment environment. Do not use Flask's development server in production.

## Security behavior and current limits
- Passwords are hashed using Werkzeug's password-hashing functions; passwords are not stored as plaintext.
- Session cookies are HttpOnly and SameSite=Lax. CSRF tokens are checked on state-changing requests.
- All new public registrations have Viewer role. Admin-only routes check the role on the server.
- Uploads are size-limited to 20 MiB and filtered by filename extension. File bytes are encrypted with AES-256-GCM using a fresh nonce per file before disk storage. Downloads are decrypted only after access checks.
- Metadata (title, description, owner, category, original filename) is not encrypted in the database.
- This starter is not a full security audit: no email verification, password reset, MFA, login rate limiting, malware scanning, immutable remote audit log, key rotation, or account/session management UI yet. Add these before handling sensitive or regulated documents.
- Set `TRUSTVAULT_HTTPS=1` only when served over HTTPS. Use a reverse proxy / production WSGI server for deployment.
- Run security tests with `python -m unittest discover -s tests -v` after installing requirements.
- Do not upload sensitive documents to an internet-facing instance until it has been reviewed and hardened.
