# TrustVault Threat Model

## Scope
TrustVault is a Flask application for encrypted file uploads and role-based document sharing. This is a threat model and test plan, not a certification or claim that every control is complete.

## Assets
- Document contents and encrypted files
- Document metadata and owner identities
- User passwords, session cookies, CSRF tokens, and application keys
- Sharing grants and revocations
- Activity logs and role assignments

## Threats and required checks

| Threat | Attack | Mitigation / expected behavior | Test |
|---|---|---|---|
| IDOR / cross-user access | Change a document ID in a download URL | Every route checks access to that specific document | Unshared viewer downloads another user's document; expect 403 |
| Unauthorized sharing | Viewer or unrelated owner posts to sharing route | Only admin or that document's owner can grant/revoke | Direct GET and POST as viewer/unrelated owner; expect 403 |
| Privilege escalation | Submit `role=admin` at registration | Server assigns a safe role; ignores client role | Register with admin role field; stored role must be viewer |
| Metadata leakage | Search/list unrestricted legacy records | Listing only includes owned/shared records (admins see all) | Viewer list must not contain another user's unshared title |
| Unauthorized deletion | POST another owner's document ID | Only admin or document owner can delete | Direct POST as viewer/unrelated owner; expect 403 |
| CSRF | Submit state-changing request without token | Require valid CSRF token for POST/PUT/PATCH/DELETE | Missing token must return 400 |
| Session compromise | Steal or reuse session cookie | HttpOnly, SameSite, secure cookies under HTTPS; clear session at logout | Inspect deployed cookie flags; verify logout removes auth session |
| Unsafe upload | Upload unsupported or oversized file | Extension allowlist and 20 MiB request limit; generated encrypted filename | Test unsupported extension and oversize body |
| Secret exposure | Commit secret/encryption key | Keys supplied through environment, never source control | Search Git history and deployed environment configuration |
| Audit-log access | Non-admin requests `/admin/logs` | Admin-only server-side guard | Owner/viewer request; expect 403 |
| Audit-log gaps/tampering | Security denials not recorded or DB logs altered | Record security-relevant actions; restrict log viewing | Trigger denied actions and inspect events; note SQLite logs are not immutable |
| Production persistence | Free host restarts and loses local SQLite/files | Use persistent storage or managed database/object storage before real use | Restart deployment and verify test data persists |

## Intended authorization matrix

| Action | Admin | Document owner | Shared viewer | Unrelated user |
|---|---|---|---|---|
| List/download | All documents | Own and explicitly shared documents | Only active shares | No |
| Grant/revoke | Yes | Own documents only | No | No |
| Delete | Yes | Own documents only | No | No |
| View activity logs | Yes | No | No | No |
| Assign admin role | Controlled admin operation only | No | No | No |

## Audit events
The app should record registration, login success/failure, logout, upload, download, share grant/revoke, deletion, and denied authorization attempts. Logs include timestamp, actor, action, outcome, and limited details. Never log passwords, secret keys, session tokens, or document contents.

## Known limitations to disclose
- Logs are stored in SQLite and are not tamper-proof against someone who can modify the database.
- No MFA, password reset, login throttling, malware scanning, or key rotation is implemented in this starter.
- Metadata is not encrypted, even though uploaded file bytes are encrypted.
- A free hosting service's local filesystem may be ephemeral. Do not use the deployed demo for confidential documents unless persistent storage and backups are configured.
- Run the test suite and record results before marking a control as passed.
