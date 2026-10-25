# TrustVault — Threat model

**Assets:** confidential documents, the role/permission model, the audit trail, user credentials.
**Actors:** anonymous visitor, authenticated owner/viewer acting beyond their rights, malicious document owner, compromised or curious insider, admin-account attacker.
**Trust boundaries:** browser ↔ app; app ↔ SQLite/disk; owner ↔ shared user.

| # | Threat | Where | Mitigation (code) | Test |
|---|---|---|---|---|
| T1 | **IDOR** — guess/enumerate a document ID to read or download it | `/documents/<id>`, `/download` | UUID ids; every route calls `require()` → `access_level()`; denial → 403 + audit | `test_stranger_cannot_read_download_or_see_in_search` |
| T2 | **Privilege escalation** — non-owner shares/revokes/deletes/edits | share, revoke, delete, edit | `require(doc,'manage'/'edit')`; owner or admin only for manage | `test_stranger_cannot_share_revoke_delete_edit`, `test_share_read_then_revoke` |
| T3 | **Self-registering as admin** / mass assignment of `role` | `/register` | Whitelist `owner`/`viewer`; admin only seeded or granted by admin | `test_cannot_self_register_as_admin` |
| T4 | **Viewer gains write** via an edit share or by uploading | upload, share | Viewer cannot reach `/upload`; edit grant to viewer refused; role downgrade strips edit grants; `access_level` caps viewers at read | `test_viewer_cannot_upload_or_get_edit` |
| T5 | **Admin-only surface exposed** (logs, users, dashboard) | `/logs` `/users` `/dashboard` | `@roles_required('admin')` on route + denial audited | `test_non_admin_blocked_from_admin_pages_and_actions` |
| T6 | **Search/category leakage** — results or counts reveal inaccessible docs | `/search`, `/categories` | Single `ACCESSIBLE` SQL predicate applied to every listing query | `test_stranger_cannot_read…`, `test_sql_injection_in_search` |
| T7 | **Credential attacks** — brute force, user enumeration, timing | `/login` | scrypt hashes; 5 failures/10 min per username + per IP lockout; same message and dummy-hash timing for unknown users | `test_bad_login_generic_message_and_lockout` |
| T8 | **Session fixation / CSRF** | all state changes | `session.clear()` on login; per-session CSRF token on every POST; SameSite=Lax, HttpOnly, Secure cookies | `test_csrf_required` |
| T9 | **Stale access** — disabled/demoted user keeps session | every request | User re-loaded from DB each request; `active=0` kills the session immediately | `test_disabled_user_session_dies` |
| T10 | **Malicious upload** — script/HTML, disguised type, path traversal | `/upload`, `/edit` | Extension allow-list + magic bytes; 10 MB cap; stored under random name; `secure_filename`; served only as `attachment` + `nosniff` | `test_upload_rejects…`, `test_path_traversal_filename_neutralised` |
| T11 | **XSS / injection** | all templates & queries | Jinja autoescape; strict CSP (`default-src 'none'`, no JS at all); parameterised SQL only; LIKE wildcards escaped | `test_xss_title_escaped`, `test_headers` |
| T12 | **Audit tampering / repudiation** — admin or attacker edits the log | `audit` table | SHA-256 hash chain; each row commits to the previous; `/logs` and dashboard re-verify the whole chain on every view | `test_audit_tamper_detected` |
| T13 | **Silent denials** — attacks leave no trace | all | Login success/fail/lockout, register, view, download, upload, edit, share, revoke, delete, role change, password change, **access_denied**, **csrf_rejected** are all logged with actor + IP | `test_audit_records_denials_and_chain_verifies` |
| T14 | **Clickjacking / MIME sniffing / referrer leaks** | responses | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, `no-referrer`, HSTS, `no-store` | `test_headers` |

## Known gaps (honest list)
- **Hash chain is tamper-*evident*, not tamper-*proof*:** someone with full DB write access could recompute the entire chain. Mitigation in production: periodically anchor the latest hash off-system.
- Files are stored unencrypted on the server disk; Render free-tier disk is ephemeral (data resets on redeploy/restart).
- No email verification, MFA, or password-reset flow.
- Rate limiting is DB-backed per username/IP; a distributed attacker can still try many usernames slowly.
- Registration reveals whether a username/email is taken; sharing reveals whether a username exists (to authenticated owners only).
- No antivirus scanning of uploads.
- Profile image upload not implemented (avatar is the user's initial).
