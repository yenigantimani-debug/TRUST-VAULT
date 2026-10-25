# TrustVault — AI Work Log

Keep this file in the repository while working. The commit URL fields below must be replaced with actual GitHub commit URLs after making each commit. Do not invent links or claim tests passed unless they were run.

## 2026-10-23 — Flask setup and authentication
- **What I asked:** Help me build and debug a Flask document-sharing application with registration and sign-in.
- **What the tool produced:** Flask setup, route, and template guidance.
- **What was wrong / what I checked:** Generated changes must match the actual routes and templates; a project can render while individual endpoints still fail.
- **What I did instead:** Checked the existing Flask route names and templates, retained the existing authentication design, and verified the app's syntax.
- **Commit:** TODO — add the real commit URL.

## 2026-10-24 — Authorization: sharing controls
- **What I asked:** Enforce the admin, owner, and viewer roles for document sharing.
- **What the tool produced:** General role-based UI and server-side access guidance.
- **What was wrong / what I checked:** Hiding a “Manage access” link is not security; a viewer can call the route directly unless the server rejects the request.
- **What I did instead:** Added direct-route tests for viewer and unrelated-owner attempts to open or POST to sharing routes. The test suite must be run in an environment with requirements installed before claiming these tests pass.
- **Commit:** TODO — add the real commit URL.

## 2026-10-24 — Authorization: document ID tampering
- **What I asked:** Stop users from downloading documents that were not shared with them.
- **What the tool produced:** A document permission helper and listing/download routes.
- **What was wrong / what I checked:** The old helper allowed every signed-in user to access records marked unrestricted. That could expose legacy document metadata and downloads without an explicit grant.
- **What I did instead:** Changed access to fail closed: admins and owners retain access, while other users need a share record. Legacy unrestricted records are migrated to restricted access. Added tests for direct download and document-list visibility.
- **Commit:** TODO — add the real commit URL.

## 2026-10-25 — UI regression and preservation
- **What I asked:** Make the workspace match the dark green/emerald reference.
- **What the tool produced:** CSS intended to style the Documents page, then a full stylesheet replacement.
- **What was wrong:** The replacement did not preserve the full shared layout and authentication styling, so parts of the UI appeared unstyled or changed.
- **What I did instead:** Added shared layout styles and checked the page templates. The live browser appearance still needs manual verification after running the app.
- **Commit:** TODO — add the real commit URL.

## 2026-10-25 — Audit trail and authorization tests
- **What I asked:** Ensure only administrators can see activity logs and record denied sharing attempts.
- **What the tool produced:** An admin-only logs route and audit event helper.
- **What was wrong / what I checked:** An audit trail should not be called immutable or tamper-proof unless there is an implementation and evidence for that claim. Authorization denials should be observable.
- **What I did instead:** Kept the logs route server-side admin-only and added logging for denied share-management and document-delete attempts, plus a test for non-admin log access. The logs are database-backed and are not immutable against a database administrator.
- **Commit:** TODO — add the real commit URL.

## 2026-10-25 — Release readiness
- **What I asked:** Prepare TrustVault for public deployment and evaluation.
- **What the tool produced:** Deployment and security checklist guidance.
- **What was wrong / what I checked:** A public URL alone does not prove secure deployment; secret keys, encrypted-file storage, and SQLite persistence must be configured deliberately.
- **What I did instead:** Added a Gunicorn start command and Render configuration template. Configure both secret environment variables manually, and do not store real confidential files on an ephemeral free filesystem.
- **Commit:** TODO — add the real commit URL.

## Before submission
- Commit this file early and update it as work progresses.
- Replace each TODO with a real commit URL.
- Correct any entry that does not match what actually happened.
- Run the tests and record their actual results.
