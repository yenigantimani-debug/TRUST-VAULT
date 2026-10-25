# PROMPTS.md — how I used AI (keep this updated AS YOU WORK)

> Rules for every entry: real date/time · what I asked · what the tool produced · **what was wrong** · what I did instead · commit link.
> "The AI was helpful" scores nothing. Write only what actually happened.

## Entry template
### YYYY-MM-DD HH:MM — <short title>
- **Asked:** …
- **Produced:** …
- **Wrong / risky:** … (be specific: file, line, behaviour you proved)
- **I did:** … 
- **Commit:** <link>

---
## Entries to write (do these checks yourself, then record what you really found)

1. **Authorisation (required topic).** Open `app.py` → `access_level()` and `require()`. Try to break them: log in as user B and request user A's `/documents/<id>`, `/download`, `/share`, `/delete`. Record what happened and anything you changed.
2. **Authorisation / roles (required topic).** Try registering with `role=admin` by editing the form request; try a viewer uploading; try an owner opening `/logs`. Record results and any fix.
3. **Audit trail (required topic).** Open the SQLite DB, edit one `audit` row, reload `/logs` → should show CHAIN BROKEN. Record whether it did and what you'd improve.
4. **Your own earlier AI mistakes** — from your write-up: wrong colours (neon yellow vs emerald), unnecessary files. Add the dated entry with the commit where you fixed them.
5. **Deployment.** Record any Render/Vercel build errors the tool's instructions caused and how you resolved them.
6. **Tests.** Run `python -m unittest discover -s tests`; if any test was wrong or too weak, note it.
