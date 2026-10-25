"""TrustVault - secure multi-tenant document sharing with RBAC and a tamper-evident audit trail."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
INSTANCE = os.environ.get("TV_INSTANCE", os.path.join(BASE, "instance"))
os.makedirs(os.path.join(INSTANCE, "uploads"), exist_ok=True)

ROLES = ("admin", "owner", "viewer")
CATEGORIES = ("Contracts", "Finance", "HR", "Legal", "Reports", "Other")
ALLOWED = {"pdf", "txt", "csv", "png", "jpg", "jpeg", "docx", "xlsx", "pptx"}
MAGIC = {"pdf": b"%PDF", "png": b"\x89PNG", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
         "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "pptx": b"PK\x03\x04"}
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
MAX_FAILS, FAIL_WINDOW = 5, timedelta(minutes=10)
GENESIS = "0" * 64

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


def _secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(INSTANCE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip()


app.config.update(
    SECRET_KEY=_secret(),
    DATABASE=os.path.join(INSTANCE, "trustvault.db"),
    UPLOAD_DIR=os.path.join(INSTANCE, "uploads"),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TV_INSECURE_COOKIES") != "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    TESTING=False,
)

# ------------------------------------------------------------------ database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(
  id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL,
  filename TEXT NOT NULL, stored_name TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares(
  doc_id TEXT NOT NULL REFERENCES documents(id), user_id INTEGER NOT NULL REFERENCES users(id),
  permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
  granted_by INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(doc_id,user_id));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_id INTEGER, actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT NOT NULL, ts TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_attempts ON attempts(k, ts);
"""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], timeout=15, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    con = sqlite3.connect(app.config["DATABASE"])
    con.executescript(SCHEMA)
    if not con.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        pw = os.environ.get("ADMIN_PASSWORD")
        if not pw:
            pw = secrets.token_urlsafe(14)
            print(f"[TrustVault] generated admin password: {pw}", flush=True)
        con.execute("INSERT INTO users(username,email,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
                    ("admin", "admin@trustvault.local", generate_password_hash(pw), "admin", now()))
    con.commit()
    con.close()


# --------------------------------------------------------------- audit trail
def _digest(prev, ts, actor_id, actor, action, target, detail, ip):
    payload = json.dumps([prev, ts, actor_id, actor, action, target, detail, ip], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def audit(action, target=None, detail=None, user=None):
    """Append to a hash-chained log. Each row commits to the previous row's hash."""
    user = user if user is not None else getattr(g, "user", None)
    actor_id = user["id"] if user else None
    actor = user["username"] if user else "anonymous"
    ip = request.remote_addr if request else None
    con = db()
    con.execute("BEGIN IMMEDIATE")
    try:
        row = con.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        ts = now()
        h = _digest(prev, ts, actor_id, actor, action, target, detail, ip)
        con.execute("INSERT INTO audit(ts,actor_id,actor,action,target,detail,ip,prev_hash,hash) "
                    "VALUES(?,?,?,?,?,?,?,?,?)", (ts, actor_id, actor, action, target, detail, ip, prev, h))
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise


def verify_chain(con=None):
    """Return (ok, first_bad_id, rows_checked)."""
    con = con or db()
    prev, n = GENESIS, 0
    for r in con.execute("SELECT * FROM audit ORDER BY id"):
        n += 1
        expect = _digest(r["prev_hash"], r["ts"], r["actor_id"], r["actor"], r["action"],
                         r["target"], r["detail"], r["ip"])
        if r["prev_hash"] != prev or r["hash"] != expect:
            return False, r["id"], n
        prev = r["hash"]
    return True, None, n


# ------------------------------------------------------- auth / csrf / hooks
@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        u = db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
        if u:
            g.user = u
        else:
            session.clear()
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
        if not hmac.compare_digest(sent, session.get("csrf", "")):
            audit("csrf_rejected", request.path)
            abort(400, "Invalid or missing CSRF token.")


@app.context_processor
def inject():
    return {"csrf": session.get("csrf", ""), "me": g.get("user"), "CATEGORIES": CATEGORIES,
            "endpoint": request.endpoint}


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'self'; img-src 'self' data:; "
                                               "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


def roles_required(*roles):
    def deco(f):
        @wraps(f)
        @login_required
        def w(*a, **k):
            if g.user["role"] not in roles:
                audit("access_denied", request.path, f"role {g.user['role']} needs {'/'.join(roles)}")
                abort(403)
            return f(*a, **k)
        return w
    return deco


# ----------------------------------------------------- object-level access
def get_doc_or_404(doc_id):
    d = db().execute("SELECT d.*, u.username AS owner FROM documents d JOIN users u ON u.id=d.owner_id "
                     "WHERE d.id=?", (doc_id,)).fetchone()
    if not d:
        abort(404)
    return d


def access_level(doc, user):
    """'admin' | 'owner' | 'edit' | 'read' | None. The single source of truth for document access."""
    if user["role"] == "admin":
        return "admin"
    if doc["owner_id"] == user["id"]:
        return "owner"
    s = db().execute("SELECT permission FROM shares WHERE doc_id=? AND user_id=?",
                     (doc["id"], user["id"])).fetchone()
    if not s:
        return None
    # defence in depth: a viewer-role account can never hold edit rights
    return "read" if (user["role"] == "viewer" and s["permission"] == "edit") else s["permission"]


def require(doc_id, need):
    """need: 'read' | 'edit' | 'manage'. Returns (doc, level) or aborts 403 and audits the denial."""
    d = get_doc_or_404(doc_id)
    lvl = access_level(d, g.user)
    ok = {"read": lvl is not None, "edit": lvl in ("admin", "owner", "edit"),
          "manage": lvl in ("admin", "owner")}[need]
    if not ok:
        audit("access_denied", d["id"], f"needed {need}, had {lvl}")
        abort(403)
    return d, lvl


ACCESSIBLE = ("(d.owner_id=:uid OR d.id IN (SELECT doc_id FROM shares WHERE user_id=:uid) OR :admin=1)")


# --------------------------------------------------------------- file checks
def validate_upload(f):
    if not f or not f.filename:
        return None, "Choose a file."
    name = secure_filename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        return None, f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED))}."
    data = f.read()
    if not data:
        return None, "File is empty."
    if ext in MAGIC and not data.startswith(MAGIC[ext]):
        return None, "File content does not match its extension."
    if ext in ("txt", "csv"):
        try:
            data[:8192].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                return None, "Text files must be UTF-8."
    return (name, data), None


def store(data):
    stored = uuid.uuid4().hex
    with open(os.path.join(app.config["UPLOAD_DIR"], stored), "wb") as fh:
        fh.write(data)
    return stored


def remove_file(stored):
    try:
        os.remove(os.path.join(app.config["UPLOAD_DIR"], stored))
    except OSError:
        pass


def clean(s, n):
    return (s or "").strip()[:n]


# ------------------------------------------------------------------ auth views
def throttled(keys):
    since = (datetime.now(timezone.utc) - FAIL_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    for k, limit in keys:
        c = db().execute("SELECT COUNT(*) c FROM attempts WHERE k=? AND ts>?", (k, since)).fetchone()["c"]
        if c >= limit:
            return True
    return False


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user and g.user["role"] == "admin" else
                            "documents" if g.user else "login"))


DUMMY_HASH = generate_password_hash("not-a-real-password")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        uname = clean(request.form.get("username"), 64).lower()
        pw = request.form.get("password", "")[:256]
        keys = [(f"u:{uname}", MAX_FAILS), (f"ip:{request.remote_addr}", MAX_FAILS * 4)]
        if throttled(keys):
            audit("login_locked", uname, user={"id": None, "username": uname})
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429
        u = db().execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        ok = check_password_hash(u["pw_hash"] if u else DUMMY_HASH, pw) and u is not None and u["active"]
        if ok:
            session.clear()  # prevents session fixation
            session["uid"] = u["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            session.permanent = True
            db().execute("DELETE FROM attempts WHERE k=?", (f"u:{uname}",))
            audit("login", detail="success", user=u)
            return redirect(url_for("index"))
        now_ = now()
        for k, _ in keys:
            db().execute("INSERT INTO attempts(k,ts) VALUES(?,?)", (k, now_))
        audit("login_failed", uname, user={"id": None, "username": uname})
        flash("Invalid username or password.", "error")  # identical message either way
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        uname, email = clean(request.form.get("username"), 32), clean(request.form.get("email"), 320)
        pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
        role = request.form.get("role", "owner")
        err = None
        if not USER_RE.match(uname):
            err = "Username: 3-32 letters, digits, . _ -"
        elif not EMAIL_RE.match(email):
            err = "Enter a valid email."
        elif len(pw) < 10 or len(pw) > 128:
            err = "Password must be 10-128 characters."
        elif pw != pw2:
            err = "Passwords do not match."
        elif role not in ("owner", "viewer"):  # admin can never be self-selected
            err = "Choose a valid account type."
        if not err:
            try:
                db().execute("INSERT INTO users(username,email,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
                             (uname, email, generate_password_hash(pw), role, now()))
            except sqlite3.IntegrityError:
                err = "That username or email is already registered."
        if err:
            flash(err, "error")
            return render_template("register.html"), 400
        u = db().execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        audit("register", uname, f"role={role}", user=u)
        flash("Account created. Please sign in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------- dashboard
@app.route("/dashboard")
@roles_required("admin")
def dashboard():
    c = db()
    day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {
        "docs": c.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        "users": c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "shares": c.execute("SELECT COUNT(*) FROM shares").fetchone()[0],
        "events": c.execute("SELECT COUNT(*) FROM audit WHERE ts>?", (day,)).fetchone()[0],
        "failed": c.execute("SELECT COUNT(*) FROM audit WHERE ts>? AND action IN "
                            "('login_failed','access_denied','login_locked')", (day,)).fetchone()[0],
    }
    ok, bad, n = verify_chain()
    recent = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", stats=stats, chain_ok=ok, chain_n=n, recent=recent)


# ------------------------------------------------------------------ documents
@app.route("/documents")
@login_required
def documents():
    c = db()
    mine = c.execute("SELECT d.*, u.username AS owner FROM documents d JOIN users u ON u.id=d.owner_id "
                     "WHERE d.owner_id=? ORDER BY d.created_at DESC", (g.user["id"],)).fetchall()
    shared = c.execute("SELECT d.*, u.username AS owner, s.permission FROM shares s "
                       "JOIN documents d ON d.id=s.doc_id JOIN users u ON u.id=d.owner_id "
                       "WHERE s.user_id=? ORDER BY d.created_at DESC", (g.user["id"],)).fetchall()
    return render_template("documents.html", mine=mine, shared=shared)


@app.route("/search")
@login_required
def search():
    q = {k: clean(request.args.get(k), 100) for k in ("q", "category", "owner", "date_from", "date_to")}
    sql = ("SELECT d.*, u.username AS owner FROM documents d JOIN users u ON u.id=d.owner_id "
           f"WHERE {ACCESSIBLE}")
    p = {"uid": g.user["id"], "admin": 1 if g.user["role"] == "admin" else 0}
    if q["q"]:
        sql += " AND (d.title LIKE :q ESCAPE '\\' OR d.filename LIKE :q ESCAPE '\\')"
        p["q"] = "%" + q["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    if q["category"] in CATEGORIES:
        sql += " AND d.category=:cat"
        p["cat"] = q["category"]
    if q["owner"]:
        sql += " AND u.username LIKE :own ESCAPE '\\'"
        p["own"] = "%" + q["owner"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    if re.match(r"^\d{4}-\d{2}-\d{2}$", q["date_from"]):
        sql += " AND d.created_at>=:df"
        p["df"] = q["date_from"]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", q["date_to"]):
        sql += " AND d.created_at<:dt"
        p["dt"] = (datetime.strptime(q["date_to"], "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    rows = db().execute(sql + " ORDER BY d.created_at DESC LIMIT 200", p).fetchall()
    return render_template("search.html", rows=rows, q=q)


@app.route("/categories")
@login_required
def categories():
    p = {"uid": g.user["id"], "admin": 1 if g.user["role"] == "admin" else 0}
    counts = {r["category"]: r["n"] for r in db().execute(
        f"SELECT category, COUNT(*) n FROM documents d WHERE {ACCESSIBLE} GROUP BY category", p)}
    return render_template("categories.html", counts=counts)


@app.route("/upload", methods=["GET", "POST"])
@roles_required("admin", "owner")
def upload():
    if request.method == "POST":
        title = clean(request.form.get("title"), 150)
        cat = request.form.get("category")
        res, err = validate_upload(request.files.get("file"))
        if not title:
            err = "Title is required."
        elif cat not in CATEGORIES:
            err = "Choose a category."
        if err:
            flash(err, "error")
            return render_template("upload.html"), 400
        name, data = res
        did = uuid.uuid4().hex
        db().execute("INSERT INTO documents(id,owner_id,title,description,category,filename,stored_name,"
                     "size,sha256,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (did, g.user["id"], title, clean(request.form.get("description"), 1000), cat, name,
                      store(data), len(data), hashlib.sha256(data).hexdigest(), now(), now()))
        audit("upload", did, f"{name} ({len(data)} bytes)")
        flash("Document uploaded. Now choose who can access it.")
        return redirect(url_for("document", doc_id=did))
    return render_template("upload.html")


@app.route("/documents/<doc_id>")
@login_required
def document(doc_id):
    d, lvl = require(doc_id, "read")
    shares = []
    if lvl in ("admin", "owner"):
        shares = db().execute("SELECT s.*, u.username, u.role FROM shares s JOIN users u ON u.id=s.user_id "
                              "WHERE s.doc_id=? ORDER BY u.username", (doc_id,)).fetchall()
    audit("view", doc_id)
    return render_template("document.html", d=d, lvl=lvl, shares=shares)


@app.route("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    d, _ = require(doc_id, "read")
    audit("download", doc_id, d["filename"])
    return send_file(os.path.join(app.config["UPLOAD_DIR"], d["stored_name"]), as_attachment=True,
                     download_name=secure_filename(d["filename"]) or "download",
                     mimetype="application/octet-stream")


@app.route("/documents/<doc_id>/edit", methods=["POST"])
@login_required
def edit(doc_id):
    d, _ = require(doc_id, "edit")
    title, cat = clean(request.form.get("title"), 150), request.form.get("category")
    if not title or cat not in CATEGORIES:
        flash("Title and a valid category are required.", "error")
        return redirect(url_for("document", doc_id=doc_id))
    stored, size, sha, fname = d["stored_name"], d["size"], d["sha256"], d["filename"]
    f = request.files.get("file")
    if f and f.filename:
        res, err = validate_upload(f)
        if err:
            flash(err, "error")
            return redirect(url_for("document", doc_id=doc_id))
        fname, data = res
        remove_file(stored)
        stored, size, sha = store(data), len(data), hashlib.sha256(data).hexdigest()
    db().execute("UPDATE documents SET title=?,description=?,category=?,filename=?,stored_name=?,size=?,"
                 "sha256=?,updated_at=? WHERE id=?",
                 (title, clean(request.form.get("description"), 1000), cat, fname, stored, size, sha, now(), doc_id))
    audit("edit", doc_id, "file replaced" if f and f.filename else "metadata")
    flash("Document updated.")
    return redirect(url_for("document", doc_id=doc_id))


@app.route("/documents/<doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    d, _ = require(doc_id, "manage")
    db().execute("DELETE FROM shares WHERE doc_id=?", (doc_id,))
    db().execute("DELETE FROM documents WHERE id=?", (doc_id,))
    remove_file(d["stored_name"])
    audit("delete", doc_id, d["filename"])
    flash("Document deleted.")
    return redirect(url_for("documents"))


@app.route("/documents/<doc_id>/share", methods=["POST"])
@login_required
def share(doc_id):
    d, _ = require(doc_id, "manage")
    uname, perm = clean(request.form.get("username"), 32), request.form.get("permission")
    t = db().execute("SELECT * FROM users WHERE username=? AND active=1", (uname,)).fetchone()
    if perm not in ("read", "edit"):
        flash("Choose read or edit.", "error")
    elif not t or t["id"] == d["owner_id"]:
        flash("No such active user (or they already own this document).", "error")
    elif t["role"] == "admin":
        flash("Admins already have full access.", "error")
    elif t["role"] == "viewer" and perm == "edit":
        flash("Viewer accounts can only be given read access.", "error")
    else:
        db().execute("INSERT INTO shares(doc_id,user_id,permission,granted_by,created_at) VALUES(?,?,?,?,?) "
                     "ON CONFLICT(doc_id,user_id) DO UPDATE SET permission=excluded.permission, "
                     "granted_by=excluded.granted_by", (doc_id, t["id"], perm, g.user["id"], now()))
        audit("share", doc_id, f"{t['username']}:{perm}")
        flash(f"Granted {perm} access to {t['username']}.")
    return redirect(url_for("document", doc_id=doc_id))


@app.route("/documents/<doc_id>/revoke", methods=["POST"])
@login_required
def revoke(doc_id):
    require(doc_id, "manage")
    try:
        uid = int(request.form.get("user_id", ""))
    except ValueError:
        abort(400)
    t = db().execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    cur = db().execute("DELETE FROM shares WHERE doc_id=? AND user_id=?", (doc_id, uid))
    if cur.rowcount:
        audit("revoke", doc_id, t["username"] if t else str(uid))
        flash("Access revoked.")
    return redirect(url_for("document", doc_id=doc_id))


# ----------------------------------------------------------- admin-only views
@app.route("/logs")
@roles_required("admin")
def logs():
    action = clean(request.args.get("action"), 40)
    sql, p = "SELECT * FROM audit", []
    if action:
        sql += " WHERE action=?"
        p.append(action)
    rows = db().execute(sql + " ORDER BY id DESC LIMIT 300", p).fetchall()
    ok, bad, n = verify_chain()
    actions = [r[0] for r in db().execute("SELECT DISTINCT action FROM audit ORDER BY 1")]
    return render_template("logs.html", rows=rows, ok=ok, bad=bad, n=n, actions=actions, action=action)


@app.route("/users")
@roles_required("admin")
def users():
    rows = db().execute("SELECT u.*, (SELECT COUNT(*) FROM documents WHERE owner_id=u.id) docs "
                        "FROM users u ORDER BY u.id").fetchall()
    return render_template("users.html", rows=rows)


@app.route("/users/<int:uid>/role", methods=["POST"])
@roles_required("admin")
def set_role(uid):
    role = request.form.get("role")
    t = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not t or role not in ROLES:
        abort(400)
    if t["id"] == g.user["id"]:
        flash("You cannot change your own role.", "error")
    else:
        db().execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        if role == "viewer":  # downgrade any edit grants immediately
            db().execute("UPDATE shares SET permission='read' WHERE user_id=?", (uid,))
        audit("role_change", t["username"], f"{t['role']} -> {role}")
        flash("Role updated.")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/active", methods=["POST"])
@roles_required("admin")
def set_active(uid):
    t = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not t:
        abort(404)
    if t["id"] == g.user["id"]:
        flash("You cannot disable your own account.", "error")
    else:
        new = 0 if t["active"] else 1
        db().execute("UPDATE users SET active=? WHERE id=?", (new, uid))
        audit("account_enabled" if new else "account_disabled", t["username"])
        flash("Account updated.")
    return redirect(url_for("users"))


# --------------------------------------------------------------------- profile
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        cur, new, new2 = (request.form.get(k, "") for k in ("current", "new", "new2"))
        if not check_password_hash(g.user["pw_hash"], cur):
            flash("Current password is incorrect.", "error")
        elif len(new) < 10 or len(new) > 128 or new != new2:
            flash("New password must be 10-128 characters and match the confirmation.", "error")
        else:
            db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), g.user["id"]))
            audit("password_change")
            session["csrf"] = secrets.token_urlsafe(32)
            flash("Password updated.")
        return redirect(url_for("profile"))
    return render_template("profile.html")


# ---------------------------------------------------------------------- errors
MESSAGES = {400: "Bad request.", 403: "You do not have permission to do that.", 404: "Not found.",
            413: "File too large (10 MB max).", 429: "Too many requests.", 500: "Something went wrong."}


def _err(e):
    code = getattr(e, "code", 500) or 500
    return render_template("error.html", code=code, msg=MESSAGES.get(code, "Error.")), code


for _c in MESSAGES:
    app.register_error_handler(_c, _err)


@app.errorhandler(Exception)
def _unhandled(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return _err(e)
    app.logger.exception(e)
    return render_template("error.html", code=500, msg=MESSAGES[500]), 500


init_db()
