import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask, abort, flash, g, redirect, render_template, request, send_file,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
UPLOAD_DIR = INSTANCE / "encrypted_uploads"
DB_PATH = INSTANCE / "trustvault.sqlite3"
INSTANCE.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY", ""),
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,  # 20 MiB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)
if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError(
        "Set TRUSTVAULT_SECRET_KEY to a random value of at least 32 characters. "
        "See README.md."
    )

def encryption_key():
    raw = os.environ.get("TRUSTVAULT_ENCRYPTION_KEY", "")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError("TRUSTVAULT_ENCRYPTION_KEY must be 64 hex characters.") from exc
    if len(key) != 32:
        raise RuntimeError("TRUSTVAULT_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return key

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','owner','viewer')),
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      owner_id INTEGER NOT NULL REFERENCES users(id),
      original_filename TEXT,
      encrypted_filename TEXT,
      content_type TEXT,
      size_bytes INTEGER NOT NULL DEFAULT 0,
      restricted INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id),
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT ''
    );
    """)
    # Fail closed for legacy records that were created before sharing grants existed.
    # Owners and admins retain access; other users need an explicit document_shares row.
    db.execute("UPDATE documents SET restricted=1 WHERE restricted=0")
    # Migrate older TrustVault databases whose role constraint only allowed admin/viewer.
    role_sql = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()[0]
    if "'owner'" not in role_sql:
        db.commit()
        db.execute("PRAGMA foreign_keys = OFF")
        db.executescript("""
        CREATE TABLE users_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','owner','viewer')),
          created_at TEXT NOT NULL
        );
        INSERT INTO users_new(id,username,email,password_hash,role,created_at)
          SELECT id,username,email,password_hash,role,created_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
        """)
        db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS document_shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
      granted_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL,
      UNIQUE(document_id,user_id)
    );
    """)
    db.commit()

@app.before_request
def initialize_and_csrf():
    init_db()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(str(session.get("csrf_token", "")), str(supplied)):
            abort(400, description="Invalid or missing CSRF token.")

@app.context_processor
def inject_globals():
    return {"csrf_token": session.get("csrf_token", ""), "current_user": current_user()}

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()

def log_event(action, status="SUCCESS", detail=""):
    user = current_user()
    username = user["username"] if user else "Guest"
    user_id = user["id"] if user else None
    get_db().execute(
        "INSERT INTO audit_logs(created_at,user_id,username,action,status,detail) VALUES(?,?,?,?,?,?)",
        (now_iso(), user_id, username, action, status, detail[:300])
    )
    get_db().commit()

def can_access_document(user, doc, required="read"):
    if not user or not doc:
        return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    share = get_db().execute(
        "SELECT permission FROM document_shares WHERE document_id=? AND user_id=?",
        (doc["id"], user["id"])
    ).fetchone()
    if not share:
        return False
    return required == "read" or share["permission"] == "edit"

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if user["role"] != "admin":
            log_event("ACCESS_DENIED", "DENIED", request.path)
            abort(403)
        return view(*args, **kwargs)
    return wrapped

CATEGORIES = ["Finance", "HR", "Legal", "IT", "Education", "Personal", "General", "Other"]
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "csv", "png", "jpg", "jpeg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user() else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not (3 <= len(username) <= 50):
            flash("Username must be between 3 and 50 characters.", "error")
        elif len(password) < 12:
            flash("Password must be at least 12 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (username, email, generate_password_hash(password), "viewer", now_iso())
                )
                db.commit()
                row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                log_event("ACCOUNT_REGISTER", detail=f"user_id={row['id']}")
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                get_db().rollback()
                flash("Username or email is already registered.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
            (identity, identity)
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            log_event("LOGIN", "DENIED", "Invalid credentials")
            flash("Invalid username/email or password.", "error")
        else:
            session.clear()
            session["user_id"] = row["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            log_event("LOGIN", detail="Authenticated")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("LOGOUT")
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    db = get_db()
    if user["role"] == "admin":
        docs_count = db.execute("SELECT COUNT(*) n FROM documents").fetchone()["n"]
        logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8").fetchall()
        users_count = db.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    else:
        docs_count = db.execute(
            "SELECT COUNT(DISTINCT d.id) n FROM documents d LEFT JOIN document_shares s ON s.document_id=d.id AND s.user_id=? WHERE d.owner_id=? OR s.user_id IS NOT NULL",
            (user["id"], user["id"])
        ).fetchone()["n"]
        logs = []
        users_count = None
    return render_template("dashboard.html", docs_count=docs_count, logs=logs, users_count=users_count)

@app.route("/categories")
@login_required
def categories():
    descriptions = {
        "Finance": "Financial records and reports",
        "HR": "People and workplace documents",
        "Legal": "Contracts and legal records",
        "IT": "Technical and system documentation",
        "Education": "Learning and academic files",
        "Personal": "Personal documents",
        "General": "General workspace documents",
        "Other": "Other categorized files",
    }
    return render_template("categories.html", categories=CATEGORIES, descriptions=descriptions)

@app.route("/documents")
@login_required
def documents():
    user = current_user()
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "ALL")
    sql = """SELECT DISTINCT d.*, u.username owner_name FROM documents d
             JOIN users u ON u.id=d.owner_id
             LEFT JOIN document_shares s ON s.document_id=d.id AND s.user_id=?
             WHERE (d.owner_id=? OR s.user_id IS NOT NULL)"""
    params = [user["id"], user["id"]]
    if user["role"] == "admin":
        sql = """SELECT d.*, u.username owner_name FROM documents d
                 JOIN users u ON u.id=d.owner_id WHERE 1=1"""
        params = []
    if q:
        sql += " AND (d.title LIKE ? OR d.description LIKE ? OR u.username LIKE ?)"
        params.extend([f"%{q}%"] * 3)
    if category != "ALL" and category in CATEGORIES:
        sql += " AND d.category=?"
        params.append(category)
    sql += " ORDER BY d.id DESC"
    rows = get_db().execute(sql, params).fetchall()
    return render_template("documents.html", documents=rows, categories=CATEGORIES, q=q, category=category)

@app.route("/documents/upload", methods=["GET", "POST"])
@login_required
def upload():
    if current_user()["role"] not in {"admin", "owner"}:
        log_event("DOCUMENT_UPLOAD", "DENIED", "role_not_permitted")
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "General")
        description = request.form.get("description", "").strip()
        file = request.files.get("file")
        if not title or not description or category not in CATEGORIES:
            flash("Please provide a title, description, and valid category.", "error")
            return render_template("upload.html", categories=CATEGORIES)
        encrypted_name = None
        original_name = None
        content_type = None
        size = 0
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Unsupported file type.", "error")
                return render_template("upload.html", categories=CATEGORIES)
            original_name = secure_filename(file.filename)
            plaintext = file.read()
            if len(plaintext) > app.config["MAX_CONTENT_LENGTH"]:
                abort(413)
            nonce = os.urandom(12)
            encrypted = nonce + AESGCM(encryption_key()).encrypt(nonce, plaintext, None)
            encrypted_name = secrets.token_hex(24) + ".bin"
            (UPLOAD_DIR / encrypted_name).write_bytes(encrypted)
            content_type = file.mimetype or "application/octet-stream"
            size = len(plaintext)
        user = current_user()
        get_db().execute(
            """INSERT INTO documents(title,category,description,owner_id,original_filename,
               encrypted_filename,content_type,size_bytes,restricted,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (title, category, description, user["id"], original_name, encrypted_name,
             content_type, size, 1, now_iso())
        )
        get_db().commit()
        log_event("DOCUMENT_UPLOAD", detail=title)
        flash("Document metadata saved and attached file encrypted at rest.", "success")
        return redirect(url_for("documents"))
    return render_template("upload.html", categories=CATEGORIES)

@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    user = current_user()
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    if not can_access_document(user, doc, "read"):
        log_event("DOCUMENT_DOWNLOAD", "DENIED", f"document_id={doc_id}")
        abort(403)
    if not doc["encrypted_filename"]:
        flash("This record has no attached file.", "warning")
        return redirect(url_for("documents"))
    path = UPLOAD_DIR / doc["encrypted_filename"]
    try:
        blob = path.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        plaintext = AESGCM(encryption_key()).decrypt(nonce, ciphertext, None)
    except Exception:
        app.logger.exception("Could not decrypt stored file")
        abort(500, description="Could not decrypt file. Check the encryption key and file integrity.")
    log_event("DOCUMENT_DOWNLOAD", detail=doc["title"])
    return send_file(
        BytesIO(plaintext), as_attachment=True,
        download_name=doc["original_filename"] or "document",
        mimetype=doc["content_type"] or "application/octet-stream"
    )

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    user = current_user()
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_event("DOCUMENT_DELETE", "DENIED", f"document_id={doc_id}")
        abort(403)
    filename = doc["encrypted_filename"]
    title = doc["title"]
    db.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    db.commit()
    if filename:
        try:
            (UPLOAD_DIR / filename).unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Unable to remove encrypted file after document deletion")
    log_event("DOCUMENT_DELETE", detail=f"document_id={doc_id}; title={title}")
    flash("Document deleted.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/sharing", methods=["GET", "POST"])
@login_required
def sharing(doc_id):
    user = current_user()
    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        log_event("SHARE_MANAGE", "DENIED", f"document_id={doc_id}")
        abort(403)
    if request.method == "POST":
        action = request.form.get("action", "grant")
        if action not in {"grant", "revoke"}:
            abort(400, description="Invalid sharing action.")
        target = request.form.get("username", "").strip()
        target_user = db.execute("SELECT id, username FROM users WHERE username=? COLLATE NOCASE", (target,)).fetchone()
        if action == "revoke":
            if not target_user:
                flash("User was not found.", "error")
            else:
                db.execute("DELETE FROM document_shares WHERE document_id=? AND user_id=?", (doc_id, target_user["id"]))
                db.commit()
                log_event("SHARE_REVOKE", detail=f"document_id={doc_id}; user={target_user['username']}")
                flash("Access revoked.", "success")
        elif not target_user:
            flash("Enter an existing user's username.", "error")
        elif target_user["id"] == doc["owner_id"]:
            flash("The owner already has full access.", "warning")
        else:
            permission = request.form.get("permission", "read")
            if permission not in {"read", "edit"}:
                permission = "read"
            db.execute("""INSERT INTO document_shares(document_id,user_id,permission,granted_by,created_at)
                          VALUES(?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET
                          permission=excluded.permission, granted_by=excluded.granted_by, created_at=excluded.created_at""",
                       (doc_id, target_user["id"], permission, user["id"], now_iso()))
            db.commit()
            log_event("SHARE_GRANT", detail=f"document_id={doc_id}; user={target_user['username']}; permission={permission}")
            flash(f"{permission.title()} access granted to {target_user['username']}.", "success")
        return redirect(url_for("sharing", doc_id=doc_id))
    shares = db.execute("""SELECT s.permission,s.created_at,u.username,u.email FROM document_shares s
                           JOIN users u ON u.id=s.user_id WHERE s.document_id=? ORDER BY u.username""", (doc_id,)).fetchall()
    return render_template("sharing.html", document=doc, shares=shares)

@app.route("/admin/logs")
@admin_required
def logs():
    rows = get_db().execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("logs.html", logs=rows)

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="File is too large. Maximum size is 20 MiB."), 413

@app.cli.command("make-owner")
def make_owner():
    """Promote an existing registered account to document owner."""
    init_db()
    username = input("Existing username to make owner: ").strip()
    row = get_db().execute("SELECT id FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    if not row:
        raise SystemExit("User not found. Register the account first.")
    get_db().execute("UPDATE users SET role='owner' WHERE id=?", (row["id"],))
    get_db().commit()
    print(f"{username} is now an owner.")

@app.cli.command("create-admin")
def create_admin():
    """Create an administrator account interactively."""
    init_db()
    username = input("Admin username: ").strip()
    email = input("Admin email: ").strip().lower()
    import getpass
    password = getpass.getpass("Admin password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    try:
        get_db().execute(
            "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            (username, email, generate_password_hash(password), "admin", now_iso())
        )
        get_db().commit()
        print("Admin account created.")
    except sqlite3.IntegrityError:
        raise SystemExit("Username or email already exists.")

if __name__ == "__main__":
    app.run(debug=False)
