"""Security tests - each maps to a threat in THREATS.md. Run: python -m unittest discover -s tests -v"""
import io, os, re, shutil, sqlite3, tempfile, unittest

_tmp = tempfile.mkdtemp()
os.environ.update(TV_INSTANCE=_tmp, SECRET_KEY="test", ADMIN_PASSWORD="AdminPass-12345", TV_INSECURE_COOKIES="1")
os.makedirs(os.path.join(_tmp, "uploads"), exist_ok=True)
import app as tv  # noqa: E402

PDF = b"%PDF-1.4 hello"


class Client:
    def __init__(self):
        self.c = tv.app.test_client()

    def token(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        m = re.search(r'name="csrf" value="([^"]+)"', html)
        return m.group(1) if m else ""

    def post(self, path, data=None, page="/profile", **kw):
        d = dict(data or {})
        d.setdefault("csrf", self.token(page))
        return self.c.post(path, data=d, **kw)

    def login(self, u, p):
        return self.c.post("/login", data={"username": u, "password": p, "csrf": self.token()})


def make_user(name, role="owner", pw="Password-12345"):
    c = Client()
    r = c.c.post("/register", data={"username": name, "email": f"{name}@x.io", "password": pw,
                                    "password2": pw, "role": role, "csrf": c.token("/register")})
    assert r.status_code == 302, r.get_data(as_text=True)
    assert c.login(name, pw).status_code == 302
    return c


def upload(c, title="Doc", data=PDF, name="a.pdf"):
    r = c.c.post("/upload", data={"title": title, "category": "Legal", "csrf": c.token("/upload"),
                                  "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    assert r.status_code == 302, r.get_data(as_text=True)
    return r.headers["Location"].rsplit("/", 1)[-1]


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob = make_user("alice"), make_user("bob")
        cls.vic = make_user("vic", "viewer")
        cls.admin = Client(); assert cls.admin.login("admin", "AdminPass-12345").status_code == 302
        cls.doc = upload(cls.alice, "Alice secret")

    # --- authentication / session
    def test_anonymous_redirected(self):
        for p in ("/documents", "/search", "/upload", f"/documents/{self.doc}", f"/documents/{self.doc}/download", "/logs"):
            self.assertEqual(Client().c.get(p).status_code, 302, p)

    def test_bad_login_generic_message_and_lockout(self):
        c = Client()
        a = c.login("alice", "wrong").get_data(as_text=True)
        b = c.login("nobody-here", "wrong").get_data(as_text=True)
        self.assertIn("Invalid username or password", a); self.assertIn("Invalid username or password", b)
        for _ in range(6):
            r = c.login("locktest", "x")
        self.assertEqual(r.status_code, 429)

    def test_cannot_self_register_as_admin(self):
        c = Client()
        r = c.c.post("/register", data={"username": "evil", "email": "e@x.io", "password": "Password-12345",
                                        "password2": "Password-12345", "role": "admin", "csrf": c.token("/register")})
        self.assertEqual(r.status_code, 400)

    def test_csrf_required(self):
        self.assertEqual(self.alice.c.post(f"/documents/{self.doc}/delete").status_code, 400)
        self.assertEqual(self.alice.c.post("/logout", data={"csrf": "bad"}).status_code, 400)

    # --- authorization (IDOR / privilege)
    def test_stranger_cannot_read_download_or_see_in_search(self):
        self.assertEqual(self.bob.c.get(f"/documents/{self.doc}").status_code, 403)
        self.assertEqual(self.bob.c.get(f"/documents/{self.doc}/download").status_code, 403)
        self.assertNotIn("Alice secret", self.bob.c.get("/search?q=secret").get_data(as_text=True))
        self.assertNotIn("Alice secret", self.bob.c.get("/documents").get_data(as_text=True))

    def test_stranger_cannot_share_revoke_delete_edit(self):
        for path, data in ((f"/documents/{self.doc}/share", {"username": "bob", "permission": "read"}),
                           (f"/documents/{self.doc}/revoke", {"user_id": "1"}),
                           (f"/documents/{self.doc}/delete", {}),
                           (f"/documents/{self.doc}/edit", {"title": "pwn", "category": "Legal"})):
            self.assertEqual(self.bob.post(path, data).status_code, 403, path)

    def test_unknown_doc_is_404(self):
        self.assertEqual(self.alice.c.get("/documents/" + "0" * 32).status_code, 404)

    def test_share_read_then_revoke(self):
        d = upload(self.alice, "Shared one")
        self.alice.post(f"/documents/{d}/share", {"username": "bob", "permission": "read"}, page=f"/documents/{d}")
        self.assertEqual(self.bob.c.get(f"/documents/{d}/download").status_code, 200)
        self.assertEqual(self.bob.post(f"/documents/{d}/edit", {"title": "x", "category": "Legal"}).status_code, 403)
        self.assertEqual(self.bob.post(f"/documents/{d}/share", {"username": "vic", "permission": "read"}).status_code, 403)
        uid = tv.sqlite3.connect(tv.app.config["DATABASE"]).execute("SELECT id FROM users WHERE username='bob'").fetchone()[0]
        self.alice.post(f"/documents/{d}/revoke", {"user_id": uid}, page=f"/documents/{d}")
        self.assertEqual(self.bob.c.get(f"/documents/{d}/download").status_code, 403)

    def test_edit_permission_allows_edit_but_not_share(self):
        d = upload(self.alice, "Editable")
        self.alice.post(f"/documents/{d}/share", {"username": "bob", "permission": "edit"}, page=f"/documents/{d}")
        self.assertEqual(self.bob.post(f"/documents/{d}/edit", {"title": "bob edit", "category": "Legal"}).status_code, 302)
        self.assertEqual(self.bob.post(f"/documents/{d}/delete").status_code, 403)
        self.assertEqual(self.bob.post(f"/documents/{d}/share", {"username": "vic", "permission": "read"}).status_code, 403)

    def test_viewer_cannot_upload_or_get_edit(self):
        r = self.vic.c.post("/upload", data={"title": "t", "category": "Legal", "csrf": self.vic.token("/documents"),
                                             "file": (io.BytesIO(PDF), "a.pdf")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 403)
        d = upload(self.alice, "ForVic")
        self.alice.post(f"/documents/{d}/share", {"username": "vic", "permission": "edit"}, page=f"/documents/{d}")
        self.assertEqual(self.vic.c.get(f"/documents/{d}").status_code, 403)  # edit grant to viewer refused

    def test_non_admin_blocked_from_admin_pages_and_actions(self):
        for p in ("/logs", "/dashboard", "/users"):
            self.assertEqual(self.alice.c.get(p).status_code, 403, p)
        self.assertEqual(self.alice.post("/users/1/role", {"role": "owner"}).status_code, 403)
        self.assertEqual(self.alice.post("/users/1/active").status_code, 403)

    def test_admin_can_access_everything(self):
        self.assertEqual(self.admin.c.get(f"/documents/{self.doc}/download").status_code, 200)
        self.assertEqual(self.admin.c.get("/logs").status_code, 200)

    def test_disabled_user_session_dies(self):
        c = make_user("temp1")
        uid = tv.sqlite3.connect(tv.app.config["DATABASE"]).execute("SELECT id FROM users WHERE username='temp1'").fetchone()[0]
        self.admin.post(f"/users/{uid}/active", page="/users")
        self.assertEqual(c.c.get("/documents").status_code, 302)

    # --- uploads
    def test_upload_rejects_bad_type_and_disguised_content(self):
        for data, name in ((b"<script>alert(1)</script>", "x.html"), (b"MZ\x90", "x.exe"), (b"not a pdf", "x.pdf")):
            r = self.alice.c.post("/upload", data={"title": "t", "category": "Legal", "csrf": self.alice.token("/upload"),
                                                   "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
            self.assertEqual(r.status_code, 400, name)

    def test_path_traversal_filename_neutralised(self):
        d = upload(self.alice, "trav", name="../../etc/passwd.pdf")
        r = self.alice.c.get(f"/documents/{d}/download")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers["Content-Disposition"]); self.assertNotIn("..", r.headers["Content-Disposition"])

    def test_headers(self):
        r = self.alice.c.get("/documents")
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_xss_title_escaped(self):
        upload(self.alice, "<img src=x onerror=alert(1)>")
        self.assertNotIn("<img src=x", self.alice.c.get("/documents").get_data(as_text=True))

    def test_sql_injection_in_search(self):
        r = self.bob.c.get("/search?q=' OR 1=1 --&owner=' OR '1'='1")
        self.assertEqual(r.status_code, 200); self.assertNotIn("Alice secret", r.get_data(as_text=True))

    # --- audit trail
    def test_audit_records_denials_and_chain_verifies(self):
        self.bob.c.get(f"/documents/{self.doc}")
        con = sqlite3.connect(tv.app.config["DATABASE"]); con.row_factory = sqlite3.Row
        self.assertTrue(con.execute("SELECT 1 FROM audit WHERE action='access_denied' AND actor='bob'").fetchone())
        with tv.app.app_context():
            self.assertTrue(tv.verify_chain(con)[0])

    def test_audit_tamper_detected(self):
        con = sqlite3.connect(tv.app.config["DATABASE"])
        con.execute("UPDATE audit SET actor='nobody' WHERE id=(SELECT MIN(id) FROM audit WHERE action='login')"); con.commit()
        con.row_factory = sqlite3.Row
        self.assertFalse(tv.verify_chain(con)[0])
        self.assertIn("CHAIN BROKEN", self.admin.c.get("/logs").get_data(as_text=True))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
