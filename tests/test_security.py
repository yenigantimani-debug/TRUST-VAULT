import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("TRUSTVAULT_SECRET_KEY", "test-secret-key-" + "a" * 48)
os.environ.setdefault("TRUSTVAULT_ENCRYPTION_KEY", "11" * 32)

import app as trustvault
from werkzeug.security import generate_password_hash

class TrustVaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        trustvault.DB_PATH = root / "test.sqlite3"
        trustvault.UPLOAD_DIR = root / "encrypted_uploads"
        trustvault.UPLOAD_DIR.mkdir()
        trustvault.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = trustvault.app.test_client()
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "test-csrf"
        with self.client.application.app_context():
            db = trustvault.get_db()
            trustvault.init_db()
            self.admin = self._user(db, "admin", "admin")
            self.owner = self._user(db, "owner", "owner")
            self.viewer = self._user(db, "viewer", "viewer")
            self.other_owner = self._user(db, "other", "owner")
            db.execute("INSERT INTO documents(title,category,description,owner_id,restricted,created_at) VALUES(?,?,?,?,1,?)",
                       ("Secret file", "Legal", "Private test document", self.owner, trustvault.now_iso()))
            db.commit()
            self.doc_id = db.execute("SELECT id FROM documents WHERE title='Secret file'").fetchone()["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _user(self, db, username, role):
        cur = db.execute("INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                         (username, username + "@example.test", generate_password_hash("test-password-long"), role, trustvault.now_iso()))
        db.commit()
        return cur.lastrowid

    def login_as(self, user_id):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["csrf_token"] = "test-csrf"

    def test_viewer_cannot_manage_sharing(self):
        self.login_as(self.viewer)
        response = self.client.get(f"/documents/{self.doc_id}/sharing")
        self.assertEqual(response.status_code, 403)

    def test_unrelated_owner_cannot_manage_sharing(self):
        self.login_as(self.other_owner)
        response = self.client.post(f"/documents/{self.doc_id}/sharing", data={"csrf_token":"test-csrf", "username":"viewer"})
        self.assertEqual(response.status_code, 403)

    def test_unshared_viewer_cannot_download_document(self):
        self.login_as(self.viewer)
        response = self.client.get(f"/documents/{self.doc_id}/download")
        self.assertEqual(response.status_code, 403)

    def test_unshared_viewer_does_not_see_document_metadata(self):
        self.login_as(self.viewer)
        response = self.client.get("/documents")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Secret file", response.data)

    def test_owner_can_manage_own_sharing(self):
        self.login_as(self.owner)
        response = self.client.get(f"/documents/{self.doc_id}/sharing")
        self.assertEqual(response.status_code, 200)

    def test_non_admin_cannot_view_audit_logs(self):
        self.login_as(self.owner)
        response = self.client.get("/admin/logs")
        self.assertEqual(response.status_code, 403)

    def test_post_without_csrf_is_rejected(self):
        self.login_as(self.owner)
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "expected-token"
        response = self.client.post(f"/documents/{self.doc_id}/sharing", data={"username":"viewer"})
        self.assertEqual(response.status_code, 400)

    def test_registration_cannot_choose_admin_role(self):
        with self.client.session_transaction() as sess:
            sess.clear()
            sess["csrf_token"] = "test-csrf"
        response = self.client.post("/register", data={
            "csrf_token":"test-csrf", "username":"newuser", "email":"new@example.test",
            "password":"a-very-long-test-password", "confirm_password":"a-very-long-test-password", "role":"admin"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with self.client.application.app_context():
            row = trustvault.get_db().execute("SELECT role FROM users WHERE username='newuser'").fetchone()
            self.assertEqual(row["role"], "viewer")

if __name__ == "__main__":
    unittest.main()
