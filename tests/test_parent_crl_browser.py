"""Browser authorization and real signed parent-CRL retrieval through CDP."""
from contextlib import closing
from datetime import UTC, datetime, timedelta
import json
import sqlite3
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app import authority_is_active, get_db
from mfa import code_at_counter, decrypt_secret, time_counter
from monitoring_transports import MonitoringError
import pki
import test_app


class ParentCRLBrowserTests(unittest.TestCase):
    # Reuse fixture helpers without inheriting the full application test suite.
    base_url = test_app.PKIMasterTestCase.base_url
    setUpClass = classmethod(test_app.PKIMasterTestCase.setUpClass.__func__)
    setUp = test_app.PKIMasterTestCase.setUp
    get = test_app.PKIMasterTestCase.get
    post = test_app.PKIMasterTestCase.post
    form_token = test_app.PKIMasterTestCase.form_token
    local_ca = test_app.PKIMasterTestCase.local_ca
    count = test_app.PKIMasterTestCase.count
    create_ca = test_app.PKIMasterTestCase.create_ca
    issue_leaf = test_app.PKIMasterTestCase.issue_leaf
    import_root_crl = test_app.PKIMasterTestCase.import_root_crl
    add_second_admin = test_app.PKIMasterTestCase.add_second_admin
    reviewer_client = test_app.PKIMasterTestCase.reviewer_client
    cdp_url = "https://parent.example/ca.crl"
    fetch_path = "/ca/parent-crls/fetch"

    def activate_cdp_issuer(self, *, cdp=True):
        authority = self.create_ca("issuing", "CDP Issuing CA")
        signed = pki.sign_ca_request(
            authority["csr_pem"], "issuing", 30, "root", *self.external_root[:2],
            crl_url=self.cdp_url if cdp else None,
        )
        root = x509.load_pem_x509_certificate(self.external_root[0].encode())
        response = self.post("/ca/activate", {
            "authority_id": str(authority["id"]), "certificate_pem": signed[0],
            "chain_pem": self.external_root[0],
            "trusted_root_sha256": root.fingerprint(hashes.SHA256()).hex(),
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.local_ca()["state"], "active")
        return self.local_ca()

    def crl(self, number=1, entries=()):
        return pki.build_crl(*self.external_root[:2], entries, number, 7)

    def fresh_form(self, *, username="admin", client=None, **changes):
        client = client or self.client
        token = self.form_token(client.get("/", base_url=self.base_url))
        with self.app.app_context():
            user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            counter = max(time_counter(), user["mfa_last_counter"] + 1)
            code = code_at_counter(decrypt_secret(user["mfa_secret"]), counter)
        return counter, {
            "csrf_token": token, "authority_id": str(self.local_ca()["id"]),
            "totp_code": code, **changes,
        }

    def fetch(self, *, client=None, username="admin", **changes):
        client = client or self.client
        counter, data = self.fresh_form(username=username, client=client, **changes)
        with patch("mfa.time_counter", return_value=counter):
            return client.post(self.fetch_path, base_url=self.base_url,
                               follow_redirects=True, data=data)

    def test_signed_cdp_crl_enables_signing_without_a_network_write_transaction(self):
        authority = self.activate_cdp_issuer()
        with self.app.app_context():
            self.assertFalse(authority_is_active(get_db().execute("SELECT * FROM authorities").fetchone()))
        page = self.get(f"/authorities/{authority['id']}")
        self.assertIn(b"Fetch parent CRLs via CDP", page.data)
        content = self.crl()

        def download(url, **kwargs):
            self.assertEqual(url, self.cdp_url)
            self.assertFalse(get_db().in_transaction, "Network I/O must not hold SQLite's writer lock")
            return content

        with patch("monitoring_transports.http_request", side_effect=download) as network:
            response = self.fetch()
        self.assertEqual(network.call_count, 1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.path, f"/authorities/{authority['id']}")
        stored = x509.load_pem_x509_crl(self.local_ca()["parent_crls_pem"].encode())
        self.assertEqual(stored.public_bytes(serialization.Encoding.DER), content)
        self.issue_leaf()
        self.assertEqual(self.count("certificates"), 1)

    def test_missing_cdp_is_visible_and_cannot_start_a_download(self):
        authority = self.activate_cdp_issuer(cdp=False)
        page = self.get(f"/authorities/{authority['id']}")
        self.assertIn(b"has no CRL distribution points", page.data)
        with patch("monitoring_transports.http_request") as network:
            response = self.fetch()
        network.assert_not_called()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"has no CRL distribution points", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")

    def test_wrong_crl_and_transport_error_preserve_existing_bundle(self):
        self.activate_cdp_issuer()
        self.import_root_crl(number=2)
        original = self.local_ca()["parent_crls_pem"]
        wrong_root = pki.create_ca_certificate("Unrelated Root", 90, "root")
        wrong_crl = pki.build_crl(*wrong_root[:2], (), 3, 7)
        for result in (wrong_crl, MonitoringError("The configured HTTP endpoint is unavailable.")):
            with self.subTest(result=type(result).__name__):
                options = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with patch("monitoring_transports.http_request", **options) as network:
                    response = self.fetch()
                self.assertTrue(network.called)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.local_ca()["parent_crls_pem"], original)
                self.assertIsNone(self.local_ca()["revoked_at"])

    def test_multica_fetch_changes_only_the_selected_authority(self):
        first = self.create_ca("root", "Independent Root")
        with self.app.app_context():
            get_db().execute("UPDATE settings SET value='true' WHERE key='multi_ca_enabled'")
            get_db().commit()
        self.post("/authorities", {
            "name": "Selected Issuer", "common_name": "Selected Issuer", "role": "issuing",
        })
        with self.app.app_context():
            selected = dict(get_db().execute("SELECT * FROM authorities WHERE name='Selected Issuer'").fetchone())
        signed = pki.sign_ca_request(selected["csr_pem"], "issuing", 30, "root", *self.external_root[:2],
                                     crl_url=self.cdp_url)
        root = x509.load_pem_x509_certificate(self.external_root[0].encode())
        self.post("/ca/activate", {
            "authority_id": str(selected["id"]), "certificate_pem": signed[0],
            "chain_pem": self.external_root[0],
            "trusted_root_sha256": root.fingerprint(hashes.SHA256()).hex(),
        })
        with patch("monitoring_transports.http_request", return_value=self.crl()) as network:
            response = self.fetch(authority_id=str(selected["id"]))
        self.assertEqual(network.call_count, 1)
        self.assertEqual(response.request.path, f"/authorities/{selected['id']}")
        with self.app.app_context():
            selected_now = get_db().execute("SELECT * FROM authorities WHERE id=?", (selected["id"],)).fetchone()
            first_now = get_db().execute("SELECT * FROM authorities WHERE id=?", (first["id"],)).fetchone()
            self.assertTrue(authority_is_active(selected_now))
            self.assertTrue(selected_now["parent_crls_pem"])
            self.assertEqual(first_now["parent_crls_pem"], first["parent_crls_pem"])

    def test_downloaded_crl_cannot_roll_back_the_stored_number(self):
        self.activate_cdp_issuer()
        self.import_root_crl(number=3)
        original = self.local_ca()["parent_crls_pem"]
        with patch("monitoring_transports.http_request", return_value=self.crl(number=2)):
            response = self.fetch()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rollback", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], original)

    def test_authenticated_parent_revocation_is_persisted_and_blocks_signing(self):
        authority = self.activate_cdp_issuer()
        content = self.crl(2, [{
            "serial_number": authority["serial_number"],
            "revoked_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            "revocation_reason": "ca_compromise",
        }])
        with patch("monitoring_transports.http_request", return_value=content):
            response = self.fetch()
        self.assertEqual(response.status_code, 200)
        revoked = self.local_ca()
        self.assertIsNotNone(revoked["revoked_at"])
        self.assertEqual(x509.load_pem_x509_crl(revoked["parent_crls_pem"].encode())
                         .public_bytes(serialization.Encoding.DER), content)
        with patch("monitoring_transports.http_request", return_value=self.crl(number=3)):
            self.fetch()
        self.assertEqual(self.local_ca()["revoked_at"], revoked["revoked_at"])
        self.issue_leaf()
        self.assertEqual(self.count("certificates"), 0)

    def test_csrf_invalid_totp_and_replayed_totp_never_fetch(self):
        self.activate_cdp_issuer()
        with patch("monitoring_transports.http_request") as network:
            response = self.fetch(csrf_token="invalid")
            self.assertEqual(response.status_code, 403)
            response = self.fetch(totp_code="not-a-code")
            self.assertEqual(response.status_code, 401)
        network.assert_not_called()

        counter, form = self.fresh_form()
        with patch("mfa.time_counter", return_value=counter):
            with patch("monitoring_transports.http_request", return_value=self.crl()) as network:
                response = self.client.post(self.fetch_path, base_url=self.base_url, data=form)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(network.call_count, 1)
            with patch("monitoring_transports.http_request") as network:
                response = self.client.post(self.fetch_path, base_url=self.base_url, data=form)
                self.assertEqual(response.status_code, 401)
            network.assert_not_called()

    def test_operator_auditor_and_unverified_sessions_cannot_fetch(self):
        self.activate_cdp_issuer()
        for role in ("operator", "auditor"):
            with self.subTest(role=role):
                with self.app.app_context():
                    get_db().execute("UPDATE users SET role=? WHERE username='admin'", (role,))
                    get_db().commit()
                with patch("monitoring_transports.http_request") as network:
                    response = self.fetch()
                self.assertEqual(response.status_code, 403)
                network.assert_not_called()
        with self.app.app_context():
            get_db().execute("UPDATE users SET role='admin' WHERE username='admin'")
            get_db().commit()
        _, form = self.fresh_form()
        with self.client.session_transaction() as session:
            session["mfa_verified"] = False
        with patch("monitoring_transports.http_request") as network:
            response = self.client.post(self.fetch_path, base_url=self.base_url, data=form)
            self.assertEqual(response.status_code, 302)
            anonymous = self.app.test_client()
            response = anonymous.post(self.fetch_path, base_url=self.base_url, data=form)
            self.assertEqual(response.status_code, 302)
        network.assert_not_called()
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")

    def test_concurrent_revocation_rejects_downloaded_bundle(self):
        authority = self.activate_cdp_issuer()
        timestamp = datetime.now(UTC).isoformat()

        def download(url, **kwargs):
            self.assertFalse(get_db().in_transaction)
            with closing(sqlite3.connect(self.app.config["DATABASE"], timeout=1)) as db, db:
                db.execute("UPDATE authorities SET revoked_at=?, revocation_reason='unspecified' WHERE id=?",
                           (timestamp, authority["id"]))
            return self.crl()

        with patch("monitoring_transports.http_request", side_effect=download) as network:
            response = self.fetch()
        self.assertEqual(network.call_count, 1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.local_ca()["revoked_at"], timestamp)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")

    def test_concurrently_imported_newer_crl_cannot_be_replaced(self):
        authority = self.activate_cdp_issuer()
        newer = x509.load_der_x509_crl(self.crl(5)).public_bytes(serialization.Encoding.PEM).decode()

        def download(url, **kwargs):
            self.assertFalse(get_db().in_transaction)
            with closing(sqlite3.connect(self.app.config["DATABASE"], timeout=1)) as db, db:
                db.execute("UPDATE authorities SET parent_crls_pem=? WHERE id=?", (newer, authority["id"]))
            return self.crl(4)

        with patch("monitoring_transports.http_request", side_effect=download):
            response = self.fetch()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rollback", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], newer)

    def test_four_eyes_queues_without_network_then_fetches_after_independent_approval(self):
        self.activate_cdp_issuer()
        reviewer = self.reviewer_client(self.add_second_admin())
        with self.app.app_context():
            get_db().execute("UPDATE settings SET value='true' WHERE key='require_dual_approval'")
            get_db().commit()
        with patch("monitoring_transports.http_request") as network:
            response = self.fetch()
        self.assertEqual(response.status_code, 200)
        network.assert_not_called()
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")
        with self.app.app_context():
            pending = dict(get_db().execute("SELECT * FROM approval_requests").fetchone())
        self.assertEqual(pending["endpoint"], "fetch_parent_crls_cdp")
        self.assertEqual(pending["status"], "pending")
        self.assertNotIn("totp_code", json.loads(pending["form_data"]))
        with patch("monitoring_transports.http_request", return_value=self.crl()) as network:
            response = self.fetch(client=reviewer, username="reviewer", approval_id=str(pending["id"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(network.call_count, 1)
        self.assertTrue(self.local_ca()["parent_crls_pem"])
        with self.app.app_context():
            decision = get_db().execute("SELECT * FROM approval_requests WHERE id=?", (pending["id"],)).fetchone()
            self.assertEqual(decision["status"], "approved")
            self.assertNotEqual(decision["requested_by"], decision["reviewed_by"])


if __name__ == "__main__":
    unittest.main()
