"""Web configuration, durable publication, and revocation under transport failure."""

from datetime import UTC, datetime, timedelta
import re
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID

from app import create_app, get_db
from audit_integrity import AuditIntegrityError
from mfa_helpers import complete_mfa
import pki
import publication


class PublicationTests(unittest.TestCase):
    base_url = "https://localhost"
    password = "publication administrator passphrase"
    sftp_password = "publication-only-secret-password"
    crl_url = "https://public.example/pki/ca.crl"
    aia_url = "https://public.example/pki/ca.cer"

    @classmethod
    def setUpClass(cls):
        cls.local_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072)):
            cls.external_root = pki.create_ca_certificate("Publication parent", 365, "root")
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_csr = (x509.CertificateSigningRequestBuilder().subject_name(pki.build_subject("service.example"))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("service.example")]), critical=False)
            .sign(cls.leaf_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        cls.ssh_passphrase = "separate SSH test passphrase"
        cls.ssh_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(cls.ssh_passphrase.encode())).decode()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        generator = patch("pki.generate_private_key", return_value=self.local_key)
        generator.start()
        self.addCleanup(generator.stop)
        self.app_config = {"TESTING": True, "INSTANCE_PATH": directory.name}
        self.app = create_app(self.app_config)
        self.client = self.app.test_client()
        response = self.post("/setup", {"username": "admin", "password": self.password,
            "password_confirm": self.password, "organization": "Publication test", "public_base_url": "https://pki.example"})
        self.assertEqual(response.status_code, 200)
        complete_mfa(self.client, self.app)

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=self.base_url, **kwargs)

    def post(self, path, values=None, client=None, **kwargs):
        client = client or self.client
        page = self.get("/", client, follow_redirects=True)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return client.post(path, base_url=self.base_url, follow_redirects=True,
                           data={"csrf_token": token, **(values or {})}, **kwargs)

    def state(self):
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM publication_state WHERE id=1").fetchone())

    def authority(self):
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM authorities").fetchone()
            return dict(row) if row else None

    def configuration(self):
        with self.app.app_context():
            return publication.configuration()

    def values(self, **updates):
        values = {"enabled": "on", "crl_url": self.crl_url, "aia_url": self.aia_url,
            "host": "sftp.example", "port": "22", "directory": "/public/pki", "username": "publisher",
            "host_key_sha256": "SHA256:" + "A" * 43, "auth_method": "password",
            "password": self.sftp_password, "private_key_pem": "", "private_key_passphrase": ""}
        values.update(updates)
        return values

    def configure(self, **updates):
        response = self.post("/settings/publication", self.values(**updates))
        self.assertEqual(response.status_code, 200, response.data)
        return response

    def create_ca(self, role="root", days=365):
        previous = self.state()["generation"]
        response = self.post("/authorities", {"name": "Publication CA", "common_name": "Publication CA",
                                              "role": role, "validity_days": str(days)})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self.authority())
        self.assertGreater(self.state()["generation"], previous)
        return self.authority()

    def activate_issuer(self):
        authority = self.create_ca("issuing")
        signed = pki.sign_ca_request(authority["csr_pem"], "issuing", 90, "root", self.external_root[0], self.external_root[1])
        fingerprint = x509.load_pem_x509_certificate(self.external_root[0].encode()).fingerprint(hashes.SHA256()).hex()
        previous = self.state()["generation"]
        response = self.post("/ca/activate", {"certificate_pem": signed[0], "chain_pem": self.external_root[0],
                                             "trusted_root_sha256": fingerprint})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.authority()["state"], "active")
        self.assertGreater(self.state()["generation"], previous)
        crl = pki.build_crl(self.external_root[0], self.external_root[1], [], 1, 7)
        response = self.post("/ca/parent-crls", {"parent_crls_pem": x509.load_der_x509_crl(crl).public_bytes(serialization.Encoding.PEM).decode()})
        self.assertEqual(response.status_code, 200)
        return self.authority()

    def cycle(self):
        with self.app.app_context():
            return publication.run_publication_cycle()

    def test_publication_settings_and_manual_publish_require_administrator_and_csrf(self):
        anonymous = self.app.test_client()
        self.assertEqual(self.get("/settings/publication", anonymous).status_code, 302)
        self.assertEqual(anonymous.post("/publication/publish", base_url=self.base_url).status_code, 302)
        self.assertEqual(self.client.post("/settings/publication", base_url=self.base_url, data=self.values()).status_code, 403)
        self.assertEqual(self.client.post("/publication/publish", base_url=self.base_url).status_code, 403)
        for role in ("operator", "auditor"):
            self.post("/users", {"action": "create", "username": role, "role": role, "password": self.password})
            client = self.app.test_client()
            self.post("/login", {"username": role, "password": self.password}, client)
            complete_mfa(client, self.app, role)
            self.assertEqual(self.get("/settings/publication", client).status_code, 403)
            self.assertEqual(self.post("/publication/publish", client=client).status_code, 403)

    def test_secrets_are_encrypted_preserved_on_blank_and_absent_from_pages_and_audit(self):
        self.configure()
        self.configure(password="")
        self.assertEqual(self.configuration()["password"], self.sftp_password)
        self.configure(auth_method="key", password="", private_key_pem=self.ssh_key,
                       private_key_passphrase=self.ssh_passphrase)
        response = self.configure(auth_method="key", password="")
        config = self.configuration()
        self.assertEqual(config["private_key_pem"], self.ssh_key)
        self.assertEqual(config["private_key_passphrase"], self.ssh_passphrase)
        self.assertEqual(config["password"], "")
        with self.app.app_context():
            db = get_db()
            encrypted = db.execute("SELECT value FROM settings WHERE key='publication_config'").fetchone()[0]
            audit = " ".join(str(tuple(row)) for row in db.execute("SELECT * FROM audit_events"))
        for secret in (self.sftp_password, self.ssh_passphrase, self.ssh_key):
            self.assertNotIn(secret, encrypted)
            self.assertNotIn(secret, audit)
            self.assertNotIn(secret.encode(), response.data)

    def test_target_change_requires_new_credentials_without_altering_saved_target(self):
        self.configure()
        before = self.configuration()
        generation = self.state()["generation"]
        response = self.post("/settings/publication", self.values(host="different.example", password=""))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.configuration(), before)
        self.assertEqual(self.state()["generation"], generation)
        self.configure(host="different.example", password="replacement-publication-password")
        self.assertEqual(self.configuration()["host"], "different.example")

    def test_unencrypted_replacement_ssh_key_clears_the_stored_passphrase(self):
        self.configure(auth_method="key", password="", private_key_pem=self.ssh_key,
                       private_key_passphrase=self.ssh_passphrase)
        key = serialization.load_pem_private_key(self.ssh_key.encode(), self.ssh_passphrase.encode())
        unencrypted = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
        response = self.configure(auth_method="key", password="", private_key_pem=unencrypted,
                                  private_key_passphrase="")
        self.assertEqual(self.configuration()["private_key_pem"], unencrypted)
        self.assertEqual(self.configuration()["private_key_passphrase"], "")
        self.assertNotIn(unencrypted.encode(), response.data)
        self.assertNotIn(self.ssh_passphrase.encode(), response.data)

    def test_invalid_urls_and_missing_host_pin_do_not_replace_saved_configuration(self):
        self.configure()
        before = self.configuration()
        for changes in ({"crl_url": "https://public.example/ca.crl?token=secret"},
                        {"aia_url": self.crl_url}, {"host_key_sha256": ""}):
            with self.subTest(changes=changes):
                response = self.post("/settings/publication", self.values(**changes))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.configuration(), before)

    def test_url_only_mode_embeds_overrides_and_exposes_public_der_certificate(self):
        self.configure(enabled="")
        authority = self.activate_issuer()
        response = self.post("/certificates", {"authority_id": str(authority["id"]), "common_name": "service.example",
            "csr_pem": self.leaf_csr, "profile": "server", "validity_days": "30"})
        self.assertEqual(response.status_code, 200)
        leaf = x509.load_pem_x509_certificate(self.get("/certificates/1/cert").data)
        aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value[0]
        self.assertEqual(aia.access_method, AuthorityInformationAccessOID.CA_ISSUERS)
        self.assertEqual(aia.access_location.value, self.aia_url)
        crl = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0]
        self.assertEqual(crl.full_name[0].value, self.crl_url)
        anonymous = self.app.test_client()
        response = self.get("/aia/1.cer", anonymous)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pkix-cert")
        self.assertEqual(response.data, x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER))
        self.assertEqual(self.get("/aia/9223372036854775808.cer", anonymous).status_code, 404)
        self.assertEqual(self.get("/aia/999.cer", anonymous).status_code, 404)
        with patch("publication.publish") as upload:
            self.assertEqual(self.cycle(), {"status": "disabled"})
            upload.assert_not_called()

    def test_pending_ca_has_no_public_aia_artifact_and_no_upload(self):
        self.create_ca("issuing")
        self.configure()
        self.assertEqual(self.get("/aia/1.cer", self.app.test_client()).status_code, 404)
        with patch("publication.publish") as upload:
            self.assertEqual(self.cycle(), {"status": "waiting"})
            upload.assert_not_called()

    def test_queue_commit_and_rollback_survive_application_restart(self):
        original = self.state()["generation"]
        with self.app.app_context():
            db = get_db()
            publication.queue_publication(db)
            db.rollback()
        self.assertEqual(self.state()["generation"], original)
        with self.app.app_context():
            db = get_db()
            publication.queue_publication(db)
            publication.queue_publication(db)
            db.commit()
        restarted = create_app(self.app_config)
        with restarted.app_context():
            self.assertEqual(get_db().execute("SELECT generation FROM publication_state WHERE id=1").fetchone()[0], original + 2)

    def test_audit_corruption_after_startup_blocks_background_network_and_mutation(self):
        self.create_ca()
        self.configure()
        original_state = self.state()
        original_authority = self.authority()
        with self.app.app_context():
            db = get_db()
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit_events SET detail='forged history' WHERE id=1")
            db.commit()
            event_count = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            with patch("publication.publish") as upload:
                with self.assertRaises(AuditIntegrityError):
                    publication.run_publication_cycle()
                upload.assert_not_called()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM crls").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], event_count)
        self.assertEqual(self.state(), original_state)
        self.assertEqual(self.authority(), original_authority)

    def test_success_uploads_only_public_artifacts_and_unchanged_cycle_is_idle(self):
        authority = self.create_ca()
        self.configure()
        with patch("publication.publish") as upload:
            result = self.cycle()
            self.assertEqual(result["status"], "published")
            artifacts = upload.call_args.args[1]
            self.assertEqual({artifact["name"] for artifact in artifacts}, {"ca.cer", "chain.pem", "ca.crl"})
            for artifact in artifacts:
                self.assertNotIn(b"PRIVATE KEY", artifact["content"])
            by_name = {artifact["name"]: artifact["content"] for artifact in artifacts}
            certificate = x509.load_der_x509_certificate(by_name["ca.cer"])
            self.assertEqual(certificate.serial_number, int(authority["serial_number"], 0))
            self.assertTrue(x509.load_der_x509_crl(by_name["ca.crl"]).is_signature_valid(certificate.public_key()))
            self.assertEqual(self.cycle(), {"status": "idle"})
            upload.assert_called_once()
        state = self.state()
        self.assertEqual(state["published_generation"], state["generation"])
        self.assertEqual(state["last_published_crl_number"], result["crl_number"])
        self.assertTrue(state["last_success"])

    def test_failed_upload_preserves_revocation_and_manual_retry_clears_backoff(self):
        self.activate_issuer()
        self.configure()
        self.post("/certificates", {"authority_id": "1", "common_name": "service.example",
            "csr_pem": self.leaf_csr, "profile": "server", "validity_days": "30"})
        generation = self.state()["generation"]
        with patch("publication.publish", side_effect=RuntimeError("private password=" + self.sftp_password)) as upload:
            response = self.post("/certificates/1/revoke", {"reason": "key_compromise"})
            self.assertEqual(response.status_code, 200)
            upload.assert_not_called()
            self.assertGreater(self.state()["generation"], generation)
            self.assertEqual(self.cycle(), {"status": "failed"})
            failed = self.state()
            self.assertEqual(failed["failures"], 1)
            self.assertGreater(failed["next_attempt_at"], 0)
            self.assertLess(failed["published_generation"], failed["generation"])
            self.assertNotIn(self.sftp_password, failed["last_error"])
            with self.app.app_context():
                certificate = dict(get_db().execute("SELECT * FROM certificates WHERE id=1").fetchone())
            self.assertTrue(certificate["revoked_at"])
            self.assertEqual(certificate["revocation_reason"], "key_compromise")
            crl = x509.load_der_x509_crl(next(artifact["content"] for artifact in upload.call_args.args[1] if artifact["name"] == "ca.crl"))
            self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(certificate["serial_number"], 0)))
            self.assertEqual(self.cycle(), {"status": "waiting"})
            upload.assert_called_once()
        with patch("publication.publish") as retry:
            response = self.post("/publication/publish")
            self.assertEqual(response.status_code, 200)
            retry.assert_called_once()
        succeeded = self.state()
        self.assertEqual(succeeded["failures"], 0)
        self.assertEqual(succeeded["last_error"], "")
        self.assertEqual(succeeded["next_attempt_at"], 0)
        self.assertEqual(succeeded["generation"], succeeded["published_generation"])
        self.assertNotIn(self.sftp_password.encode(), self.get("/audit").data)

    def test_changes_queued_during_upload_remain_pending(self):
        self.create_ca()
        self.configure()

        def change_during_upload(_config, _artifacts):
            publication.queue_publication(get_db())
            get_db().commit()

        with patch("publication.publish", side_effect=change_during_upload):
            result = self.cycle()
        self.assertEqual(result["status"], "published")
        pending = self.state()
        self.assertEqual(pending["published_generation"], result["generation"])
        self.assertGreater(pending["generation"], pending["published_generation"])
        with patch("publication.publish") as upload:
            self.assertEqual(self.cycle()["status"], "published")
            upload.assert_called_once()
        self.assertEqual(self.state()["generation"], self.state()["published_generation"])

    def test_retry_backoff_survives_restart_and_increases_after_another_failure(self):
        self.create_ca()
        self.configure()
        with patch("publication.publish", side_effect=RuntimeError("private transport diagnostic")):
            self.assertEqual(self.cycle(), {"status": "failed"})
        first = self.state()
        restarted = create_app(self.app_config)
        with restarted.app_context():
            with patch("publication.publish", side_effect=RuntimeError("private diagnostic")) as upload:
                self.assertEqual(publication.run_publication_cycle(), {"status": "waiting"})
                upload.assert_not_called()
                with patch("publication.time.time", return_value=first["next_attempt_at"] + 1):
                    self.assertEqual(publication.run_publication_cycle(), {"status": "failed"})
                upload.assert_called_once()
        second = self.state()
        self.assertEqual(second["failures"], 2)
        self.assertGreaterEqual(second["next_attempt_at"], first["next_attempt_at"] + 120)
        self.assertLess(second["published_generation"], second["generation"])
        self.assertNotIn("private", second["last_error"])

    def test_subordinate_approval_embeds_the_parent_publication_urls(self):
        self.create_ca()
        self.configure(enabled="")
        self.post("/users", {"action": "create", "username": "reviewer", "role": "admin", "password": self.password})
        reviewer = self.app.test_client()
        self.post("/login", {"username": "reviewer", "password": self.password}, reviewer)
        complete_mfa(reviewer, self.app, "reviewer")
        child_key = serialization.load_pem_private_key(self.external_root[1].encode(), None)
        with patch("pki.generate_private_key", return_value=child_key):
            csr, _ = pki.create_ca_request("Remote Issuing CA", "issuing")
        self.post("/ca/requests", {"csr_pem": csr, "role": "issuing", "validity_days": "30"})
        response = self.post("/ca/requests/1/approve", client=reviewer)
        self.assertEqual(response.status_code, 200)
        certificate = x509.load_pem_x509_certificate(self.get("/subordinates/1/cert").data)
        aia = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value[0]
        self.assertEqual(aia.access_method, AuthorityInformationAccessOID.CA_ISSUERS)
        self.assertEqual(aia.access_location.value, self.aia_url)
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value, self.crl_url)

    def test_publication_lock_prevents_overlapping_uploads_and_target_changes(self):
        self.create_ca()
        self.configure()
        original = self.configuration()
        with self.app.app_context(), publication.publication_lock() as acquired:
            self.assertTrue(acquired)
            with patch("publication.publish") as upload:
                self.assertEqual(publication.run_publication_cycle(), {"status": "busy"})
                response = self.post("/settings/publication", self.values(host="different.example"))
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"publication is running", response.data)
                upload.assert_not_called()
        self.assertEqual(self.configuration(), original)

    def test_disabled_mode_remains_available_with_unusable_saved_credentials(self):
        self.configure()
        response = self.post("/settings/publication", {"crl_url": self.crl_url, "aia_url": self.aia_url})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.configuration()["enabled"])
        self.assertEqual(self.configuration()["password"], self.sftp_password)
        with patch("publication.publish") as upload:
            self.assertEqual(self.cycle(), {"status": "disabled"})
            upload.assert_not_called()

    def test_timer_renews_crl_before_expiry_without_republishing_every_minute(self):
        self.create_ca()
        self.configure()
        with patch("publication.publish"):
            first = self.cycle()
        with self.app.app_context():
            original = x509.load_der_x509_crl(get_db().execute("SELECT der FROM crls").fetchone()[0])
        future = original.next_update_utc - timedelta(hours=12)

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz else future.replace(tzinfo=None)

        with patch("publication.datetime", Clock), patch("pki.datetime", Clock):
            with patch("publication.publish") as upload:
                renewed = self.cycle()
                self.assertEqual(renewed["status"], "published")
                self.assertGreater(renewed["crl_number"], first["crl_number"])
                self.assertEqual(self.cycle(), {"status": "idle"})
                upload.assert_called_once()

    def test_ca_expiry_capped_crl_is_not_resigned_each_minute(self):
        self.create_ca(days=1)
        self.configure()
        with patch("publication.publish"):
            first = self.cycle()
        with self.app.app_context():
            original = x509.load_der_x509_crl(get_db().execute("SELECT der FROM crls").fetchone()[0])
        future = original.next_update_utc - timedelta(minutes=10)

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz else future.replace(tzinfo=None)

        with patch("publication.datetime", Clock), patch("pki.datetime", Clock):
            with patch("publication.publish") as upload:
                self.assertEqual(self.cycle(), {"status": "idle"})
                self.assertEqual(self.cycle(), {"status": "idle"})
                upload.assert_not_called()
        self.assertEqual(self.state()["last_published_crl_number"], first["crl_number"])

    def test_expired_ca_cannot_upload_a_stale_crl_as_current(self):
        authority = self.create_ca(days=1)
        self.configure()
        with patch("publication.publish"):
            self.assertEqual(self.cycle()["status"], "published")
        future = datetime.fromisoformat(authority["not_after"]) + timedelta(seconds=1)

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz else future.replace(tzinfo=None)

        with patch("publication.datetime", Clock), patch("pki.datetime", Clock):
            with patch("publication.publish") as upload:
                self.assertEqual(self.cycle(), {"status": "failed"})
                upload.assert_not_called()
        self.assertEqual(self.state()["failures"], 1)
        self.assertIn("validity", self.state()["last_error"])


if __name__ == "__main__":
    unittest.main()
