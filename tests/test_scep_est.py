import base64
import hashlib
import json
import shutil
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from asn1crypto import cms, core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

import scep_est
from app import create_app, encrypt_private_key, get_db


class ScepEstTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[1] / "build" / ("scep-est-" + uuid4().hex)
        self.directory.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.app = create_app({
            "TESTING": True,
            "INSTANCE_PATH": str(self.directory),
            "DATABASE": str(self.directory / "pki.sqlite"),
        })
        self.client = self.app.test_client()

    def test_protocols_are_unavailable_by_default(self):
        self.assertEqual(self.client.get("/scep?operation=GetCACaps").status_code, 503)
        self.assertEqual(self.client.get("/scep?operation=GetCACert").status_code, 503)
        self.assertEqual(self.client.get("/.well-known/est/cacerts", base_url="https://pki.example").status_code, 503)
        self.assertEqual(self.client.post(
            "/.well-known/est/simpleenroll", base_url="https://pki.example"
        ).status_code, 503)

    def test_malformed_or_invalid_persisted_config_fails_closed(self):
        for raw in ('{', '[]', '{"enabled":"yes"}', '{"scep":1}', '{"validity_days":true}', '{"validity_days":0}'):
            with self.subTest(raw=raw), self.app.app_context():
                db = get_db()
                db.execute("""INSERT INTO settings VALUES ('scep_est_config',?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (raw,))
                db.commit()
                with self.assertRaises(RuntimeError):
                    scep_est._config()

    def test_enabled_scep_caps_and_est_authentication_gate(self):
        with self.app.app_context():
            db = get_db()
            db.execute("INSERT INTO settings VALUES ('public_base_url','https://pki.example') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            db.execute("""INSERT INTO settings VALUES ('scep_est_config',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (json.dumps({"enabled": True, "scep": True, "est": True, "validity_days": 30}),))
            db.commit()
        caps = self.client.get("/scep?operation=GetCACaps")
        self.assertEqual(caps.status_code, 200)
        self.assertIn(b"POSTPKIOperation", caps.data)
        enrollment = self.client.post(
            "/.well-known/est/simpleenroll", base_url="https://pki.example",
            data=b"", content_type="application/pkcs10",
        )
        self.assertEqual(enrollment.status_code, 401)
        with patch("scep_est._limit", side_effect=scep_est.EnrollmentRateLimitError("limited")):
            limited = self.client.post(
                "/scep?operation=PKIOperation", data=b"request",
                content_type="application/x-pki-message",
            )
        self.assertEqual(limited.status_code, 429)

    def test_est_simpleenroll_issues_under_bound_policy_and_consumes_credential(self):
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
        now = datetime.now(UTC)
        issuer = (
            x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
            .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.example.com")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("device.example.com")]), critical=False)
            .sign(leaf_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        )
        identifier, secret = "est-credential-123", "S" * 48
        with self.app.app_context():
            db = get_db()
            template_id = db.execute("SELECT id FROM certificate_templates WHERE builtin='server'").fetchone()[0]
            db.execute("""INSERT INTO authorities
                (id,name,role,common_name,parent_id,certificate_pem,private_key_pem,
                 serial_number,not_before,not_after,state,csr_pem,parent_chain_pem,
                 parent_crls_pem,key_backend,key_reference)
                VALUES (1,'Test Issuing CA','issuing','Test Issuing CA',NULL,?,?,?,?,?,
                        'active','','','','software','')""",
                (issuer.public_bytes(serialization.Encoding.PEM).decode(),
                 encrypt_private_key(issuer_key.private_bytes(
                     serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                     serialization.NoEncryption()).decode()),
                 format(issuer.serial_number, "x"), issuer.not_valid_before_utc.isoformat(),
                 issuer.not_valid_after_utc.isoformat()))
            db.execute("INSERT INTO settings VALUES ('public_base_url','https://pki.example') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            db.execute("""INSERT INTO settings VALUES ('scep_est_config',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (json.dumps({"enabled": True, "scep": False, "est": True, "validity_days": 30}),))
            db.execute("""INSERT INTO enrollment_credentials
                (id,label,protocol,secret_hash,authority_id,template_id,domains,validity_days,created_at,expires)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (identifier, "Test EST device", "est", hashlib.sha256(secret.encode()).hexdigest(),
                 1, str(template_id), json.dumps(["example.com"]), 30,
                 scep_est._stamp(), "2999-01-01T00:00:00Z"))
            db.commit()
        authority = {"id": 1, "role": "issuing", "state": "active", "revoked_at": None,
                     "certificate_pem": issuer.public_bytes(serialization.Encoding.PEM).decode(),
                     "parent_chain_pem": ""}
        authorization = "Basic " + base64.b64encode(f"{identifier}:{secret}".encode()).decode()
        with patch("scep_est._issuer", return_value=(authority, issuer, issuer_key)):
            response = self.client.post(
                "/.well-known/est/simpleenroll", base_url="https://pki.example",
                data=csr, content_type="application/pkcs10",
                headers={"Authorization": authorization},
            )
            self.assertEqual(response.status_code, 200, response.data)
            self.assertTrue(response.headers["Content-Type"].startswith("application/pkcs7-mime"))
            bundle = cms.ContentInfo.load(response.data, strict=True)["content"]
            certificates = scep_est._cms_certificates(bundle)
            self.assertEqual(len(certificates), 2)
            self.assertIn("device.example.com", {
                certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                for certificate in certificates
            })
            replay = self.client.post(
                "/.well-known/est/simpleenroll", base_url="https://pki.example",
                data=csr, content_type="application/pkcs10",
                headers={"Authorization": authorization},
            )
            self.assertEqual(replay.status_code, 401)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM certificates").fetchone()[0], 1)
            self.assertIsNotNone(get_db().execute(
                "SELECT used_at FROM enrollment_credentials WHERE id=?", (identifier,)
            ).fetchone()["used_at"])

    def test_scep_pkcsreq_checks_cms_and_credential_then_returns_encrypted_certrep(self):
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SCEP CA")])
        now = datetime.now(UTC)
        issuer = (
            x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
            .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )
        client_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SCEP client")])
        client_certificate = (
            x509.CertificateBuilder().subject_name(client_name).issuer_name(client_name)
            .public_key(client_signing_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True)
            .sign(client_signing_key, hashes.SHA256())
        )
        secret = "D" * 48
        csr_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scep.example.com")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("scep.example.com")]), critical=False)
            .add_attribute(x509.ObjectIdentifier(scep_est.OID_CHALLENGE_PASSWORD),
                           secret.encode())
            .sign(csr_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        )
        with self.app.app_context():
            db = get_db()
            template_id = db.execute("SELECT id FROM certificate_templates WHERE builtin='server'").fetchone()[0]
            db.execute("""INSERT INTO authorities
                (id,name,role,common_name,parent_id,certificate_pem,private_key_pem,
                 serial_number,not_before,not_after,state,csr_pem,parent_chain_pem,
                 parent_crls_pem,key_backend,key_reference)
                VALUES (1,'Test SCEP CA','issuing','Test SCEP CA',NULL,?,?,?,?,?,
                        'active','','','','software','')""",
                (issuer.public_bytes(serialization.Encoding.PEM).decode(),
                 encrypt_private_key(issuer_key.private_bytes(
                     serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                     serialization.NoEncryption()).decode()),
                 format(issuer.serial_number, "x"), issuer.not_valid_before_utc.isoformat(),
                 issuer.not_valid_after_utc.isoformat()))
            db.execute("INSERT INTO settings VALUES ('public_base_url','https://pki.example') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            db.execute("""INSERT INTO settings VALUES ('scep_est_config',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (json.dumps({"enabled": True, "scep": True, "est": False, "validity_days": 30}),))
            db.execute("""INSERT INTO enrollment_credentials
                (id,label,protocol,secret_hash,authority_id,template_id,domains,validity_days,created_at,expires)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("scep-credential-123", "SCEP device", "scep", hashlib.sha256(secret.encode()).hexdigest(),
                 1, str(template_id), json.dumps(["scep.example.com"]), 30,
                 scep_est._stamp(), "2999-01-01T00:00:00Z"))
            db.commit()
        transaction_id, sender_nonce = "scep-transaction-123", b"N" * 16
        envelope = scep_est._cms_encrypt(csr, issuer)
        request_attributes = [
            cms.CMSAttribute({"type": cms.CMSAttributeType(scep_est.OID_MESSAGE_TYPE),
                              "values": [core.PrintableString("19")]}),
            cms.CMSAttribute({"type": cms.CMSAttributeType(scep_est.OID_TRANSACTION_ID),
                              "values": [core.PrintableString(transaction_id)]}),
            cms.CMSAttribute({"type": cms.CMSAttributeType(scep_est.OID_SENDER_NONCE),
                              "values": [core.OctetString(sender_nonce)]}),
        ]
        pkcsreq = scep_est._cms_sign(envelope, client_signing_key, client_certificate,
                                     content_type="enveloped_data", extra_attrs=request_attributes)
        authority = {"id": 1, "role": "issuing", "state": "active", "revoked_at": None,
                     "certificate_pem": issuer.public_bytes(serialization.Encoding.PEM).decode(),
                     "parent_chain_pem": ""}
        with patch("scep_est._issuer", return_value=(authority, issuer, issuer_key)):
            with self.app.test_request_context("/scep?operation=PKIOperation", base_url="https://pki.example"):
                parsed_request = scep_est._scep_request(pkcsreq)
                self.assertEqual(parsed_request[2], transaction_id)
            response = self.client.post(
                "/scep?operation=PKIOperation", base_url="https://pki.example",
                data=pkcsreq, content_type="application/x-pki-message",
            )
        self.assertEqual(response.status_code, 200, response.data)
        signed = cms.ContentInfo.load(response.data, strict=True)["content"]
        signer_info = signed["signer_infos"][0]
        self.assertEqual(scep_est._cms_attribute(signer_info, scep_est.OID_MESSAGE_TYPE), "3")
        self.assertEqual(scep_est._cms_attribute(signer_info, scep_est.OID_PKI_STATUS), "0")
        self.assertEqual(scep_est._cms_attribute(signer_info, scep_est.OID_TRANSACTION_ID), transaction_id)
        issuer.public_key().verify(
            signer_info["signature"].native, signer_info["signed_attrs"].untag().dump(),
            padding.PKCS1v15(), hashes.SHA256(),
        )
        encrypted_reply = signed["encap_content_info"]["content"].untag().dump()
        clear_reply = scep_est._decrypt_enveloped(encrypted_reply, client_signing_key)
        reply = cms.ContentInfo.load(clear_reply, strict=True)["content"]
        self.assertIn("scep.example.com", {
            certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            for certificate in scep_est._cms_certificates(reply)
        })
        with self.app.app_context():
            db = get_db()
            self.assertIsNotNone(db.execute(
                "SELECT used_at FROM enrollment_credentials WHERE protocol='scep'"
            ).fetchone()["used_at"])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0], 1)

    def test_certs_only_is_well_formed_cms_signed_data(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True)
            .sign(key, hashes.SHA256())
        )
        encoded = scep_est._cms_certificates_only([certificate])
        info = cms.ContentInfo.load(encoded, strict=True)
        self.assertEqual(info["content_type"].native, "signed_data")
        self.assertEqual(info["content"]["signer_infos"].native, [])
        self.assertEqual(len(scep_est._cms_certificates(info["content"])), 1)
        payload = b"CMS signing and envelope round trip"
        signed = scep_est._cms_sign(payload, key, certificate)
        _, recovered, signer = scep_est._verify_signed_data(signed)
        self.assertEqual(recovered, payload)
        self.assertEqual(signer.serial_number, certificate.serial_number)
        scep_attribute = cms.CMSAttribute({
            "type": cms.CMSAttributeType(scep_est.OID_MESSAGE_TYPE),
            "values": [core.PrintableString("3")],
        })
        envelope = scep_est._cms_encrypt(payload, certificate)
        certrep = scep_est._cms_sign(envelope, key, certificate, content_type="enveloped_data",
                                     extra_attrs=[scep_attribute])
        parsed, _, _ = scep_est._verify_signed_data(certrep)
        self.assertEqual(scep_est._cms_attribute(parsed["signer_infos"][0], scep_est.OID_MESSAGE_TYPE), "3")
        _, wrapped_content, _ = scep_est._verify_signed_data(certrep)
        self.assertEqual(scep_est._decrypt_enveloped(wrapped_content, key), payload)
        self.assertEqual(scep_est._decrypt_enveloped(envelope, key), payload)

    def test_credential_secret_is_only_stored_as_hash_and_revocation_blocks_it(self):
        secret = "K" * 48
        with self.app.app_context():
            db = get_db()
            db.execute("""INSERT INTO enrollment_credentials
                (id,label,protocol,secret_hash,authority_id,template_id,domains,validity_days,created_at,expires)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("credential-test-123", "Test device", "est", hashlib.sha256(secret.encode()).hexdigest(),
                 1, "1", json.dumps(["device.example.com"]), 30,
                 scep_est._stamp(), "2999-01-01T00:00:00Z"))
            db.commit()
            row = scep_est._authorize("est", "credential-test-123", secret)
            self.assertEqual(row["label"], "Test device")
            self.assertNotEqual(row["secret_hash"], secret)
            self.assertIsNone(db.execute("SELECT used_at FROM enrollment_credentials WHERE id=?",
                                         (row["id"],)).fetchone()["used_at"])
            db.execute("UPDATE enrollment_credentials SET revoked=1 WHERE id=?", (row["id"],))
            db.commit()
            with self.assertRaises(ValueError):
                scep_est._authorize("est", "credential-test-123", secret)

    def test_domain_scope_does_not_allow_implicit_wildcards_or_apex(self):
        with self.assertRaises(ValueError):
            scep_est._domain("*.example.com")
        with self.assertRaises(ValueError):
            scep_est._domain("example")
        self.assertEqual(scep_est._domain("device.example.com"), "device.example.com")


if __name__ == "__main__":
    unittest.main()
