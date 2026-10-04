"""Signed ACME transactions, enrollment policy, and real certificate issuance."""
import hashlib
import hmac
import json
import re
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import NameOID

import acme_service as acme
from app import get_db
from audit_integrity import verify_chain
import pki
from test_distributed_ca import Node


def public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": acme._b64(numbers.x.to_bytes(32, "big")), "y": acme._b64(numbers.y.to_bytes(32, "big"))}


class ProtocolClient:
    def __init__(self, node):
        self.client = node.app.test_client()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = None
        self.base = "https://issuing.example"

    def jws(self, path, payload, *, nonce=None, key=None, jwk=False, url=None, nested=False):
        key = key or self.key
        header = {"alg": "ES256", "url": url or self.base + path}
        if not nested:
            header["nonce"] = nonce or self.client.head("/acme/new-nonce", base_url=self.base).headers["Replay-Nonce"]
        if jwk or not self.kid:
            header["jwk"] = public_jwk(key)
        else:
            header["kid"] = self.kid
        protected = acme._b64(acme._json(header).encode())
        encoded = "" if payload is None else acme._b64(acme._json(payload).encode())
        r, s = utils.decode_dss_signature(key.sign((protected + "." + encoded).encode(), ec.ECDSA(hashes.SHA256())))
        return {"protected": protected, "payload": encoded, "signature": acme._b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}

    def post(self, path, payload, **kwargs):
        path = urlsplit(path).path
        return self.client.post(path, base_url=self.base, data=acme._json(self.jws(path, payload, **kwargs)), content_type="application/jose+json")

    def binding(self, credential):
        header = {"alg": "HS256", "kid": credential["id"], "url": self.base + "/acme/new-account"}
        protected = acme._b64(acme._json(header).encode())
        encoded = acme._b64(acme._json(public_jwk(self.key)).encode())
        signature = hmac.new(acme._unb64(credential["secret"]), (protected + "." + encoded).encode(), hashlib.sha256).digest()
        return {"protected": protected, "payload": encoded, "signature": acme._b64(signature)}

    def register(self, credential):
        response = self.post("/acme/new-account", {"contact": ["mailto:test@example.com"], "externalAccountBinding": self.binding(credential)})
        if response.status_code == 201:
            self.kid = response.headers["Location"]
        return response


class AcmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pki.create_ca_certificate("ACME Root", 365, "root")
        cls.root_crl = x509.load_der_x509_crl(pki.build_crl(cls.root[0], cls.root[1], [], 1, 7)).public_bytes(serialization.Encoding.PEM).decode()

    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.node = Node(self, "issuing")
        authority = self.node.records("authorities")[-1]
        pem, *_ = pki.sign_ca_request(authority["csr_pem"], "issuing", 180, "root", self.root[0], self.root[1])
        self.node.post("/ca/activate", {"certificate_pem": pem, "chain_pem": self.root[0],
            "trusted_root_sha256": x509.load_pem_x509_certificate(self.root[0].encode()).fingerprint(hashes.SHA256()).hex()})
        self.node.post("/ca/parent-crls", {"parent_crls_pem": self.root_crl})
        self.node.post("/settings/certificate-templates", {"action": "save", "name": "ACME services", "description": "Test", "profile": "server",
            "default_validity_days": "30", "max_validity_days": "90", "dns_suffixes": "example.com", "roles": ["admin", "acme"], "enabled": "on", "allow_wildcards": "on"})
        with self.node.app.app_context():
            self.template = get_db().execute("SELECT id FROM certificate_templates WHERE name='ACME services'").fetchone()[0]
        saved = self.node.post("/settings/acme", {"action": "save", "enabled": "on", "http01": "on", "dns01": "on", "validity_days": "30"})
        self.assertIn(b"ACME settings saved", saved.data)
        self.protocol = ProtocolClient(self.node)
        self.credential = self.credential_for()
        self.assertEqual(self.protocol.register(self.credential).status_code, 201)

    def credential_for(self, domains="app.example.com,*.example.com"):
        page = self.node.post("/settings/acme", {"action": "create_eab", "label": "Test client", "domains": domains, "profile_id": str(self.template)})
        fields = re.search(rb"EAB key ID</dt><dd><code>([^<]+)</code></dd><dt>EAB HMAC key</dt><dd><code>([^<]+)</code>", page.data)
        self.assertIsNotNone(fields, page.data)
        return {"id": fields[1].decode(), "secret": fields[2].decode()}

    def test_contact_length_is_checked_before_validation(self):
        with self.assertRaises(acme.AcmeError):
            acme._contacts({"contact": ["mailto:" + "mailto:" * 40]})

    def new_order(self, names=("app.example.com",), protocol=None):
        response = (protocol or self.protocol).post("/acme/new-order", {"identifiers": [{"type": "dns", "value": name} for name in names]})
        self.assertEqual(response.status_code, 201, response.data)
        return response.headers["Location"], response.json

    def ready_order(self, names=("app.example.com",), kind="http-01"):
        order_url, order = self.new_order(names)
        for auth_url in order["authorizations"]:
            response = self.protocol.post(auth_url, None)
            self.assertEqual(response.status_code, 200, response.data)
            challenge = next(item for item in response.json["challenges"] if item["type"] == kind)
            with patch("acme_service.validate_http01") as http, patch("acme_service.validate_dns01") as dns:
                validation = self.protocol.post(challenge["url"], {})
                self.assertEqual(validation.json["status"], "valid", validation.data)
                (http if kind == "http-01" else dns).assert_called_once()
        self.assertEqual(self.protocol.post(order_url, None).json["status"], "ready")
        return order_url, order

    def csr(self, names=("app.example.com",), common_name=None, key=None, ca=False):
        key = key or ec.generate_private_key(ec.SECP256R1())
        subject = [] if common_name is None else [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
        if ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        return key, {"csr": acme._b64(der)}

    def test_complete_signed_enrollment_issue_download_and_revoke(self):
        order_url, order = self.ready_order()
        key, csr = self.csr()
        final = self.protocol.post(order["finalize"], csr)
        self.assertEqual(final.status_code, 200, final.data)
        self.assertEqual(final.json["status"], "valid")
        response = self.protocol.post(final.json["certificate"], None)
        self.assertEqual(response.mimetype, "application/pem-certificate-chain")
        chain = x509.load_pem_x509_certificates(response.data)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].public_key(), key.public_key())
        self.assertEqual(chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName), ["app.example.com"])
        self.assertEqual(self.protocol.post(order["finalize"], csr).json["certificate"], final.json["certificate"])
        certificates = self.node.records("certificates")
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0]["private_key_pem"], "")
        self.assertEqual(certificates[0]["template_id"], self.template)
        self.assertIn('"name": "ACME services"', certificates[0]["template_snapshot"])
        revoked = self.protocol.post("/acme/revoke-cert", {"certificate": acme._b64(chain[0].public_bytes(serialization.Encoding.DER)), "reason": 1})
        self.assertEqual(revoked.status_code, 200, revoked.data)
        self.assertTrue(self.node.records("certificates")[0]["revoked_at"])
        self.assertEqual(self.node.records("certificates")[0]["revocation_reason"], "key_compromise")
        with self.node.app.app_context():
            verify_chain(get_db(), self.node.app.config["KEY_ENCRYPTION_SECRET"])

    def test_nonce_replay_url_signature_and_post_as_get(self):
        path = "/acme/new-order"
        body = self.protocol.jws(path, {"identifiers": [{"type": "dns", "value": "app.example.com"}]})
        for status in (201, 400):
            response = self.protocol.client.post(path, base_url=self.protocol.base, data=acme._json(body), content_type="application/jose+json")
            self.assertEqual(response.status_code, status, response.data)
        self.assertTrue(response.json["type"].endswith(":badNonce"))
        self.assertIn("Replay-Nonce", response.headers)
        bad_url = self.protocol.post(path, {}, url=self.protocol.base + "/acme/directory")
        self.assertEqual(bad_url.status_code, 400)
        wrong_signature = self.protocol.post(path, {}, key=ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual(wrong_signature.status_code, 400)
        order_url, _ = self.new_order()
        self.assertEqual(self.protocol.post(order_url, {}).status_code, 400)

    def test_eab_required_one_use_expiry_and_secret_erasure(self):
        other = ProtocolClient(self.node)
        missing = other.post("/acme/new-account", {})
        self.assertTrue(missing.json["type"].endswith(":externalAccountRequired"))
        reused = other.register(self.credential)
        self.assertEqual(reused.status_code, 403)
        malformed = other.binding(self.credential)
        header = acme._loads(acme._unb64(malformed["protected"]))
        header["kid"] = []
        malformed["protected"] = acme._b64(acme._json(header).encode())
        self.assertEqual(other.post("/acme/new-account", {"externalAccountBinding": malformed}).status_code, 403)
        with self.node.app.app_context():
            self.assertEqual(get_db().execute("SELECT secret FROM acme_eab WHERE id=?", (self.credential["id"],)).fetchone()[0], "")
        credential = self.credential_for()
        with self.node.app.app_context():
            get_db().execute("UPDATE acme_eab SET expires='2000-01-01T00:00:00Z' WHERE id=?", (credential["id"],))
            get_db().commit()
        self.assertEqual(other.register(credential).status_code, 403)

    def test_cross_account_order_authorization_challenge_certificate_and_domains(self):
        other = ProtocolClient(self.node)
        self.assertEqual(other.register(self.credential_for()).status_code, 201)
        order_url, order = self.ready_order()
        _, csr = self.csr()
        certificate_url = self.protocol.post(order["finalize"], csr).json["certificate"]
        auth = self.protocol.post(order["authorizations"][0], None).json
        for resource in (order_url, order["authorizations"][0], auth["challenges"][0]["url"], certificate_url):
            response = other.post(resource, None)
            self.assertEqual(response.status_code, 403, response.data)
        rejected = self.protocol.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "evil.invalid"}]})
        self.assertTrue(rejected.json["type"].endswith(":rejectedIdentifier"))

    def test_csr_names_ca_escalation_weak_key_and_not_ready(self):
        _, order = self.new_order()
        _, csr = self.csr()
        self.assertTrue(self.protocol.post(order["finalize"], csr).json["type"].endswith(":orderNotReady"))
        _, ready = self.ready_order()
        bad_requests = [self.csr(("other.example.com",))[1], self.csr(common_name="other.example.com")[1],
                        self.csr(ca=True)[1], self.csr(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))[1]]
        for bad in bad_requests:
            response = self.protocol.post(ready["finalize"], bad)
            self.assertEqual(response.status_code, 400, response.data)
            self.assertTrue(response.json["type"].endswith(":badCSR"))
        self.assertEqual(self.node.records("certificates"), [])

    def test_policy_and_parent_crls_rechecked_at_finalize(self):
        _, order = self.ready_order()
        _, csr = self.csr()
        with self.node.app.app_context():
            get_db().execute("UPDATE certificate_templates SET dns_suffixes='[\"other.example.com\"]' WHERE id=?", (self.template,))
            get_db().commit()
        self.assertEqual(self.protocol.post(order["finalize"], csr).status_code, 400)
        with self.node.app.app_context():
            get_db().execute("UPDATE certificate_templates SET dns_suffixes='[\"example.com\"]' WHERE id=?", (self.template,))
            get_db().execute("UPDATE authorities SET parent_crls_pem=''")
            get_db().commit()
        self.assertEqual(self.protocol.post(order["finalize"], csr).status_code, 503)
        self.assertEqual(self.node.records("certificates"), [])

    def test_template_lifetime_caps_acme_default_and_long_names_fail_early(self):
        with self.node.app.app_context():
            get_db().execute("UPDATE certificate_templates SET default_validity_days=15,max_validity_days=30 WHERE id=?", (self.template,))
            get_db().execute("UPDATE settings SET value=? WHERE key='acme_config'", (acme._json({"enabled": True, "allow_private": False, "http01": True, "dns01": True, "validity_days": 90}),))
            get_db().commit()
        _, order = self.ready_order()
        _, csr = self.csr()
        self.assertEqual(self.protocol.post(order["finalize"], csr).json["status"], "valid")
        certificate = x509.load_pem_x509_certificate(self.node.records("certificates")[0]["certificate_pem"].encode())
        self.assertLessEqual((certificate.not_valid_after_utc - certificate.not_valid_before_utc).days, 15)
        long_name = "a" * 60 + ".example.com"
        response = self.protocol.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": long_name}]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("64-character", response.json["detail"])

    def test_wildcard_dns_challenge_and_validation_failure(self):
        order_url, order = self.new_order(("*.example.com",))
        auth = self.protocol.post(order["authorizations"][0], None).json
        self.assertTrue(auth["wildcard"])
        self.assertEqual(auth["identifier"]["value"], "example.com")
        self.assertEqual([item["type"] for item in auth["challenges"]], ["dns-01"])
        with patch("acme_service.validate_dns01", side_effect=acme.AcmeError("incorrectResponse", "No TXT proof.")):
            failed = self.protocol.post(auth["challenges"][0]["url"], {})
        self.assertEqual(failed.json["status"], "invalid")
        self.assertEqual(self.protocol.post(order_url, None).json["status"], "invalid")
        _, ready = self.ready_order(("*.example.com",), "dns-01")
        _, csr = self.csr(("*.example.com",))
        self.assertEqual(self.protocol.post(ready["finalize"], csr).json["status"], "valid")

    def test_account_key_rollover_then_deactivation(self):
        replacement = ec.generate_private_key(ec.SECP256R1())
        malformed = self.protocol.jws("/acme/key-change", [], key=replacement, jwk=True, nested=True)
        self.assertEqual(self.protocol.post("/acme/key-change", malformed).status_code, 400)
        inner = self.protocol.jws("/acme/key-change", {"account": self.protocol.kid, "oldKey": public_jwk(self.protocol.key)}, key=replacement, jwk=True, nested=True)
        response = self.protocol.post("/acme/key-change", inner)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.protocol.post(self.protocol.kid, None).status_code, 400)
        self.protocol.key = replacement
        self.assertEqual(self.protocol.post(self.protocol.kid, None).status_code, 200)
        self.assertEqual(self.protocol.post(self.protocol.kid, {"status": "deactivated"}).status_code, 200)
        self.assertEqual(self.protocol.post("/acme/new-order", {}).status_code, 403)

    def test_admin_csrf_and_audit_tampering(self):
        anonymous = self.node.app.test_client()
        response = anonymous.post("/settings/acme", base_url=self.node.base, data={"action": "save"})
        self.assertEqual(response.status_code, 302)
        response = self.node.client.post("/settings/acme", base_url=self.node.base, data={"action": "save"})
        self.assertEqual(response.status_code, 403)
        with self.node.app.app_context():
            get_db().execute("DROP TRIGGER audit_no_update")
            get_db().execute("UPDATE audit_events SET detail='tampered' WHERE id=(SELECT MIN(id) FROM audit_events)")
            get_db().commit()
        response = self.protocol.post("/acme/new-order", {})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.node.records("certificates"), [])

    def test_unauthenticated_requests_do_not_scan_audit_history_and_body_is_bounded(self):
        # Session-independent ACME authorization precedes expensive audit work.
        with patch("acme_service._verify_audit") as verify:
            response = self.protocol.client.post("/acme/new-order", base_url=self.protocol.base, data="{}", content_type="application/jose+json")
            self.assertEqual(response.status_code, 400)
            anonymous = ProtocolClient(self.node)
            self.assertEqual(anonymous.post("/acme/new-account", {}).status_code, 400)
            verify.assert_not_called()
            oversized = self.protocol.client.post("/acme/new-order", base_url=self.protocol.base, data="x" * 131073, content_type="application/jose+json")
            self.assertEqual(oversized.status_code, 413)
            with self.node.app.app_context():
                get_db().execute("UPDATE settings SET value=? WHERE key='acme_config'", (acme._json({"enabled": False}),))
                get_db().commit()
            disabled = self.protocol.client.post("/acme/new-order", base_url=self.protocol.base, data="{}", content_type="application/jose+json")
            self.assertEqual(disabled.status_code, 503)
            verify.assert_not_called()

    def test_certbot_client_library_interoperability(self):
        # Optional external interoperability check; core protocol tests above do
        # not need the Certbot development dependency to run.
        try:
            from acme import client, messages
            import josepy as jose
            import requests
        except ImportError:
            self.skipTest("Install the optional acme (Certbot client) package for interoperability verification.")
        flask_client = self.node.app.test_client()

        class FlaskTransport(requests.adapters.BaseAdapter):
            def send(self, prepared, **kwargs):
                result = flask_client.open(urlsplit(prepared.url).path, method=prepared.method, base_url="https://issuing.example",
                                           headers=dict(prepared.headers), data=prepared.body)
                response = requests.Response()
                response.status_code = result.status_code
                response.headers.update(result.headers)
                if result.headers.getlist("Link"):
                    response.headers["Link"] = ", ".join(result.headers.getlist("Link"))
                response._content = result.data
                response._content_consumed = True
                response.url = prepared.url
                response.request = prepared
                return response

            def close(self):
                pass

        key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
        network = client.ClientNetwork(key=key)
        self.addCleanup(network.session.close)
        network.session.mount("https://issuing.example", FlaskTransport())
        directory = messages.Directory.from_json(network.get("https://issuing.example/acme/directory").json())
        client_v2 = client.ClientV2(directory, network)
        credential = self.credential_for()
        binding = messages.ExternalAccountBinding.from_data(key.public_key(), credential["id"], credential["secret"], directory)
        registration = client_v2.new_account(messages.NewRegistration.from_data(email="certbot@example.com", terms_of_service_agreed=True, external_account_binding=binding))
        self.assertIn(registration.body.status, ("valid", messages.STATUS_VALID))
        cert_key, csr = self.csr()
        csr_pem = x509.load_der_x509_csr(acme._unb64(csr["csr"])).public_bytes(serialization.Encoding.PEM)
        order = client_v2.new_order(csr_pem)
        with patch("acme_service.validate_http01") as validator:
            for authorization in order.authorizations:
                challenge = next(item for item in authorization.body.challenges if item.chall.typ == "http-01")
                client_v2.answer_challenge(challenge, challenge.response(key))
            issued = client_v2.poll_and_finalize(order)
        validator.assert_called_once()
        chain = x509.load_pem_x509_certificates(issued.fullchain_pem.encode())
        self.assertEqual(chain[0].public_key(), cert_key.public_key())
        self.assertEqual(len(chain), 3)


if __name__ == "__main__":
    unittest.main()
