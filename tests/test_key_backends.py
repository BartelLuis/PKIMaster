"""External key lifecycle, strict Azure transport, and real isolated SoftHSM."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch
from urllib.error import HTTPError

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.x509.oid import SignatureAlgorithmOID

import key_backends as providers
import pki


class LocalTestSigner(providers.ExternalSigner):
    """An in-memory test double only; production has no fallback implementation."""

    def __init__(self, key):
        self.key = key

    def public_key(self):
        return self.key.public_key()

    def _sign(self, data):
        return self.key.sign(data, providers.pss_padding(), hashes.SHA256())


def check_pss(test, signed, public_key):
    test.assertEqual(signed.signature_algorithm_oid, SignatureAlgorithmOID.RSASSA_PSS)
    if not isinstance(signed, x509.CertificateRevocationList):
        test.assertEqual(signed.signature_hash_algorithm.name, "sha256")
    data = (signed.tbs_certificate_bytes if isinstance(signed, x509.Certificate) else
            signed.tbs_certlist_bytes if isinstance(signed, x509.CertificateRevocationList) else
            signed.tbs_certrequest_bytes)
    public_key.verify(signed.signature, data, providers.pss_padding(), hashes.SHA256())


class ExternalLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.child_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def test_complete_external_root_child_leaf_and_crl_lifecycle(self):
        root_signer, child_signer = LocalTestSigner(self.root_key), LocalTestSigner(self.child_key)
        root = pki.create_ca_certificate("External root", 3650, "root", signer=root_signer)
        self.assertEqual(root[1], "")
        root_certificate = x509.load_pem_x509_certificate(root[0].encode())
        check_pss(self, root_certificate, root_signer.public_key())
        request, private = pki.create_ca_request("External issuing", "issuing", signer=child_signer)
        self.assertEqual(private, "")
        csr = x509.load_pem_x509_csr(request.encode())
        check_pss(self, csr, child_signer.public_key())
        child = pki.sign_ca_request(request, "issuing", 365, "root", root[0], root_signer)
        check_pss(self, x509.load_pem_x509_certificate(child[0].encode()), root_signer.public_key())
        self.assertEqual(pki.validate_ca_activation(child[0], root[0], child_signer, "External issuing", "issuing"), root[0])
        with patch("pki.generate_private_key", return_value=self.root_key):
            leaf = pki.issue_end_entity_certificate("external.example", child[0], child_signer, 30, ["external.example"], minimum_rsa_bits=3072)
        check_pss(self, x509.load_pem_x509_certificate(leaf[0].encode()), child_signer.public_key())
        self.assertTrue(leaf[1].startswith("-----BEGIN RSA PRIVATE KEY-----"))
        crl = x509.load_der_x509_crl(pki.build_crl(child[0], child_signer, [{
            "serial_number": leaf[2], "revoked_at": (pki.utc_now() - timedelta(seconds=1)).isoformat(),
            "revocation_reason": "superseded",
        }], 9, 1))
        check_pss(self, crl, child_signer.public_key())
        self.assertTrue(pki.crl_signature_is_valid(crl, child_signer.public_key()))
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(leaf[2], 16)))
        with self.assertRaisesRegex(ValueError, "match"):
            pki.validate_ca_activation(child[0], root[0], root_signer, "External issuing", "issuing")
        with self.assertRaisesRegex(ValueError, "export"):
            pki.serialize_private_key(child_signer)

    def test_invalid_remote_signature_is_never_accepted(self):
        signer = LocalTestSigner(self.root_key)
        with patch.object(signer, "_sign", return_value=b"invalid"):
            with self.assertRaisesRegex(ValueError, "invalid signature"):
                pki.create_ca_certificate("Bad remote signature", 365, "root", signer=signer)
        with patch.object(signer, "sign", return_value=b"invalid"):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                pki.create_ca_request("Bad custom signer", "issuing", signer=signer)

    def test_software_rsa_signatures_also_use_pss(self):
        with patch("pki.generate_private_key", return_value=self.root_key):
            root = pki.create_ca_certificate("Software root", 365, "root")
            request, _ = pki.create_ca_request("Software child", "issuing")
        check_pss(self, x509.load_pem_x509_certificate(root[0].encode()), self.root_key.public_key())
        check_pss(self, x509.load_pem_x509_csr(request.encode()), self.root_key.public_key())
        check_pss(self, x509.load_der_x509_crl(pki.build_crl(root[0], root[1], [], 1, 1)), self.root_key.public_key())


class AzureProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    def setUp(self):
        self.config = {
            "vault_url": "https://pkimaster-test.vault.azure.net",
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "client_secret": "test-secret-never-log", "key_name": "ca-key", "key_type": "RSA-HSM",
        }
        self.kid = self.config["vault_url"] + "/keys/ca-key/" + "a" * 32
        public = self.key.public_key().public_numbers()
        self.bundle = {"key": {"kid": self.kid, "kty": "RSA-HSM", "key_ops": ["sign", "verify"],
                       "e": providers._base64(public.e.to_bytes(3, "big")),
                       "n": providers._base64(public.n.to_bytes(512, "big"))}, "attributes": {"enabled": True}}
        self.requests = []
        self.signature_kid = self.kid
        self.corrupt_signature = False
        self.transport = patch("key_backends._request_json", side_effect=self.fake_transport)
        self.transport.start()
        self.addCleanup(self.transport.stop)

    def fake_transport(self, method, url, body=None, **options):
        self.requests.append((method, url, body, options))
        if "login.microsoftonline.com" in url:
            self.assertEqual(body["scope"], "https://vault.azure.net/.default")
            self.assertEqual(body["grant_type"], "client_credentials")
            return {"access_token": "a.fake.token", "expires_in": 3600}
        self.assertEqual(options["headers"]["Authorization"], "Bearer a.fake.token")
        if "/create?" in url or method == "GET":
            return copy.deepcopy(self.bundle)
        self.assertEqual(url, self.kid + "/sign?api-version=" + providers.AZURE_API_VERSION)
        self.assertEqual(body["alg"], "PS256")
        signature = self.key.sign(providers._unbase64(body["value"]), providers.pss_padding(), utils.Prehashed(hashes.SHA256()))
        return {"kid": self.signature_kid, "value": providers._base64(b"bad" if self.corrupt_signature else signature)}

    def pinned(self):
        return {**self.config, "key_id": self.kid, "public_key_sha256": providers.public_key_fingerprint(self.key.public_key())}

    def test_provision_pins_version_and_load_only_gets_exact_key(self):
        signer, config = providers.provision_signer("azure", self.config)
        self.assertEqual(config["key_id"], self.kid)
        self.assertEqual(config["public_key_sha256"], providers.public_key_fingerprint(self.key.public_key()))
        create = next(request for request in self.requests if "/create?" in request[1])
        self.assertEqual(create[2]["key_size"], 4096)
        self.assertEqual(create[2]["key_ops"], ["sign", "verify"])
        self.assertFalse(create[2]["attributes"]["exportable"])
        self.assertFalse(hasattr(signer, "private_bytes"))
        self.requests.clear()
        loaded = providers.load_signer("azure", config)
        loaded.sign(b"local verification of cloud PS256")
        self.assertFalse(any("/create?" in request[1] for request in self.requests))
        self.assertTrue(any(request[1] == self.kid + "?api-version=" + providers.AZURE_API_VERSION for request in self.requests))

    def test_software_and_hsm_azure_protection_types_remain_distinct(self):
        for protection in ("RSA", "RSA-HSM"):
            with self.subTest(protection=protection):
                self.bundle["key"]["kty"] = protection
                _, config = providers.provision_signer("azure", {**self.config, "key_type": protection, "key_id": self.kid})
                self.assertEqual(config["key_type"], protection)
        self.bundle["key"]["kty"] = "RSA"
        with self.assertRaisesRegex(ValueError, "protection"):
            providers.load_signer("azure", self.pinned())

    def test_bad_signatures_and_wrong_versions_fail_closed(self):
        signer = providers.load_signer("azure", self.pinned())
        self.corrupt_signature = True
        with self.assertRaisesRegex(ValueError, "invalid signature"):
            signer.sign(b"test")
        self.corrupt_signature = False
        self.signature_kid = self.kid[:-1] + "b"
        with self.assertRaisesRegex(ValueError, "different key version"):
            signer.sign(b"test")

    def test_external_key_change_missing_pin_and_unversioned_urls_are_rejected(self):
        for changes in ({"public_key_sha256": "0" * 64}, {"public_key_sha256": ""},
                        {"key_id": self.kid.rsplit("/", 1)[0]},
                        {"key_id": self.kid.replace("pkimaster-test", "other-vault")},
                        {"key_id": self.kid + "?api-version=7.4"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                providers.load_signer("azure", {**self.pinned(), **changes})

    def test_malformed_or_unusable_cloud_key_is_rejected(self):
        original = copy.deepcopy(self.bundle)
        cases = [
            ("attributes", {"enabled": False}), ("attributes", {"enabled": True, "exp": 1}),
            ("attributes", {"enabled": True, "nbf": 99999999999}),
            ("attributes", {"enabled": True, "exportable": True}),
            ("release_policy", {"data": "export-policy"}),
            ("key", {**original["key"], "key_ops": ["sign", "decrypt"]}),
            ("key", {**original["key"], "d": "private-key-material"}),
            ("key", {**original["key"], "kid": self.kid[:-1] + "b"}),
        ]
        for name, value in cases:
            with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                self.bundle = {**original, name: value}
                providers.load_signer("azure", self.pinned())

    def test_untrusted_urls_and_invalid_tenant_never_receive_credentials(self):
        for value in ("http://example.vault.azure.net", "https://example.vault.azure.net.evil.test", "https://127.0.0.1", "https://user:secret@example.vault.azure.net", "https://example.vault.azure.net:443", "https://example.vault.azure.net/path"):
            self.requests.clear()
            with self.subTest(url=value), self.assertRaises(ValueError):
                providers.load_signer("azure", {**self.pinned(), "vault_url": value})
            self.assertEqual(self.requests, [])
        with self.assertRaises(ValueError):
            providers.load_signer("azure", {**self.pinned(), "tenant_id": "common/../evil"})

    def test_azure_signed_x509_is_verified_locally(self):
        signer = providers.load_signer("azure", self.pinned())
        result = pki.create_ca_certificate("Azure Key Vault root", 365, "root", signer=signer)
        self.assertEqual(result[1], "")
        check_pss(self, x509.load_pem_x509_certificate(result[0].encode()), self.key.public_key())


class ProviderTransportTests(unittest.TestCase):
    def test_redirects_are_rejected_and_network_errors_are_sanitized(self):
        with self.assertRaisesRegex(ValueError, "redirect"):
            providers._NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test")
        with patch("key_backends.build_opener") as build:
            build.return_value.open.side_effect = HTTPError("https://vault.example", 401, "SECRET", {}, None)
            with self.assertRaises(ValueError) as failure:
                providers._request_json("GET", "https://vault.example")
            self.assertNotIn("SECRET", str(failure.exception))

    def test_provider_errors_never_trigger_software_fallback(self):
        for method in (providers.load_signer, providers.provision_signer):
            with self.assertRaises(ValueError):
                method("missing", {})
        with patch("key_backends._request_json", side_effect=ValueError("offline")), self.assertRaises(ValueError):
            providers.load_signer("azure", {"vault_url": "https://ca-vault.vault.azure.net", "tenant_id": "1" * 32,
                "client_id": "2" * 32, "client_secret": "secret", "key_id": "https://ca-vault.vault.azure.net/keys/ca/" + "a" * 32,
                "public_key_sha256": "a" * 64})


SOFTHSM_MODULE = next((path for path in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if Path(path).is_file()), None)


@unittest.skipUnless(SOFTHSM_MODULE and importlib.util.find_spec("PyKCS11"), "Real SoftHSM/PyKCS11 is not installed")
class RealSoftHSMTests(unittest.TestCase):
    def test_real_nonextractable_key_and_complete_lifecycle_in_isolated_process(self):
        # A separate process isolates the PKCS#11 library's global C_Initialize
        # configuration from any application tests and never touches real tokens.
        with tempfile.TemporaryDirectory(prefix="pkimaster-softhsm-test-") as directory:
            storage = Path(directory)
            (storage / "tokens").mkdir(mode=0o700)
            configuration = storage / "softhsm2.conf"
            configuration.write_text(f"directories.tokendir = {storage / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
            script = r'''
import os
from datetime import timedelta
from cryptography import x509
from cryptography.x509.oid import SignatureAlgorithmOID
import key_backends as providers
import pki
config = {"module_path": os.environ["PKIMASTER_TEST_MODULE"], "token_label": "PKIMaster isolated test", "user_pin": "test-user-pin-92471"}
config = providers.initialize_softhsm(config, "test-officer-pin-85136")
assert "so_pin" not in config
try:
    providers.initialize_softhsm(config, "test-officer-pin-85136")
except ValueError:
    pass
else:
    raise AssertionError("existing token was initialized again")
signer, pinned = providers.provision_signer("pkcs11", config)
assert signer.public_key().key_size == 4096
assert pinned["token_serial"] and pinned["key_id"] and pinned["public_key_sha256"]
root = pki.create_ca_certificate("SoftHSM root", 365, "root", signer=signer)
assert root[1] == ""
certificate = x509.load_pem_x509_certificate(root[0].encode())
certificate.verify_directly_issued_by(certificate)
assert certificate.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS
loaded = providers.load_signer("pkcs11", pinned)
child_signer, child_pinned = providers.provision_signer("pkcs11", config)
csr, private = pki.create_ca_request("SoftHSM issuing", "issuing", signer=child_signer)
assert private == ""
child = pki.sign_ca_request(csr, "issuing", 90, "root", root[0], loaded)
pki.validate_ca_activation(child[0], root[0], child_signer, "SoftHSM issuing", "issuing")
leaf = pki.issue_end_entity_certificate("token.example", child[0], child_signer, 10, ["token.example"])
x509.load_pem_x509_certificate(leaf[0].encode()).verify_directly_issued_by(x509.load_pem_x509_certificate(child[0].encode()))
crl = x509.load_der_x509_crl(pki.build_crl(child[0], child_signer, [{"serial_number": leaf[2], "revoked_at": (pki.utc_now() - timedelta(seconds=1)).isoformat(), "revocation_reason": "superseded"}], 2, 1))
assert pki.crl_signature_is_valid(crl, child_signer.public_key())
for changes in ({"user_pin": "incorrect-pin"}, {"key_id": "ff" * 20}, {"public_key_sha256": "0" * 64}, {"token_serial": "wrong-token"}):
    try:
        providers.load_signer("pkcs11", {**pinned, **changes})
    except ValueError:
        pass
    else:
        raise AssertionError("changed identity or wrong credentials accepted")
with providers._token_session(pinned) as (api, session, _):
    _, private = providers._token_keys(api, session, pinned)
    assert session.getAttributeValue(private, [api.CKA_EXTRACTABLE, api.CKA_SENSITIVE]) == [False, True]
    try:
        exponent = session.getAttributeValue(private, [api.CKA_PRIVATE_EXPONENT])[0]
        assert not exponent
    except api.PyKCS11Error:
        pass
os.environ["SOFTHSM2_CONF"] += ".changed"
try:
    providers.load_signer("pkcs11", pinned)
except ValueError:
    pass
else:
    raise AssertionError("changed token store silently reused cached library")
print("Real SoftHSM lifecycle and nonextractability checks passed")
'''
            environment = {**os.environ, "SOFTHSM2_CONF": str(configuration), "PKIMASTER_TEST_MODULE": SOFTHSM_MODULE}
            result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1], env=environment,
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
