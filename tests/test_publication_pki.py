"""Signed certificate publication extensions follow RFC 5280 section 4.2.2.1."""
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID

from key_backends import ExternalSigner, pss_padding
import pki


class TestExternalSigner(ExternalSigner):
    def __init__(self, key):
        self.key = key

    def public_key(self):
        return self.key.public_key()

    def _sign(self, data):
        return self.key.sign(data, pss_padding(), hashes.SHA256())


class PublicationExtensionTests(unittest.TestCase):
    root_aia = "https://publication.example/ca/root.cer"
    root_crl = "http://publication.example/crls/root.crl"
    issuer_aia = "http://publication.example:8080/ca/issuing.cer"
    issuer_crl = "https://publication.example/crls/issuing.crl"

    @classmethod
    def setUpClass(cls):
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.child_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with patch("pki.generate_private_key", return_value=cls.root_key):
            cls.root = pki.create_ca_certificate("Publication root", 365, "root")
        with patch("pki.generate_private_key", return_value=cls.child_key):
            cls.request, cls.child_private = pki.create_ca_request("Publication issuing", "issuing")
        cls.child = pki.sign_ca_request(cls.request, "issuing", 90, "root", cls.root[0], cls.root[1],
                                       crl_url=cls.root_crl, aia_url=cls.root_aia)
        cls.root_certificate = x509.load_pem_x509_certificate(cls.root[0].encode())
        cls.child_certificate = x509.load_pem_x509_certificate(cls.child[0].encode())

    def certificate(self, pem):
        # Check the extensions as decoded from the final signed DER artifact.
        loaded = x509.load_pem_x509_certificate(pem.encode())
        return x509.load_der_x509_certificate(loaded.public_bytes(serialization.Encoding.DER))

    def assert_discovery(self, certificate, issuer, aia_url, crl_url):
        certificate.verify_directly_issued_by(issuer)
        extension = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        self.assertFalse(extension.critical)
        self.assertEqual(len(extension.value), 1)
        descriptor = extension.value[0]
        self.assertEqual(descriptor.access_method, AuthorityInformationAccessOID.CA_ISSUERS)
        self.assertIsInstance(descriptor.access_location, x509.UniformResourceIdentifier)
        self.assertEqual(descriptor.access_location.value, aia_url)
        crl = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        self.assertFalse(crl.critical)
        self.assertEqual([name.value for name in crl.value[0].full_name], [crl_url])
        self.assertNotEqual(aia_url, crl_url)

    def test_signed_ca_request_points_to_parent_certificate_and_crl(self):
        certificate = self.certificate(self.child[0])
        self.assert_discovery(certificate, self.root_certificate, self.root_aia, self.root_crl)
        self.assertEqual(pki.validate_ca_activation(self.child[0], self.root[0], self.child_private,
                                                   "Publication issuing", "issuing"), self.root[0])

    def test_legacy_ca_builder_supports_issuer_publication(self):
        with patch("pki.generate_private_key", return_value=self.child_key):
            result = pki.create_ca_certificate("Legacy child", 90, "issuing", "root", self.root[0], self.root[1],
                                               crl_url=self.root_crl, aia_url=self.root_aia)
        self.assert_discovery(self.certificate(result[0]), self.root_certificate, self.root_aia, self.root_crl)

    def test_leaf_uses_issuing_certificate_not_root_or_child_url(self):
        with patch("pki.generate_private_key", return_value=self.root_key):
            result = pki.issue_end_entity_certificate("service.example", self.child[0], self.child_private, 30,
                ["service.example"], aia_url=self.issuer_aia, crl_url=self.issuer_crl)
        self.assert_discovery(self.certificate(result[0]), self.child_certificate, self.issuer_aia, self.issuer_crl)

    def test_external_provider_preserves_aia_when_signing_certificates(self):
        signer = TestExternalSigner(self.root_key)
        result = pki.sign_ca_request(self.request, "issuing", 90, "root", self.root[0], signer,
                                     self.root_crl, aia_url=self.root_aia)
        self.assert_discovery(self.certificate(result[0]), self.root_certificate, self.root_aia, self.root_crl)
        with patch("pki.generate_private_key", return_value=self.root_key):
            leaf = pki.issue_end_entity_certificate("external.example", self.child[0], TestExternalSigner(self.child_key),
                30, ["external.example"], aia_url=self.issuer_aia, crl_url=self.issuer_crl)
        self.assert_discovery(self.certificate(leaf[0]), self.child_certificate, self.issuer_aia, self.issuer_crl)

    def test_root_and_default_calls_do_not_invent_publication_endpoints(self):
        for extension in (x509.AuthorityInformationAccess, x509.CRLDistributionPoints):
            with self.assertRaises(x509.ExtensionNotFound):
                self.root_certificate.extensions.get_extension_for_class(extension)
        result = pki.sign_ca_request(self.request, "issuing", 90, "root", self.root[0], self.root[1])
        for extension in (x509.AuthorityInformationAccess, x509.CRLDistributionPoints):
            with self.assertRaises(x509.ExtensionNotFound):
                self.certificate(result[0]).extensions.get_extension_for_class(extension)

    def test_explicit_root_publication_remains_backward_compatible(self):
        result = pki.create_ca_certificate("Explicit root", 365, "root", signer=TestExternalSigner(self.root_key),
                                           crl_url=self.root_crl, aia_url=self.root_aia)
        certificate = self.certificate(result[0])
        self.assert_discovery(certificate, certificate, self.root_aia, self.root_crl)
        self.assertEqual(result[1], "")

    def test_requested_csr_publication_urls_are_not_copied(self):
        requested_aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier("https://untrusted.example/ocsp")),
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("https://untrusted.example/wrong.cer")),
        ])
        builder = (x509.CertificateSigningRequestBuilder().subject_name(pki.build_subject("Requested endpoint"))
                   .add_extension(requested_aia, critical=False))
        request = builder.sign(self.root_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
        result = pki.issue_end_entity_certificate("service.example", self.child[0], self.child_private, 30,
            ["service.example"], csr_pem=request, aia_url=self.issuer_aia, crl_url=self.issuer_crl)
        self.assertEqual(result[1], "")
        self.assert_discovery(self.certificate(result[0]), self.child_certificate, self.issuer_aia, self.issuer_crl)
        without_aia = pki.issue_end_entity_certificate("service.example", self.child[0], self.child_private, 30,
            ["service.example"], csr_pem=request)
        with self.assertRaises(x509.ExtensionNotFound):
            self.certificate(without_aia[0]).extensions.get_extension_for_class(x509.AuthorityInformationAccess)

    def test_invalid_publication_urls_are_rejected_before_external_signing(self):
        values = ("", "/issuer.cer", "//example/issuer.cer", "ftp://example/issuer.cer", "https:///issuer.cer",
                  "https://user:password@example/issuer.cer", "https://@example/issuer.cer", "https://example/issuer.cer#part",
                  "https://example/issuer.cer#", "https://example\\evil/issuer.cer", "https://example/path\\file.cer",
                  "https://example:0/issuer.cer", "https://example:65536/issuer.cer", "https://example:/issuer.cer",
                  "https://example:abc/issuer.cer", "https://bad_host/issuer.cer", "https://*.example/issuer.cer",
                  "https://example/white space.cer", "https://example/\r\nissuer.cer", "https://example/\x7fissuer.cer",
                  "https://example/issuer.cer\t", "https://exämple/issuer.cer", "https://example/%5cissuer.cer",
                  "https://example/%0d%0aissuer.cer", "https://example/invalid%escape", "https://[fe80::1%25eth0]/ca.cer",
                  443, b"https://example/issuer.cer")
        signer = TestExternalSigner(self.root_key)
        for field in ("aia_url", "crl_url"):
            for value in values:
                with self.subTest(field=field, value=value), patch.object(signer, "_sign") as sign:
                    with self.assertRaises(ValueError):
                        pki.sign_ca_request(self.request, "issuing", 90, "root", self.root[0], signer, **{field: value})
                    sign.assert_not_called()
        for factory in (
            lambda: pki.create_ca_certificate("Invalid root AIA", 365, "root", signer=signer, aia_url="file:///key.pem"),
            lambda: pki.issue_end_entity_certificate("service.example", self.child[0], TestExternalSigner(self.child_key),
                30, ["service.example"], aia_url="https://user:password@example/issuer.cer"),
        ):
            with patch("pki.generate_private_key", return_value=self.root_key), self.assertRaises(ValueError):
                factory()

    def test_ascii_dns_and_ip_urls_keep_exact_locations(self):
        for value in ("https://xn--bcher-kva.example/issuer.cer", "http://192.0.2.10:8080/issuer.cer",
                      "https://[2001:db8::1]:8443/issuer.cer", "https://publication.example/issuer%20certificate.cer?version=1"):
            with self.subTest(url=value):
                result = pki.sign_ca_request(self.request, "issuing", 90, "root", self.root[0], self.root[1], aia_url=value)
                certificate = self.certificate(result[0])
                certificate.verify_directly_issued_by(self.root_certificate)
                location = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value[0].access_location
                self.assertEqual(location.value, value)


if __name__ == "__main__":
    unittest.main()
