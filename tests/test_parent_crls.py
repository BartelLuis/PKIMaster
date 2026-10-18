"""Parent CRL discovery, authenticated fallback and revocation propagation."""
from datetime import UTC, datetime, timedelta
import unittest
from unittest.mock import call, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import validate_parent_crls
from monitoring_transports import MAX_DOWNLOAD, MonitoringError
from parent_crls import ParentCRLError, fetch_parent_crls, parent_crl_sources


def point(*urls, **kwargs):
    return x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(url) for url in urls] or None,
        relative_name=kwargs.get("relative_name"), reasons=kwargs.get("reasons"),
        crl_issuer=kwargs.get("crl_issuer"))


class ParentCRLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime.now(UTC).replace(microsecond=0)
        cls.root_key = ec.generate_private_key(ec.SECP256R1())
        cls.parent_key = ec.generate_private_key(ec.SECP256R1())
        cls.child_key = ec.generate_private_key(ec.SECP256R1())
        cls.root = cls.certificate("Root", cls.root_key, points=[point("https://root.example/irrelevant.crl")])
        cls.parent = cls.certificate("Intermediate", cls.parent_key, cls.root, cls.root_key,
                                     [point("https://root.example/crl")])
        cls.child = cls.certificate("Issuing", cls.child_key, cls.parent, cls.parent_key,
                                    [point("https://intermediate.example/crl")])

    @classmethod
    def certificate(cls, name, key, issuer=None, issuer_key=None, points=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(issuer.subject if issuer else subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(cls.now - timedelta(days=1)).not_valid_after(cls.now + timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
        if points is not None:
            builder = builder.add_extension(x509.CRLDistributionPoints(points), critical=False)
        return builder.sign(issuer_key or key, hashes.SHA256())

    @classmethod
    def crl(cls, issuer, key, *, stale=False, revoked=None, extension=None):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
                   .last_update(cls.now - timedelta(days=2))
                   .next_update(cls.now + timedelta(days=-1 if stale else 1))
                   .add_extension(x509.CRLNumber(1), critical=False))
        if revoked:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder()
                .serial_number(revoked.serial_number).revocation_date(cls.now - timedelta(hours=1)).build())
        if extension:
            builder = builder.add_extension(extension, critical=True)
        return builder.sign(key, hashes.SHA256())

    @staticmethod
    def pem(item):
        return item.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def authority(self, child=None, parents=None):
        return {"certificate_pem": self.pem(child or self.child),
                "parent_chain_pem": "".join(self.pem(parent) for parent in (parents if parents is not None else [self.parent, self.root]))}

    def test_discovery_uses_each_child_cdp_and_never_root_cdp_or_network(self):
        with patch("monitoring_transports.http_request") as request:
            self.assertEqual(parent_crl_sources(self.authority()),
                             [["https://intermediate.example/crl"], ["https://root.example/crl"]])
        request.assert_not_called()

    def test_discovery_deduplicates_supported_urls_and_ignores_unsupported_points(self):
        child = self.certificate("Issuing", self.child_key, self.parent, self.parent_key, [
            point("https://partial.example/crl", reasons=frozenset([x509.ReasonFlags.key_compromise])),
            point("https://indirect.example/crl", crl_issuer=[x509.DirectoryName(self.root.subject)]),
            point("ldap://directory.example/crl", "https://intermediate.example/crl"),
            point("https://intermediate.example/crl", "http://mirror.example/crl")])
        self.assertEqual(parent_crl_sources(self.authority(child))[0],
                         ["https://intermediate.example/crl", "http://mirror.example/crl"])

    def test_discovery_rejects_absent_and_unsupported_distribution_points(self):
        unsupported = [
            None,
            [point("ldap://directory.example/crl")],
            [point("https://partial.example/crl", reasons=frozenset([x509.ReasonFlags.key_compromise]))],
            [point("https://indirect.example/crl", crl_issuer=[x509.DirectoryName(self.root.subject)])],
            [point(relative_name=x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "relative")]))],
            [point("https://secret:password@example.com/crl")],
            [point("https://example.com/crl#fragment")],
        ]
        with patch("monitoring_transports.http_request") as request:
            for points in unsupported:
                with self.subTest(points=points):
                    child = self.certificate("Issuing", self.child_key, self.parent, self.parent_key, points)
                    with self.assertRaises(ParentCRLError) as caught:
                        parent_crl_sources(self.authority(child))
                    self.assertNotIn("password", str(caught.exception))
        request.assert_not_called()

    def test_all_ancestors_need_sources_before_any_download(self):
        parent = self.certificate("Intermediate", self.parent_key, self.root, self.root_key)
        with patch("monitoring_transports.http_request") as request, self.assertRaisesRegex(ParentCRLError, "parent CRL 2.*no CRL distribution"):
            fetch_parent_crls(self.authority(parents=[parent, self.root]))
        request.assert_not_called()

    def test_discovery_rejects_excessive_sources_and_parent_count(self):
        child = self.certificate("Issuing", self.child_key, self.parent, self.parent_key,
                                 [point(*(f"https://mirror{index}.example/crl" for index in range(4)))])
        with self.assertRaisesRegex(ParentCRLError, "more than three"):
            parent_crl_sources(self.authority(child))
        with self.assertRaisesRegex(ParentCRLError, "eight parent"):
            parent_crl_sources(self.authority(parents=[self.root] * 9))
        with self.assertRaises(ParentCRLError):
            parent_crl_sources(self.authority(child=self.root, parents=[]))

    def test_fetch_canonicalizes_der_and_pem_in_immediate_issuer_to_root_order(self):
        parent_crl = self.crl(self.parent, self.parent_key)
        root_crl = self.crl(self.root, self.root_key)
        expected = self.pem(parent_crl) + self.pem(root_crl)
        with patch("monitoring_transports.http_request", side_effect=[
                parent_crl.public_bytes(serialization.Encoding.DER), ("\n\n" + self.pem(root_crl) + "\n").encode()]) as request:
            self.assertEqual(fetch_parent_crls(self.authority()), expected)
        self.assertEqual(request.call_args_list, [
            call("https://intermediate.example/crl", limit=MAX_DOWNLOAD),
            call("https://root.example/crl", limit=MAX_DOWNLOAD)])
        self.assertEqual(validate_parent_crls(self.authority(), expected), expected)

    def test_explicit_sources_work_without_cdp_and_deduplicate(self):
        child = self.certificate("Issuing", self.child_key, self.root, self.root_key)
        crl = self.crl(self.root, self.root_key)
        with patch("monitoring_transports.http_request", return_value=self.pem(crl).encode()) as request:
            self.assertEqual(fetch_parent_crls(self.authority(child, [self.root]),
                [["https://manual.example/crl", "https://manual.example/crl"]]), self.pem(crl))
        request.assert_called_once_with("https://manual.example/crl", limit=MAX_DOWNLOAD)

    def test_explicit_sources_are_all_validated_before_network(self):
        invalid = [[], [["https://ok.example/crl"]],
                   [["https://ok.example/crl"], []],
                   [["https://ok.example/crl"], ["file:///private/key"]],
                   [["https://ok.example/crl"], ["https://user:secret@example.com/crl"]],
                   [["https://ok.example/crl"], [None]],
                   [["https://ok.example/crl"], ["https://mirror.example/" + str(index) for index in range(4)]]]
        with patch("monitoring_transports.http_request") as request:
            for sources in invalid:
                with self.subTest(sources=sources), self.assertRaises(ParentCRLError):
                    fetch_parent_crls(self.authority(), sources)
        request.assert_not_called()

    def test_network_parse_signature_freshness_and_scope_errors_try_next_source(self):
        good = self.crl(self.root, self.root_key)
        failures = [MonitoringError("unavailable"), b"<html>not a CRL</html>",
                    self.crl(self.root, self.parent_key).public_bytes(serialization.Encoding.DER),
                    self.crl(self.root, self.root_key, stale=True).public_bytes(serialization.Encoding.DER),
                    self.crl(self.root, self.root_key, extension=x509.DeltaCRLIndicator(0)).public_bytes(serialization.Encoding.DER),
                    self.crl(self.root, self.root_key, extension=x509.IssuingDistributionPoint(
                        None, None, False, True, None, False, False)).public_bytes(serialization.Encoding.DER),
                    self.pem(good).encode() * 2,
                    good.public_bytes(serialization.Encoding.DER) + b"trailing bytes"]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch("monitoring_transports.http_request",
                    side_effect=[failure, self.pem(good).encode()]) as request:
                result = fetch_parent_crls(self.authority(self.parent, [self.root]),
                    [["https://broken.example/crl", "https://working.example/crl"]])
                self.assertEqual(result, self.pem(good))
                self.assertEqual(request.call_count, 2)

    def test_all_failed_candidates_raise_safe_error_without_partial_state(self):
        authority = self.authority()
        previous = authority.copy()
        parent_crl = self.crl(self.parent, self.parent_key)
        with patch("monitoring_transports.http_request", side_effect=[
                self.pem(parent_crl).encode(), MonitoringError("private response and credentials")]), \
                self.assertRaisesRegex(ParentCRLError, "parent 2") as caught:
            fetch_parent_crls(authority)
        self.assertNotIn("private response", str(caught.exception))
        self.assertEqual(authority, previous)

    def test_overall_deadline_prevents_more_downloads_or_partial_results(self):
        crl = self.crl(self.parent, self.parent_key)
        with patch("monitoring_transports.http_request", return_value=self.pem(crl).encode()) as request, \
                patch("parent_crls.time.monotonic", side_effect=[0, 0, 121]), \
                self.assertRaisesRegex(ParentCRLError, "overall time limit"):
            fetch_parent_crls(self.authority())
        request.assert_called_once_with("https://intermediate.example/crl", limit=MAX_DOWNLOAD)

    def test_authenticated_child_and_ancestor_revocation_never_falls_back(self):
        for revoke_ancestor in (False, True):
            parent_crl = self.crl(self.parent, self.parent_key, revoked=None if revoke_ancestor else self.child)
            root_crl = self.crl(self.root, self.root_key, revoked=self.parent if revoke_ancestor else None)
            expected = self.pem(parent_crl) + self.pem(root_crl)
            with self.subTest(revoke_ancestor=revoke_ancestor), patch("monitoring_transports.http_request",
                    side_effect=[self.pem(parent_crl).encode(), self.pem(root_crl).encode()]) as request:
                self.assertEqual(fetch_parent_crls(self.authority(), [
                    ["https://intermediate.example/crl", "https://intermediate-mirror.example/crl"],
                    ["https://root.example/crl", "https://root-mirror.example/crl"]]), expected)
                self.assertEqual(request.call_args_list, [call("https://intermediate.example/crl", limit=MAX_DOWNLOAD),
                    call("https://root.example/crl", limit=MAX_DOWNLOAD)])
            with self.assertRaisesRegex(ValueError, "ancestor is revoked"):
                validate_parent_crls(self.authority(), expected)


if __name__ == "__main__":
    unittest.main()
