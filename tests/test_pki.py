import base64
import ipaddress
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

import pki


class SubjectAlternativeNameTests(unittest.TestCase):
    def test_dns_idna_ip_and_wildcards_are_canonicalized_and_deduplicated(self):
        names = pki.parse_subject_alt_names(
            "DNS:WWW.Example.COM., www.example.com, bücher.example\n"
            "*.apps.example.com, 192.0.2.7, IP:2001:0db8::7, 2001:db8::7"
        )
        self.assertEqual(
            [(type(name), str(name.value)) for name in names],
            [
                (x509.DNSName, "www.example.com"),
                (x509.DNSName, "xn--bcher-kva.example"),
                (x509.DNSName, "*.apps.example.com"),
                (x509.IPAddress, "192.0.2.7"),
                (x509.IPAddress, "2001:db8::7"),
            ],
        )

    def test_invalid_names_are_rejected(self):
        for value in (
            "https://example.com", "user@example.com", "foo.*.example.com", "f*.example.com",
            "*.com", "*", "bad_name.example", "-bad.example", "bad-.example", "bad..example",
            "example.com..", "bad name.example", "a" * 64 + ".example", ".example", "xn--.example",
            "IP:999.0.0.1", "999.0.0.1", "IP:example.com", "fe80::1%eth0", "192.0.2.0/24",
            "DNS:192.0.2.1", "bad\x00.example", "DNS:", "IP:", "2001:::1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pki.parse_subject_alt_names([value])

    def test_too_many_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "100"):
            pki.parse_subject_alt_names([f"host{index}.example" for index in range(101)])

    def test_invalid_common_names_are_rejected(self):
        for common_name in ("", "   ", "a" * 65, "ü" * 33, "name\x00bad", "a\nb", "a\u202eb"):
            with self.subTest(common_name=common_name), self.assertRaises(ValueError):
                pki.build_subject(common_name)


class CertificateLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_result = pki.create_ca_certificate("Test Root CA", 30, "root")
        cls.root_pem, cls.root_key_pem = cls.root_result[:2]
        cls.root = x509.load_pem_x509_certificate(cls.root_pem.encode())
        cls.root_key = serialization.load_pem_private_key(cls.root_key_pem.encode(), None)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())
        cls.csr_pem = cls.make_csr(cls.ec_key, [x509.DNSName("requested.example")])

    @staticmethod
    def make_csr(key, names=(), extensions=()):
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CSR subject is not trusted")])
        )
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        for value, critical in extensions:
            builder = builder.add_extension(value, critical=critical)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def issuer_with_constraints(cls, *, ca=True, path_length=2, key_cert_sign=True, crl_sign=True, days=2):
        now = datetime.now(UTC).replace(microsecond=0)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(pki.build_subject("Restricted CA"))
            .issuer_name(cls.root.subject)
            .serial_number(x509.random_serial_number())
            .public_key(cls.ec_key.public_key())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca, path_length if ca else None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, key_cert_sign, crl_sign, False, False), critical=True)
            .sign(cls.root_key, hashes.SHA256())
        )
        key_pem = cls.ec_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        return pki.serialize_certificate(certificate), key_pem

    def issue(self, **kwargs):
        options = dict(
            common_name="approved.example", issuer_certificate_pem=self.root_pem,
            issuer_private_key_pem=self.root_key_pem, validity_days=90,
            subject_alt_names=[], csr_pem=self.csr_pem,
        )
        options.update(kwargs)
        result = pki.issue_end_entity_certificate(**options)
        return result, x509.load_pem_x509_certificate(result[0].encode())

    def test_root_has_rsa_4096_matching_key_and_ca_signing_extensions(self):
        self.assertEqual(self.root.public_key().key_size, 4096)
        self.assertEqual(self.root.public_key().public_numbers(), self.root_key.public_key().public_numbers())
        self.root.verify_directly_issued_by(self.root)
        self.assertEqual(self.root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 2)
        usage = self.root.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.key_cert_sign)
        self.assertTrue(usage.crl_sign)
        self.assertEqual(datetime.fromisoformat(self.root_result[4]), self.root.not_valid_after_utc)

    def test_generated_end_entity_has_rsa_4096_and_matching_key(self):
        result, certificate = self.issue(csr_pem=None)
        key = serialization.load_pem_private_key(result[1].encode(), None)
        self.assertEqual(certificate.public_key().key_size, 4096)
        self.assertEqual(certificate.public_key().public_numbers(), key.public_key().public_numbers())
        certificate.verify_directly_issued_by(self.root)

    def test_csr_certificate_uses_request_key_and_approved_subject(self):
        result, certificate = self.issue()
        self.assertEqual(result[1], "")
        self.assertEqual(certificate.public_key().public_numbers(), self.ec_key.public_key().public_numbers())
        self.assertEqual(certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "approved.example")
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName), ["requested.example"])
        certificate.verify_directly_issued_by(self.root)
        self.assertFalse(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment)

    def test_expiry_and_start_are_bounded_by_issuer(self):
        issuer_pem, key_pem = self.issuer_with_constraints(days=1)
        issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
        _, certificate = self.issue(issuer_certificate_pem=issuer_pem, issuer_private_key_pem=key_pem)
        self.assertEqual(certificate.not_valid_after_utc, issuer.not_valid_after_utc)
        self.assertEqual(certificate.not_valid_before_utc, issuer.not_valid_before_utc)

    def test_profiles_only_grant_selected_eku(self):
        for profile, expected in (
            ("server", [ExtendedKeyUsageOID.SERVER_AUTH]),
            ("client", [ExtendedKeyUsageOID.CLIENT_AUTH]),
            ("dual", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
        ):
            with self.subTest(profile=profile):
                _, certificate = self.issue(profile=profile)
                self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), expected)
        with self.assertRaises(ValueError):
            self.issue(profile="code_signing")

    def test_explicit_sans_replace_csr_sans_and_are_typed(self):
        _, certificate = self.issue(subject_alt_names=["approved.example", "192.0.2.2", "2001:db8::2"])
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(sans.get_values_for_type(x509.DNSName), ["approved.example"])
        self.assertEqual(sans.get_values_for_type(x509.IPAddress), [ipaddress.ip_address("192.0.2.2"), ipaddress.ip_address("2001:db8::2")])

    def test_client_can_use_a_person_name_without_sans(self):
        _, certificate = self.issue(common_name="Alex Example", profile="client", csr_pem=self.make_csr(self.ec_key))
        with self.assertRaises(x509.ExtensionNotFound):
            certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    def test_server_without_sans_uses_common_name(self):
        _, certificate = self.issue(common_name="192.0.2.8", csr_pem=self.make_csr(self.ec_key))
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress), [ipaddress.ip_address("192.0.2.8")])

    def test_csr_cannot_elevate_extensions(self):
        custom_oid = ObjectIdentifier("1.2.3.4.5")
        csr = self.make_csr(self.ec_key, extensions=[
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False),
            (x509.UnrecognizedExtension(custom_oid, b"arbitrary"), True),
        ])
        _, certificate = self.issue(csr_pem=csr)
        self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
        with self.assertRaises(x509.ExtensionNotFound):
            certificate.extensions.get_extension_for_oid(custom_oid)

    def test_ca_csrs_and_unsupported_san_types_are_rejected(self):
        requests = [
            self.make_csr(self.ec_key, extensions=[(x509.BasicConstraints(True, 0), True)]),
            self.make_csr(self.ec_key, extensions=[(x509.KeyUsage(False, False, False, False, False, True, False, False, False), True)]),
            self.make_csr(self.ec_key, names=[x509.UniformResourceIdentifier("spiffe://example/workload")]),
            self.make_csr(self.ec_key, names=[x509.DNSName("bad_name.example")]),
        ]
        for csr in requests:
            with self.subTest(csr=csr[:45]), self.assertRaises(ValueError):
                self.issue(csr_pem=csr, subject_alt_names=["approved.example"])

    def test_invalid_csr_signature_is_rejected(self):
        csr = x509.load_pem_x509_csr(self.csr_pem.encode())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE REQUEST-----\n"
        with self.assertRaisesRegex(ValueError, "signature"):
            self.issue(csr_pem=pem)

    def test_weak_rsa_and_unapproved_ec_curves_are_rejected(self):
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=1024), ec.generate_private_key(ec.SECP256K1())]
        for key in keys:
            with self.subTest(key=type(key).__name__), self.assertRaises(ValueError):
                self.issue(csr_pem=self.make_csr(key))

    def test_supported_csr_keys_are_accepted(self):
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP521R1())]
        for key in keys:
            with self.subTest(key=type(key).__name__):
                _, certificate = self.issue(csr_pem=self.make_csr(key))
                self.assertEqual(certificate.public_key().public_numbers(), key.public_key().public_numbers())

    def test_expired_and_future_issuers_are_rejected(self):
        for now in (self.root.not_valid_before_utc - timedelta(seconds=1), self.root.not_valid_after_utc):
            with self.subTest(now=now), patch("pki.utc_now", return_value=now), self.assertRaises(ValueError):
                self.issue()

    def test_non_ca_and_missing_signing_usage_are_rejected(self):
        for options in ({"ca": False}, {"key_cert_sign": False}):
            issuer_pem, key_pem = self.issuer_with_constraints(**options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.issue(issuer_certificate_pem=issuer_pem, issuer_private_key_pem=key_pem)

    def test_mismatched_issuer_key_is_rejected(self):
        issuer_pem, _ = self.issuer_with_constraints()
        with self.assertRaisesRegex(ValueError, "do not match"):
            self.issue(issuer_certificate_pem=issuer_pem)

    def test_actual_parent_path_constraint_and_expiry_limit_child(self):
        issuer_pem, key_pem = self.issuer_with_constraints(path_length=1, days=1)
        issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
        result = pki.create_ca_certificate("Limited Intermediate", 100, "intermediate", "root", issuer_pem, key_pem)
        child = x509.load_pem_x509_certificate(result[0].encode())
        self.assertEqual(child.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        self.assertEqual(child.not_valid_after_utc, issuer.not_valid_after_utc)
        child.verify_directly_issued_by(issuer)
        with self.assertRaisesRegex(ValueError, "path length"):
            pki.create_ca_certificate("Forbidden Issuing", 1, "issuing", "intermediate", result[0], result[1])

    def test_role_and_missing_issuer_constraints_are_rejected(self):
        for arguments in (
            dict(role="issuing"), dict(role="unknown"), dict(role="root", issuer_role="root"),
            dict(role="issuing", issuer_certificate_pem=self.root_pem),
            dict(role="root", issuer_certificate_pem=self.root_pem, issuer_private_key_pem=self.root_key_pem),
            dict(role="intermediate", issuer_role="issuing", issuer_certificate_pem=self.root_pem, issuer_private_key_pem=self.root_key_pem),
        ):
            with self.subTest(arguments=arguments.keys()), self.assertRaises(ValueError):
                pki.create_ca_certificate("Forbidden CA", 10, **arguments)

    def test_crl_distribution_point_is_embedded(self):
        url = "https://pki.example/crl/1.crl"
        _, certificate = self.issue(crl_url=url)
        points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        self.assertEqual(points[0].full_name[0].value, url)
        for invalid in ("/relative.crl", "file:///tmp/a.crl", "https://user:pass@example/crl", "https://example/crl#fragment", "https://example:invalid/crl", "https://example/\nbad.crl"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.issue(crl_url=invalid)

    def test_crl_is_signed_and_contains_serial_reason_authority_and_number(self):
        revoked_at = datetime.now(UTC) - timedelta(hours=1)
        data = pki.build_crl(self.root_pem, self.root_key_pem, [{
            "serial_number": "0x123456", "revoked_at": revoked_at.isoformat(), "revocation_reason": "key_compromise",
        }], crl_number=7, validity_days=2)
        crl = x509.load_der_x509_crl(data)
        self.assertTrue(crl.is_signature_valid(self.root.public_key()))
        self.assertEqual(crl.issuer, self.root.subject)
        self.assertEqual(crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, 7)
        self.assertEqual(crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier, self.root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        revoked = crl.get_revoked_certificate_by_serial_number(0x123456)
        self.assertIsNotNone(revoked)
        self.assertEqual(revoked.revocation_date_utc, revoked_at.replace(microsecond=0))
        self.assertEqual(revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason, x509.ReasonFlags.key_compromise)
        self.assertLessEqual(crl.next_update_utc, self.root.not_valid_after_utc)

    def test_empty_crl_and_issuer_expiry_cap(self):
        issuer_pem, key_pem = self.issuer_with_constraints(days=1)
        crl = x509.load_der_x509_crl(pki.build_crl(issuer_pem, key_pem, [], 1, 7))
        self.assertEqual(len(crl), 0)
        self.assertEqual(crl.next_update_utc, x509.load_pem_x509_certificate(issuer_pem.encode()).not_valid_after_utc)

    def test_invalid_crl_reason_dates_serials_and_duplicates_are_rejected(self):
        entry = {"serial_number": "0x12", "revoked_at": datetime.now(UTC).isoformat(), "revocation_reason": "unspecified"}
        variants = [
            {"revocation_reason": "remove_from_crl"}, {"revocation_reason": "invented"},
            {"serial_number": "0x0"}, {"serial_number": "0x" + "f" * 40},
            {"revoked_at": "2020-01-01T00:00:00"},
            {"revoked_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
        ]
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                pki.build_crl(self.root_pem, self.root_key_pem, [dict(entry, **changes)], 1, 7)
        with self.assertRaisesRegex(ValueError, "unique"):
            pki.build_crl(self.root_pem, self.root_key_pem, [entry, entry], 1, 7)

    def test_crl_signing_requires_crl_sign_key_usage(self):
        issuer_pem, key_pem = self.issuer_with_constraints(crl_sign=False)
        with self.assertRaisesRegex(ValueError, "authorized"):
            pki.build_crl(issuer_pem, key_pem, [], 1, 7)


if __name__ == "__main__":
    unittest.main()
