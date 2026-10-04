"""Cross-server CA enrollment and fail-closed activation validation."""

import base64
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

import pki


class CAExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072)):
            cls.root = pki.create_ca_certificate("Exchange Root", 30, "root")
            cls.intermediate_csr, cls.intermediate_key_pem = pki.create_ca_request("Exchange Policy", "intermediate")
            cls.intermediate = pki.sign_ca_request(cls.intermediate_csr, "intermediate", 90, "root", cls.root[0], cls.root[1])
            cls.issuing_csr, cls.issuing_key_pem = pki.create_ca_request("Exchange Issuing", "issuing")
            cls.issuing = pki.sign_ca_request(cls.issuing_csr, "issuing", 10, "intermediate", cls.intermediate[0], cls.intermediate_key_pem,
                                            issuer_chain_pem=cls.root[0])
        cls.root_certificate = x509.load_pem_x509_certificate(cls.root[0].encode())
        cls.root_key = serialization.load_pem_private_key(cls.root[1].encode(), None)
        cls.intermediate_key = serialization.load_pem_private_key(cls.intermediate_key_pem.encode(), None)
        cls.issuing_key = serialization.load_pem_private_key(cls.issuing_key_pem.encode(), None)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())
        cls.weak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @staticmethod
    def private_pem(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()

    @classmethod
    def request_pem(cls, *, key=None, name="External Issuing", subject=None,
                    path_length=0, ca=True, usage=None, basic_critical=True, extra=(), include_usage=True, algorithm=None):
        key = key or cls.ec_key
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject or pki.build_subject(name))
        builder = builder.add_extension(x509.BasicConstraints(ca, path_length if ca else None), critical=basic_critical)
        if include_usage:
            builder = builder.add_extension(usage or x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        for extension, critical in extra:
            builder = builder.add_extension(extension, critical)
        return builder.sign(key, algorithm or hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def certificate_pem(cls, *, key=None, signer=None, subject=None, issuer=None, path_length=0,
                        ca=True, usage=None, basic_critical=True, start=None, end=None, extra=()):
        now = datetime.now(UTC).replace(microsecond=0)
        key = key or cls.issuing_key
        builder = (x509.CertificateBuilder()
            .subject_name(subject or pki.build_subject("Exchange Issuing"))
            .issuer_name(issuer or cls.root_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start or now - timedelta(minutes=1))
            .not_valid_after(end or now + timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca, path_length if ca else None), critical=basic_critical)
            .add_extension(usage or x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        for extension, critical in extra:
            builder = builder.add_extension(extension, critical)
        return builder.sign(signer or cls.root_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    def activate_issuing(self, certificate=None, chain=None, key=None, common_name="Exchange Issuing"):
        return pki.validate_ca_activation(
            self.issuing[0] if certificate is None else certificate,
            self.intermediate[0] + self.root[0] if chain is None else chain,
            self.issuing_key_pem if key is None else key,
            common_name, "issuing",
        )

    def test_generated_request_has_proof_of_possession_and_ca_capabilities(self):
        request = x509.load_pem_x509_csr(self.intermediate_csr.encode())
        self.assertTrue(request.is_signature_valid)
        self.assertEqual(request.public_key().key_size, 3072)
        self.assertEqual(request.public_key().public_numbers(), self.intermediate_key.public_key().public_numbers())
        self.assertEqual(request.subject, pki.build_subject("Exchange Policy"))
        basic = request.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(basic.critical)
        self.assertTrue(basic.value.ca)
        self.assertIsNone(basic.value.path_length)
        usage = request.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.key_cert_sign and usage.value.crl_sign)
        root_csr, _ = pki.create_ca_request("Rollover Root", "root")
        root_request = x509.load_pem_x509_csr(root_csr.encode())
        self.assertTrue(root_request.is_signature_valid)
        self.assertEqual(root_request.subject, pki.build_subject("Rollover Root"))
        for role in ("unknown",):
            with self.subTest(role=role), self.assertRaises(ValueError):
                pki.create_ca_request("Invalid", role)

    def test_generated_ca_certificates_and_requests_omit_path_length(self):
        for role, pem in (("root", self.root[0]), ("intermediate", self.intermediate[0]), ("issuing", self.issuing[0])):
            with self.subTest(role=role):
                basic = x509.load_pem_x509_certificate(pem.encode()).extensions.get_extension_for_class(x509.BasicConstraints)
                self.assertTrue(basic.critical)
                self.assertTrue(basic.value.ca)
                self.assertIsNone(basic.value.path_length)
        for pem in (self.intermediate_csr, self.issuing_csr):
            basic = x509.load_pem_x509_csr(pem.encode()).extensions.get_extension_for_class(x509.BasicConstraints)
            self.assertIsNone(basic.value.path_length)

    def test_parent_signing_uses_csr_key_without_generating_child_private_key(self):
        with patch("pki.generate_private_key", side_effect=AssertionError("Parent must not generate the remote key")):
            result = pki.sign_ca_request(self.issuing_csr, "issuing", 90, "root", self.root[0], self.root[1], "https://pki.example/crl/root.crl")
        self.assertEqual(len(result), 4)
        certificate = x509.load_pem_x509_certificate(result[0].encode())
        certificate.verify_directly_issued_by(self.root_certificate)
        self.assertEqual(certificate.public_key().public_numbers(), self.issuing_key.public_key().public_numbers())
        self.assertEqual(int(result[1], 16), certificate.serial_number)
        self.assertEqual(datetime.fromisoformat(result[2]), certificate.not_valid_before_utc)
        self.assertEqual(datetime.fromisoformat(result[3]), certificate.not_valid_after_utc)
        self.assertEqual(certificate.not_valid_after_utc, self.root_certificate.not_valid_after_utc)
        self.assertNotIn("PRIVATE KEY", "".join(result))
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value,
                         "https://pki.example/crl/root.crl")

    def test_activation_returns_canonical_parents_without_child(self):
        canonical = self.activate_issuing(chain="\n " + self.intermediate[0] + "\n\t" + self.root[0] + " \n")
        self.assertEqual(canonical, self.intermediate[0] + self.root[0])
        self.assertEqual(len(x509.load_pem_x509_certificates(canonical.encode())), 2)
        self.assertEqual(pki.validate_ca_activation(self.intermediate[0], self.root[0], self.intermediate_key_pem,
                                                   "Exchange Policy", "intermediate"), self.root[0])
        direct = pki.sign_ca_request(self.issuing_csr, "issuing", 5, "root", self.root[0], self.root[1])
        self.assertEqual(self.activate_issuing(certificate=direct[0], chain=self.root[0]), self.root[0])

    def test_root_activation_requires_self_signature_and_no_parent(self):
        self.assertEqual(pki.validate_ca_activation(self.root[0], "", self.root[1], "Exchange Root", "root"), "")
        with self.assertRaises(ValueError):
            pki.validate_ca_activation(self.root[0], self.root[0], self.root[1], "Exchange Root", "root")

    def test_ecdsa_request_is_supported(self):
        result = pki.sign_ca_request(self.request_pem(), "issuing", 5, "root", self.root[0], self.root[1])
        certificate = x509.load_pem_x509_certificate(result[0].encode())
        self.assertEqual(certificate.public_key().public_numbers(), self.ec_key.public_key().public_numbers())
        self.assertEqual(pki.validate_ca_activation(result[0], self.root[0], self.private_pem(self.ec_key), "External Issuing", "issuing"), self.root[0])

    def test_invalid_request_signature_is_rejected(self):
        request = x509.load_pem_x509_csr(self.issuing_csr.encode())
        payload = bytearray(request.public_bytes(serialization.Encoding.DER))
        payload[-1] ^= 1
        damaged = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.b64encode(payload).decode() + "\n-----END CERTIFICATE REQUEST-----\n"
        with self.assertRaisesRegex(ValueError, "signature"):
            pki.sign_ca_request(damaged, "issuing", 5, "root", self.root[0], self.root[1])

    def test_weak_rsa_and_unapproved_ec_requests_are_rejected(self):
        for key in (self.weak_key, ec.generate_private_key(ec.SECP256K1())):
            with self.subTest(key=type(key).__name__), self.assertRaises(ValueError):
                pki.sign_ca_request(self.request_pem(key=key), "issuing", 5, "root", self.root[0], self.root[1])
        with patch("pki.generate_private_key", return_value=self.weak_key), self.assertRaisesRegex(ValueError, "3072"):
            pki.create_ca_request("Weak Local CA", "issuing")

    def test_ca_request_rejects_hashes_below_the_sha256_baseline(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            pki.sign_ca_request(self.request_pem(algorithm=hashes.SHA224()), "issuing", 5, "root", self.root[0], self.root[1])

    def test_strict_leaf_policy_rejects_weak_rsa_and_hashes_without_changing_legacy_default(self):
        weak_csr = (x509.CertificateSigningRequestBuilder().subject_name(pki.build_subject("leaf.example"))
                    .sign(self.weak_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        arguments = ("leaf.example", self.issuing[0], self.issuing_key_pem, 5, ["leaf.example"])
        legacy = pki.issue_end_entity_certificate(*arguments, csr_pem=weak_csr)
        self.assertEqual(x509.load_pem_x509_certificate(legacy[0].encode()).public_key().key_size, 2048)
        with self.assertRaisesRegex(ValueError, "3072"):
            pki.issue_end_entity_certificate(*arguments, csr_pem=weak_csr, minimum_rsa_bits=3072)
        weak_hash_csr = (x509.CertificateSigningRequestBuilder().subject_name(pki.build_subject("leaf.example"))
                        .sign(self.ec_key, hashes.SHA224()).public_bytes(serialization.Encoding.PEM).decode())
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            pki.issue_end_entity_certificate(*arguments, csr_pem=weak_hash_csr, minimum_rsa_bits=3072)

    def test_request_cannot_omit_ca_capabilities(self):
        options = (
            {"ca": False}, {"basic_critical": False},
            {"include_usage": False},
            {"usage": x509.KeyUsage(True, False, False, False, False, True, True, False, False)},
        )
        for kwargs in options:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                pki.sign_ca_request(self.request_pem(**kwargs), "issuing", 5, "root", self.root[0], self.root[1])

    def test_external_requests_with_or_without_path_length_are_signed_without_one(self):
        for path_length in (None, 0, 1, 10):
            with self.subTest(path_length=path_length):
                signed = pki.sign_ca_request(self.request_pem(path_length=path_length), "issuing", 5,
                                             "root", self.root[0], self.root[1])
                certificate = x509.load_pem_x509_certificate(signed[0].encode())
                certificate.verify_directly_issued_by(self.root_certificate)
                self.assertIsNone(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length)

    def test_activation_accepts_external_ca_without_role_based_path_length(self):
        for path_length in (None, 0, 1, 10):
            with self.subTest(path_length=path_length):
                certificate = self.certificate_pem(path_length=path_length)
                self.assertEqual(self.activate_issuing(certificate=certificate, chain=self.root[0]), self.root[0])

    def test_activation_accepts_child_constraint_above_parent_when_chain_fits(self):
        root = self.certificate_pem(key=self.root_key, subject=self.root_certificate.subject,
                                   issuer=self.root_certificate.subject, path_length=1,
                                   start=self.root_certificate.not_valid_before_utc,
                                   end=self.root_certificate.not_valid_after_utc)
        for path_length in (None, 1, 10):
            with self.subTest(path_length=path_length):
                certificate = self.certificate_pem(path_length=path_length)
                self.assertEqual(self.activate_issuing(certificate=certificate, chain=root), root)

    def test_csr_subject_must_match_supported_cn_only_identity(self):
        subjects = (
            x509.Name([]),
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "one"), x509.NameAttribute(NameOID.COMMON_NAME, "two")]),
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External Issuing"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unexpected")]),
        )
        for subject in subjects:
            # Build directly because the generic fixture uses an optional subject.
            request = (x509.CertificateSigningRequestBuilder().subject_name(subject)
                .add_extension(x509.BasicConstraints(True, 0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .sign(self.ec_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
            with self.subTest(subject=subject), self.assertRaises(ValueError):
                pki.sign_ca_request(request, "issuing", 5, "root", self.root[0], self.root[1])

    def test_unsupported_constraints_and_critical_extensions_fail_closed(self):
        extensions = [
            (x509.NameConstraints([x509.DNSName(".example")], None), True),
            (x509.NameConstraints([x509.DNSName(".example")], None), False),
            (x509.PolicyConstraints(0, None), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
            (x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5"), b"unknown"), True),
        ]
        for extension in extensions:
            with self.subTest(extension=type(extension[0]).__name__):
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    pki.sign_ca_request(self.request_pem(extra=[extension]), "issuing", 5, "root", self.root[0], self.root[1])
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    self.activate_issuing(certificate=self.certificate_pem(extra=[extension]), chain=self.root[0])

    def test_noncritical_csr_extensions_are_not_copied(self):
        oid = ObjectIdentifier("1.2.3.4.5")
        request = self.request_pem(extra=[(x509.UnrecognizedExtension(oid, b"not a policy grant"), False)])
        result = pki.sign_ca_request(request, "issuing", 5, "root", self.root[0], self.root[1])
        with self.assertRaises(x509.ExtensionNotFound):
            x509.load_pem_x509_certificate(result[0].encode()).extensions.get_extension_for_oid(oid)

    def test_wrong_role_pairs_and_constrained_issuers_are_rejected(self):
        for role, issuer_role in (("root", "root"), ("intermediate", "intermediate"), ("issuing", "issuing")):
            with self.subTest(role=role, issuer_role=issuer_role), self.assertRaises(ValueError):
                pki.sign_ca_request(self.issuing_csr, role, 5, issuer_role, self.root[0], self.root[1])
        constrained = self.certificate_pem(key=self.intermediate_key, subject=pki.build_subject("Constrained Policy"), path_length=0)
        with self.assertRaisesRegex(ValueError, "path length"):
            pki.sign_ca_request(self.issuing_csr, "issuing", 5, "intermediate", constrained, self.intermediate_key_pem,
                                issuer_chain_pem=self.root[0])
        # The root's limit remains effective even though the child has no path-length constraint.
        root = self.certificate_pem(key=self.root_key, subject=self.root_certificate.subject,
                                    issuer=self.root_certificate.subject, path_length=1)
        signed = pki.sign_ca_request(self.intermediate_csr, "intermediate", 9, "root", root, self.root[1])
        self.assertIsNone(x509.load_pem_x509_certificate(signed[0].encode()).extensions.get_extension_for_class(x509.BasicConstraints).value.path_length)
        self.assertEqual(pki.validate_ca_activation(signed[0], root, self.intermediate_key_pem,
                                                   "Exchange Policy", "intermediate"), root)
        with self.assertRaisesRegex(ValueError, "path length"):
            pki.sign_ca_request(self.issuing_csr, "issuing", 5, "intermediate", signed[0], self.intermediate_key_pem,
                                issuer_chain_pem=root)

    def test_intermediate_signing_requires_its_complete_validated_parent_chain(self):
        for chain in ("", self.intermediate[0], self.root[0] + self.root[0], "not PEM"):
            with self.subTest(chain=chain[:30]), self.assertRaises(ValueError):
                pki.sign_ca_request(self.issuing_csr, "issuing", 5, "intermediate", self.intermediate[0],
                                    self.intermediate_key_pem, issuer_chain_pem=chain)

    def test_issuer_key_mismatch_and_reused_child_identity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "do not match"):
            pki.sign_ca_request(self.issuing_csr, "issuing", 5, "root", self.root[0], self.issuing_key_pem)
        for request in (self.request_pem(key=self.root_key), self.request_pem(name="Exchange Root")):
            with self.subTest(request=request[:30]), self.assertRaisesRegex(ValueError, "distinct"):
                pki.sign_ca_request(request, "issuing", 5, "root", self.root[0], self.root[1])

    def test_activation_rejects_wrong_key_subject_and_self_signed_subordinate(self):
        for arguments in ({"key": self.intermediate_key_pem}, {"common_name": "Wrong Issuing"}):
            with self.subTest(arguments=arguments.keys()), self.assertRaises(ValueError):
                self.activate_issuing(**arguments)
        malformed = self.certificate_pem(subject=x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Exchange Issuing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unexpected"),
        ]))
        with self.assertRaisesRegex(ValueError, "subject"):
            self.activate_issuing(certificate=malformed, chain=self.root[0])
        with self.assertRaises(ValueError):
            self.activate_issuing(certificate=self.root[0], key=self.root[1],
                                  common_name="Exchange Root", chain="")

    def test_activation_rejects_missing_unordered_duplicate_or_unrelated_parents(self):
        for chain in ("", self.intermediate[0], self.root[0], self.root[0] + self.intermediate[0],
                      self.intermediate[0] + self.intermediate[0], self.issuing[0] + self.intermediate[0] + self.root[0]):
            with self.subTest(chain_length=len(chain)), self.assertRaises(ValueError):
                self.activate_issuing(chain=chain)

    def test_activation_rejects_same_subject_root_signed_by_another_key(self):
        bad_root = self.certificate_pem(key=self.root_key, signer=self.ec_key,
            subject=self.root_certificate.subject, issuer=self.root_certificate.subject, path_length=2,
            start=self.root_certificate.not_valid_before_utc, end=self.root_certificate.not_valid_after_utc)
        with self.assertRaises(ValueError):
            self.activate_issuing(chain=self.intermediate[0] + bad_root)

    def test_activation_rejects_weak_parent_even_when_links_verify(self):
        weak_root = self.certificate_pem(key=self.weak_key, signer=self.weak_key,
            subject=pki.build_subject("Weak Root"), issuer=pki.build_subject("Weak Root"), path_length=2)
        child = self.certificate_pem(signer=self.weak_key, issuer=pki.build_subject("Weak Root"))
        with self.assertRaisesRegex(ValueError, "3072"):
            self.activate_issuing(certificate=child, chain=weak_root)

    def test_activation_rejects_expired_future_and_overlong_ca_validity(self):
        now = datetime.now(UTC).replace(microsecond=0)
        variants = [
            {"start": now - timedelta(days=2), "end": now - timedelta(days=1)},
            {"start": now + timedelta(days=1), "end": now + timedelta(days=2)},
            {"end": self.root_certificate.not_valid_after_utc + timedelta(days=1)},
            {"start": self.root_certificate.not_valid_before_utc - timedelta(seconds=1)},
        ]
        for options in variants:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.activate_issuing(certificate=self.certificate_pem(**options), chain=self.root[0])

    def test_activation_rejects_non_ca_or_multipurpose_key_usage(self):
        for options in ({"ca": False}, {"basic_critical": False},
                        {"usage": x509.KeyUsage(True, False, True, False, False, True, True, False, False)}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.activate_issuing(certificate=self.certificate_pem(**options), chain=self.root[0])

    def test_activation_enforces_every_ancestor_path_length(self):
        short_root = self.certificate_pem(key=self.root_key, subject=self.root_certificate.subject,
            issuer=self.root_certificate.subject, path_length=1,
            start=self.root_certificate.not_valid_before_utc, end=self.root_certificate.not_valid_after_utc)
        with self.assertRaisesRegex(ValueError, "path length"):
            self.activate_issuing(chain=self.intermediate[0] + short_root)

    def test_activation_checks_authority_key_identifier(self):
        bad_aki = x509.AuthorityKeyIdentifier(b"wrong-issuer-id", None, None)
        certificate = self.certificate_pem(extra=[(bad_aki, False)])
        with self.assertRaisesRegex(ValueError, "identifier"):
            self.activate_issuing(certificate=certificate, chain=self.root[0])

    def test_malformed_and_mixed_pem_inputs_are_rejected(self):
        for csr in ("garbage", self.issuing_csr + self.root[1], self.issuing_csr * 2):
            with self.subTest(csr_length=len(csr)), self.assertRaises(ValueError):
                pki.sign_ca_request(csr, "issuing", 5, "root", self.root[0], self.root[1])
        for certificate, chain in (
            (self.issuing[0] + self.intermediate[0], self.root[0]),
            (self.issuing[0], self.intermediate[0] + self.root[0] + "garbage"),
            (self.issuing[0], self.intermediate[0] + self.root[1]),
        ):
            with self.subTest(lengths=(len(certificate), len(chain))), self.assertRaises(ValueError):
                self.activate_issuing(certificate=certificate, chain=chain)


if __name__ == "__main__":
    unittest.main()
