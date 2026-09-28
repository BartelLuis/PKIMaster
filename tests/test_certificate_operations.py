"""Shared policy enforcement, searchable ownership and deployed certificate checks."""
from datetime import UTC, datetime, timedelta
import json
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import get_db
from certificate_profiles import validate_issuance
from monitoring_transports import MonitoringError
from test_distributed_ca import Node
import pki
import tls_monitoring


class CertificateOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pki.create_ca_certificate("Operations Root", 365, "root")
        cls.crl = x509.load_der_x509_crl(pki.build_crl(cls.root[0], cls.root[1], [], 1, 7)).public_bytes(serialization.Encoding.PEM).decode()
        cls.key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def csr(cls, name="service.corp.example"):
        return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .sign(cls.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.node = Node(self, "issuing")
        authority = self.node.records("authorities")[0]
        signed, *_ = pki.sign_ca_request(authority["csr_pem"], "issuing", 180, "root", self.root[0], self.root[1])
        self.node.post("/ca/activate", {"certificate_pem": signed, "chain_pem": self.root[0],
                                       "trusted_root_sha256": x509.load_pem_x509_certificate(self.root[0].encode()).fingerprint(hashes.SHA256()).hex()})
        self.node.post("/ca/parent-crls", {"parent_crls_pem": self.crl})

    def template(self, **changes):
        values = {"name": "Internal services", "profile": "server", "default_validity_days": "15", "max_validity_days": "30",
                  "dns_suffixes": "corp.example", "ip_networks": "10.0.0.0/8", "allow_ip": "on", "roles": ["admin", "operator", "acme"], "enabled": "on"}
        response = self.node.post("/settings/certificate-templates", values | changes)
        self.assertEqual(response.status_code, 200, response.data)
        return self.node.records("certificate_templates")[-1]

    def issue(self, **changes):
        return self.node.post("/certificates", {"common_name": "service.corp.example", "authority_id": "1", "profile": "server",
                              "validity_days": "15", "csr_pem": self.csr(), **changes})

    def test_shared_policy_blocks_csr_names_domains_ips_wildcards_and_roles(self):
        template = self.template()
        with self.node.app.app_context():
            db = get_db()
            base = {"common_name": "service.corp.example", "subject_alt_names": "", "validity_days": 15, "role": "acme", "csr_pem": self.csr()}
            accepted = validate_issuance(db, template["id"], **base)
            self.assertEqual(accepted["subject_alt_names"], "service.corp.example")
            for changes in ({"csr_pem": self.csr("corp.example.evil")}, {"subject_alt_names": "evilcorp.example"},
                            {"subject_alt_names": "*.corp.example"}, {"subject_alt_names": "192.168.0.1"},
                            {"common_name": "outside.example"}, {"validity_days": 31}, {"role": "auditor"}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    validate_issuance(db, template["id"], **(base | changes))
            self.assertIn("10.1.2.3", validate_issuance(db, template["id"], **(base | {"subject_alt_names": "10.1.2.3"}))["subject_alt_names"])

    def test_policy_rechecked_on_renewal_and_snapshot_preserved(self):
        template = self.template()
        self.assertIn(b"Issued certificate", self.issue(template_id=str(template["id"])).data)
        original = self.node.records("certificates")[0]
        self.assertEqual(json.loads(original["template_snapshot"])["revision"], 1)
        self.template(template_id=str(template["id"]), max_validity_days="10", default_validity_days="10")
        values = {"authority_id": "1", "template_id": str(template["id"]), "common_name": "service.corp.example",
                  "subject_alt_names": "", "validity_days": "15", "key_source": "csr", "csr_pem": self.csr()}
        self.assertEqual(self.node.post("/certificates/1/renew", values).status_code, 400)
        self.assertEqual(len(self.node.records("certificates")), 1)
        self.assertEqual(self.node.records("certificates")[0]["template_snapshot"], original["template_snapshot"])
        self.assertEqual(self.node.post("/certificates/1/renew", values | {"validity_days": "10"}).status_code, 200)
        self.assertEqual(json.loads(self.node.records("certificates")[-1]["template_snapshot"])["revision"], 2)

    def test_disabled_builtin_cannot_be_bypassed_by_legacy_profile_field(self):
        with self.node.app.app_context():
            db = get_db()
            db.execute("UPDATE certificate_templates SET enabled=0 WHERE builtin='server'")
            db.commit()
        self.assertIn(b"disabled", self.issue().data)
        self.assertEqual(self.node.records("certificates"), [])
        self.assertEqual(self.node.get("/settings/certificate-templates").status_code, 200)

    def test_inventory_search_filters_export_and_renewal_metadata(self):
        self.issue()
        self.node.post("/certificates/1/metadata", {"owner": "Platform", "service_name": "=WEBSERVICE(A1)",
            "deployment_host": "web-01", "environment": "Production", "tags": "Web, internal, WEB", "notes": "Ticket INC-100", "tls_port": "443"})
        self.assertEqual(self.node.records("certificates")[0]["tags"], "web,internal")
        for query in ("q=corp.example", "q=INC-100", "owner=Platform&tag=web&environment=Production", "q=" + self.node.records("certificates")[0]["serial_number"]):
            self.assertIn(b"service.corp.example", self.node.get("/certificates/export.csv?" + query).data)
        self.assertNotIn(b"service.corp.example", self.node.get("/certificates/export.csv?tag=we").data)
        self.assertNotIn(b"service.corp.example", self.node.get("/certificates/export.csv?q=%25").data)
        csv = self.node.get("/certificates/export.csv").data.decode("utf-8-sig")
        self.assertIn("'=WEBSERVICE(A1)", csv)
        self.assertNotIn("PRIVATE KEY", csv)
        self.node.post("/certificates/1/renew", {"authority_id": "1", "common_name": "service.corp.example", "profile": "server",
            "validity_days": "15", "key_source": "csr", "csr_pem": self.csr()})
        self.assertEqual(self.node.records("certificates")[-1]["owner"], "Platform")

    def test_operator_cannot_manage_templates_or_set_network_targets(self):
        self.issue()
        with self.node.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET role='operator'")
            db.commit()
        self.assertEqual(self.node.get("/settings/certificate-templates").status_code, 403)
        self.assertEqual(self.node.post("/certificates/1/metadata", {"owner": "Operator"}).status_code, 200)
        self.assertEqual(self.node.post("/certificates/1/metadata", {"tls_host": "internal.example", "tls_enabled": "on"}).status_code, 403)
        self.assertEqual(self.node.client.post("/certificates/1/metadata", base_url=self.node.base, data={"owner": "No CSRF"}).status_code, 403)

    def test_tls_results_detect_old_certificate_and_follow_renewal(self):
        self.issue()
        self.node.post("/certificates/1/metadata", {"tls_host": "service.corp.example", "tls_port": "443", "tls_enabled": "on"})
        original = self.node.records("certificates")[0]
        expected = x509.load_pem_x509_certificate(original["certificate_pem"].encode()).fingerprint(hashes.SHA256()).hex()
        observed = {"sha256": expected, "not_after": (datetime.now(UTC) + timedelta(days=60)).isoformat(), "subject": "CN=service.corp.example"}
        with self.node.app.app_context(), patch("tls_monitoring.inspect_endpoint", return_value=observed):
            findings, _ = tls_monitoring.collect_endpoint_findings(get_db(), datetime.now(UTC), [30, 7])
            self.assertEqual(findings, [])
        self.node.post("/certificates/1/renew", {"authority_id": "1", "common_name": "service.corp.example", "profile": "server",
            "validity_days": "15", "key_source": "csr", "csr_pem": self.csr()})
        old, new = self.node.records("certificates")
        self.assertFalse(old["tls_enabled"])
        self.assertTrue(new["tls_enabled"])
        with self.node.app.app_context(), patch("tls_monitoring.inspect_endpoint", return_value=observed):
            findings, _ = tls_monitoring.collect_endpoint_findings(get_db(), datetime.now(UTC), [30, 7])
            self.assertEqual(findings[0]["key"], "deployment:2")
            self.assertIn("mismatch", findings[0]["signature"])
        with self.node.app.app_context(), patch("tls_monitoring.inspect_endpoint", side_effect=MonitoringError("Unavailable")):
            findings, _ = tls_monitoring.collect_endpoint_findings(get_db(), datetime.now(UTC), [30, 7])
            self.assertEqual(findings[0]["severity"], "error")
        self.assertIn(b"Unavailable", self.node.get("/certificates/2").data)

    def test_metadata_rejects_local_and_metadata_network_targets(self):
        self.issue()
        for host in ("127.0.0.1", "169.254.169.254", "::1", "fe80::1", "https://service.corp.example"):
            self.node.post("/certificates/1/metadata", {"tls_host": host, "tls_port": "443", "tls_enabled": "on"})
            self.assertFalse(self.node.records("certificates")[0]["tls_enabled"])


if __name__ == "__main__":
    unittest.main()
