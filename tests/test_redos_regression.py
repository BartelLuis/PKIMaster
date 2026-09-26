import unittest

from tests.test_app import PKIMasterTestCase


class ParentCRLParsingRegressionTests(PKIMasterTestCase):
    def test_parent_crl_upload_rejects_unterminated_bundle_markers(self):
        self.activate_issuer(import_crl=False)
        payload = "-----BEGIN X509 CRL-----\n" * 2000
        response = self.post("/ca/parent-crls", {"parent_crls_pem": payload})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload only PEM-encoded parent CRLs.", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")


if __name__ == "__main__":
    unittest.main()
