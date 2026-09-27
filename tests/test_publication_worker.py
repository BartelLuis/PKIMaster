from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from flask import Flask, current_app, has_app_context

import publication_worker


class PublicationWorkerTests(unittest.TestCase):
    def test_dispatch_uses_packaged_state_and_closes_application_context(self):
        application = Flask(__name__)
        result = {"status": "published", "generation": 3, "crl_number": 7}

        def publish():
            self.assertIs(current_app._get_current_object(), application)
            return result

        publisher = Mock(side_effect=publish)
        with patch.object(publication_worker, "runtime_application", return_value=application) as factory:
            with patch.dict(sys.modules, {"publication": SimpleNamespace(run_publication_cycle=publisher)}):
                with patch.dict("os.environ", {"PKIMASTER_STATE_DIRECTORY": "/tmp/other-pki"}):
                    self.assertIs(publication_worker.run_once(), result)
        factory.assert_called_once_with(Path("/var/lib/pkimaster"))
        publisher.assert_called_once_with()
        self.assertFalse(has_app_context())

    def test_test_instance_override_is_passed_to_runtime_factory(self):
        application = Flask(__name__)
        instance = Path("isolated-test-state")
        publisher = Mock(return_value={"status": "disabled"})
        with patch.object(publication_worker, "runtime_application", return_value=application) as factory:
            with patch.dict(sys.modules, {"publication": SimpleNamespace(run_publication_cycle=publisher)}):
                self.assertEqual(publication_worker.run_once(instance), {"status": "disabled"})
        factory.assert_called_once_with(instance)

    def test_dispatch_errors_propagate_after_context_cleanup(self):
        application = Flask(__name__)
        publisher = Mock(side_effect=RuntimeError("private provider diagnostic"))
        with patch.object(publication_worker, "runtime_application", return_value=application):
            with patch.dict(sys.modules, {"publication": SimpleNamespace(run_publication_cycle=publisher)}):
                with self.assertRaises(RuntimeError):
                    publication_worker.run_once()
        self.assertFalse(has_app_context())

    def invoke_main(self, result=None, error=None, arguments=(), diagnostics=False):
        output, errors = io.StringIO(), io.StringIO()

        def run():
            if diagnostics:
                print("sensitive provider stdout")
                print("sensitive provider stderr", file=sys.stderr)
            if error:
                raise error
            return result

        with patch.object(publication_worker, "run_once", side_effect=run) as worker:
            with patch.object(sys, "argv", ["publication_worker.py", *arguments]):
                with redirect_stdout(output), redirect_stderr(errors):
                    code = publication_worker.main()
        self.assertEqual(errors.getvalue(), "")
        return code, json.loads(output.getvalue()), output.getvalue(), worker

    def test_cli_emits_only_allowlisted_status_and_numeric_metadata(self):
        code, summary, text, worker = self.invoke_main({
            "status": "published", "generation": 4, "crl_number": 10,
            "password": "secret", "host": "private.example", "detail": "private diagnostic",
        }, diagnostics=True)
        self.assertEqual(code, 0)
        self.assertEqual(summary, {"status": "published", "generation": 4, "crl_number": 10})
        self.assertNotIn("secret", text)
        self.assertNotIn("private", text)
        self.assertNotIn("sensitive", text)
        worker.assert_called_once_with()

    def test_cli_exception_is_sanitized_and_fails_the_service(self):
        code, summary, text, _ = self.invoke_main(error=RuntimeError("secret private credential"), diagnostics=True)
        self.assertEqual(code, 1)
        self.assertEqual(summary, {"status": "failed"})
        self.assertNotIn("secret", text)
        self.assertNotIn("Traceback", text)

    def test_cli_distinguishes_retry_failure_from_normal_no_work(self):
        for status in publication_worker.STATUSES:
            with self.subTest(status=status):
                code, summary, _, _ = self.invoke_main({"status": status})
                self.assertEqual(code, 1 if status == "failed" else 0)
                self.assertEqual(summary, {"status": status})

    def test_cli_rejects_untrusted_status_and_metadata(self):
        for result in (None, {"status": "secret text"}, {"status": ["secret"]}):
            with self.subTest(result=result):
                code, summary, _, _ = self.invoke_main(result)
                self.assertEqual((code, summary), (1, {"status": "failed"}))
        code, summary, _, _ = self.invoke_main({"status": "idle", "generation": True, "crl_number": "secret"})
        self.assertEqual((code, summary), (0, {"status": "idle"}))

    def test_cli_cannot_redirect_the_packaged_state(self):
        code, summary, _, worker = self.invoke_main(arguments=("--instance-path", "/tmp/other-pki"))
        self.assertEqual((code, summary), (2, {"status": "invalid_arguments"}))
        worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
