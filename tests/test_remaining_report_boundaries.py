"""Offline structured-error and immutable smoke-consumer regressions."""

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import AWS_GovCloud_Analyzer as app


class ErrorPrivacyTests(unittest.TestCase):
    def test_local_and_cloudwatch_logs_omit_aws_message_metadata(self):
        synthetic_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        marker = f"role/private-team arn:aws-us-gov:iam::123456789012:user/person@example.test {synthetic_key} secret.internal.example"
        error = ClientError({"Error": {"Code": "AccessDenied", "Message": marker}}, "ListThings")
        fake = MagicMock()
        fake.put_log_events.return_value = {}
        old_handlers = list(app.logger.handlers)
        old_shutdown = app.shutdown_event.is_set()
        app.shutdown_event.clear()
        try:
            with patch.object(app, "create_aws_client", return_value=fake):
                app.setup_cloudwatch_logging("approved-synthetic-group", "synthetic", "us-gov-west-1")
            with patch.object(app.logger, "level", logging.INFO):
                with self.assertLogs(app.logger, level="ERROR") as local:
                    # assertLogs substitutes handlers, so capture its record for the
                    # actual registered CloudWatch handler after local capture.
                    result = app.safe_api_call("EC2", MagicMock(side_effect=error))
                self.assertEqual(result["error"], "AccessDenied")
                self.assertIn("Error calling EC2: AccessDenied", local.output[0])
                self.assertNotIn(marker, local.output[0])
                for handler in app.logger.handlers:
                    if getattr(handler, "_govhawk_cloudwatch", False):
                        handler.handle(local.records[0])
            message = fake.put_log_events.call_args.kwargs["logEvents"][0]["message"]
            self.assertIn("AccessDenied", message)
            for private in ("private-team", "123456789012", "person@example.test", "AKIA", "secret.internal"):
                self.assertNotIn(private, message)
        finally:
            for handler in tuple(app.logger.handlers):
                if handler not in old_handlers:
                    app.logger.removeHandler(handler)
                    handler.close()
            if old_shutdown:
                app.shutdown_event.set()

    def test_unbounded_or_control_character_error_codes_are_normalized(self):
        for code in ("x" * 10000, "AccessDenied\nidentity", "person@example.test"):
            error = ClientError({"Error": {"Code": code, "Message": "sensitive"}}, "Synthetic")
            self.assertEqual(app.sanitize_error_message(error), "Unknown")


class SmokeHandoffTests(unittest.TestCase):
    def test_report_parent_alias_is_refused_before_any_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, alias = root / "protected", root / "mutable-alias"
            target.mkdir()
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink unavailable: {exc}")
            with self.assertRaises((PermissionError, OSError)), app.private_report_file(alias / "result.json"):
                self.fail("A mutable alias must never enter the write context")
            self.assertEqual(list(target.iterdir()), [])

    def test_mutable_privileged_consumer_cannot_supply_release_handoff(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        build, rest = workflow.split("\n  smoke:\n", 1)
        smoke, attest = rest.split("\n  attest:\n", 1)
        self.assertNotIn("sudo ", build)
        self.assertIn("actions/upload-artifact@", build)
        self.assertIn("sudo apt-get install --yes bubblewrap", smoke)
        self.assertIn("artifact-ids: ${{ needs.build.outputs.artifact-id }}", smoke)
        self.assertNotIn("actions/upload-artifact@", smoke)
        self.assertNotIn("GITHUB_OUTPUT", smoke)
        self.assertNotIn("outputs:", smoke)
        self.assertIn("needs: [build, smoke]", attest)
        self.assertNotIn("needs.smoke.outputs", attest)


@unittest.skipUnless(os.name == "nt", "Actual Windows pinned-handle ACL inspection")
class WindowsParentSecurity(unittest.TestCase):
    def test_actual_private_dacl_passes_and_second_sid_mutation_fails(self):
        import ctypes.wintypes

        wintypes = ctypes.wintypes
        sid = app.current_windows_sid()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        security = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        security.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        security.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        security.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        security.SetNamedSecurityInfoW.restype = wintypes.DWORD
        with tempfile.TemporaryDirectory() as directory:
            parent = app.windows_private_report_directory(Path(directory), sid)
            try:
                with app.windows_report_directory_lock(parent, parent_sid=sid, require_user_owner=True):
                    pass
                descriptor = ctypes.c_void_p()
                sddl = f"D:P(A;OICI;FA;;;{sid})(A;;0x42;;;S-1-5-21-111111111-222222222-333333333-1234)"
                self.assertTrue(
                    security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl, 1, ctypes.byref(descriptor), None
                    )
                )
                try:
                    present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
                    self.assertTrue(
                        security.GetSecurityDescriptorDacl(
                            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
                        )
                    )
                    self.assertEqual(
                        security.SetNamedSecurityInfoW(str(parent), 1, 0x80000004, None, None, dacl, None), 0
                    )
                finally:
                    kernel.LocalFree(descriptor)
                with (
                    self.assertRaisesRegex(PermissionError, "another user"),
                    app.windows_report_directory_lock(parent, parent_sid=sid, require_user_owner=True),
                ):
                    pass
            finally:
                parent.rmdir()


if __name__ == "__main__":
    unittest.main()
