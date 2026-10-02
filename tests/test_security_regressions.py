"""Offline adversarial checks for report protection and run-scoped logging."""

import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_analyzer import FakeClient

import AWS_GovCloud_Analyzer as analyzer
from scripts import verify_release_integrity as integrity


class SecurityRegressionTests(unittest.TestCase):
    def test_notresource_and_notaction_are_not_reported_safe(self):
        for selector in ("Action", "NotAction"):
            client = FakeClient(
                "list_policies",
                [
                    {
                        "Policies": [
                            {
                                "PolicyName": "Excluded",
                                "Arn": "policy-test",
                                "DefaultVersionId": "v1",
                                "AttachmentCount": 1,
                            }
                        ]
                    }
                ],
                {
                    "get_policy_version": {
                        "PolicyVersion": {
                            "Document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        selector: "*",
                                        "NotResource": ["arn:aws-us-gov:s3:::excluded"],
                                        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                                    }
                                ]
                            }
                        }
                    }
                },
            )
            detail = analyzer.research_iam(client)["policy_details"][0]
            self.assertTrue(detail["is_overly_permissive"])
            self.assertTrue(any("NotResource" in item["description"] for item in detail["recommendations"]))

    def test_malformed_selector_is_unknown_not_safe(self):
        client = FakeClient(
            "list_policies",
            [
                {
                    "Policies": [
                        {
                            "PolicyName": "Malformed",
                            "Arn": "policy-test",
                            "DefaultVersionId": "v1",
                            "AttachmentCount": 1,
                        }
                    ]
                }
            ],
            {
                "get_policy_version": {
                    "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": 12, "Resource": "*"}]}}
                }
            },
        )
        detail = analyzer.research_iam(client)["policy_details"][0]
        self.assertIsNone(detail["is_overly_permissive"])
        self.assertEqual(detail["policy_analysis_status"], "unknown-elements")

    def test_logging_handler_is_closed_after_early_exit_and_exception(self):
        for fail in (False, True):
            handler = logging.Handler()
            handler._govhawk_cloudwatch = True

            def run(argv, handler=handler, fail=fail):
                analyzer.logger.addHandler(handler)
                if fail:
                    raise RuntimeError("interrupted run")
                return 0

            with patch.object(analyzer, "_main", run), patch.object(handler, "close") as close:
                if fail:
                    with self.assertRaises(RuntimeError):
                        analyzer.main([])
                else:
                    self.assertEqual(analyzer.main([]), 0)
                self.assertNotIn(handler, analyzer.logger.handlers)
                close.assert_called_once()
            analyzer.main(["--list-services"])
            self.assertNotIn(handler, analyzer.logger.handlers)

    def test_existing_report_entry_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("original", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                analyzer.write_json_report({"sensitive": "new"}, output)
            self.assertEqual(output.read_text(), "original")
            self.assertEqual(list(Path(directory).iterdir()), [output])

    @unittest.skipIf(os.name == "nt", "POSIX mode semantics")
    def test_permissive_umask_never_exposes_report_content(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0)
            try:
                path = Path(directory) / "report.json"
                with analyzer.private_report_file(path) as stream:
                    self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
                    stream.write(b"private")
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(previous)

    @unittest.skipIf(os.name == "nt", "Symlink privileges differ on Windows")
    def test_final_symlink_does_not_redirect_report_write(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("original")
            link = Path(directory) / "report.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                analyzer.write_json_report({"private": True}, link)
            self.assertEqual(target.read_text(), "original")

    def test_asset_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(5):
                (root / str(index)).write_bytes(b"verified")
            expected = integrity.manifest(root)
            (root / "0").write_bytes(b"changed after smoke")
            with self.assertRaises(ValueError):
                integrity.verify_assets(root, expected)

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing semantics")
    def test_windows_report_paths_cannot_be_replaced_during_write(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "reports"
            parent.mkdir()
            output = parent / "report.json"
            with analyzer.private_report_file(output) as stream:
                staging = next(parent.glob(".govhawk-private-*"))
                with self.assertRaises(PermissionError):
                    staging.rename(parent / "replacement")
                with self.assertRaises(PermissionError):
                    parent.rename(Path(directory) / "replaced-parent")
                stream.write(b"synthetic private report")
            self.assertEqual(output.read_bytes(), b"synthetic private report")
            self.assertEqual(list(parent.iterdir()), [output])

    def test_identical_mutation_of_both_builds_cannot_change_captured_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            roots = [Path(directory) / "first", Path(directory) / "repeat"]
            for root in roots:
                root.mkdir()
                for index in range(5):
                    (root / str(index)).write_bytes(b"source-derived")
            captured = integrity.manifest(roots[0])
            for root in roots:
                (root / "0").write_bytes(b"identical substituted bytes")
                with self.assertRaises(ValueError):
                    integrity.verify_assets(root, captured)

    def test_retargeted_annotated_release_tag_is_rejected(self):
        responses = [
            json.dumps({"object": {"type": "tag", "sha": "b" * 40}}).encode(),
            json.dumps({"object": {"type": "commit", "sha": "c" * 40}}).encode(),
        ]
        with patch.object(integrity, "command", side_effect=responses):
            with self.assertRaises(ValueError, msg="Retargeted tag must fail"):
                integrity.verify_tag("owner/repo", "v2.0.0", "a" * 40)

    def test_source_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "runtime.py").write_bytes(b"modified")
            with patch.object(integrity, "command", return_value=b"reviewed"):
                with self.assertRaises(ValueError):
                    integrity.verify_source(root, "a" * 40, ["runtime.py"])


if __name__ == "__main__":
    unittest.main()
