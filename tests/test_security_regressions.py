"""Offline adversarial checks for report protection and run-scoped logging."""

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_analyzer import FakeClient

import AWS_GovCloud_Analyzer as analyzer
from scripts import verify_release_integrity as integrity


class SecurityRegressionTests(unittest.TestCase):
    def test_vpc_subnet_failure_is_unknown_without_deletion_guidance(self):
        responses = [
            {"error": "synthetic AccessDenied"},
            {},
            {"Subnets": [], "truncated": True},
            {"Subnets": [{"SubnetId": "subnet-synthetic"}], "truncated": True},
            {"error": "partial synthetic result", "Subnets": [{"SubnetId": "subnet-synthetic"}]},
        ]
        for response in responses:
            with (
                self.subTest(response=response),
                patch.object(
                    analyzer, "paginated_api_call", side_effect=[{"Vpcs": [{"VpcId": "vpc-synthetic"}]}, response]
                ),
            ):
                result = analyzer.research_vpc(object())
            detail = result["vpc_details"][0]
            self.assertIsNone(detail["subnet_count"])
            self.assertFalse(detail["subnet_inventory_complete"])
            self.assertFalse(result["inventory_complete"])
            self.assertEqual(result["subnet_inventory_unknown_count"], 1)
            self.assertNotIn("delete-vpc", json.dumps(detail))

    def test_vpc_interruption_and_truncated_enumeration_are_incomplete(self):
        vpcs = [{"VpcId": "vpc-one"}, {"VpcId": "vpc-two"}]
        with (
            patch.object(analyzer, "paginated_api_call", side_effect=[{"Vpcs": vpcs}, {"Subnets": []}]),
            patch.object(analyzer.shutdown_event, "is_set", side_effect=[False, True]),
        ):
            result = analyzer.research_vpc(object())
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(result["vpcs_analyzed"], 1)
        with patch.object(analyzer, "paginated_api_call", side_effect=[{"Vpcs": [], "truncated": True}]):
            result = analyzer.research_vpc(object())
        self.assertFalse(result["inventory_complete"])

    def test_vpc_verified_subnets_keep_known_inventory_semantics(self):
        for subnets in ([], [{"SubnetId": "subnet-synthetic"}]):
            with (
                self.subTest(subnets=subnets),
                patch.object(
                    analyzer,
                    "paginated_api_call",
                    side_effect=[{"Vpcs": [{"VpcId": "vpc-synthetic"}]}, {"Subnets": subnets}],
                ),
            ):
                result = analyzer.research_vpc(object())
            detail = result["vpc_details"][0]
            self.assertEqual(detail["subnet_count"], len(subnets))
            self.assertTrue(result["inventory_complete"])
            self.assertEqual(result["subnet_inventory_unknown_count"], 0)
            self.assertEqual("delete-vpc" in json.dumps(detail), not subnets)

    @unittest.skipUnless(os.name == "nt", "Windows cleanup sharing semantics")
    def test_windows_cleanup_keeps_guards_through_unlink_on_success_and_failure(self):
        original_unlink, original_link = Path.unlink, os.link
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory) / "reports"
                parent.mkdir()
                output = parent / "result.json"
                cleaned = []

                def unlink(path, *args, parent=parent, directory=directory, cleaned=cleaned, **kwargs):
                    if path.name == "report" and path.parent.name.startswith(".govhawk-private-"):
                        with self.assertRaises(PermissionError):
                            path.parent.rename(parent / "replacement")
                        with self.assertRaises(PermissionError):
                            parent.rename(Path(directory) / "replacement-parent")
                        cleaned.append(path)
                    return original_unlink(path, *args, **kwargs)

                def link(*args, fail=fail, **kwargs):
                    if fail:
                        raise OSError("synthetic publication failure")
                    return original_link(*args, **kwargs)

                with patch.object(Path, "unlink", unlink), patch.object(analyzer.os, "link", link):
                    if fail:
                        with self.assertRaisesRegex(OSError, "synthetic publication failure"):
                            with analyzer.private_report_file(output) as stream:
                                stream.write(b"synthetic")
                    else:
                        with analyzer.private_report_file(output) as stream:
                            stream.write(b"synthetic")
                self.assertEqual(len(cleaned), 1)
                self.assertEqual(list(parent.iterdir()), [] if fail else [output])

    def test_ses_metacharacters_remain_argument_data(self):
        identity = "test&whoami@example.invalid"
        client = FakeClient(
            "list_identities",
            [{"Identities": [identity]}],
            {
                "get_identity_verification_attributes": {
                    "VerificationAttributes": {identity: {"VerificationStatus": "Failed"}}
                }
            },
        )
        result = analyzer.research_ses(client)
        recommendation = result["identity_details"][0]["recommendations"][0]
        self.assertNotIn("remediation_cli", recommendation)
        self.assertEqual(recommendation["remediation_arguments"][4], identity)

    def test_request_budget_prevents_the_next_network_call(self):
        from unittest.mock import Mock

        client = Mock()
        client.meta.method_to_api_mapping = {"list_items": "ListItems"}
        client.list_items.return_value = {"Items": []}
        wrapper = analyzer.BudgetedClient(client, analyzer.InventoryBudget(requests=1))
        with patch.object(analyzer, "run_inventory_budget", analyzer.InventoryBudget()):
            wrapper.list_items()
            with self.assertRaises(analyzer.InventoryBudgetExceeded):
                wrapper.list_items()
        self.assertEqual(client.list_items.call_count, 1)

    def test_real_sdk_paginator_cannot_bypass_operation_budget(self):
        import boto3
        from botocore.stub import Stubber

        client = boto3.client(
            "ec2", region_name="us-gov-west-1", aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
        )
        with Stubber(client) as stubber, patch.object(analyzer, "run_inventory_budget", analyzer.InventoryBudget()):
            stubber.add_response("describe_volumes", {"Volumes": [], "NextToken": "next"}, {})
            wrapper = analyzer.BudgetedClient(client, analyzer.InventoryBudget(requests=1))
            paginator = wrapper.get_paginator("describe_volumes")
            with self.assertRaises(analyzer.InventoryBudgetExceeded):
                list(paginator.paginate())
            stubber.assert_no_pending_responses()

    def test_item_byte_and_elapsed_budgets_fail_closed(self):
        for budget, response in (
            (analyzer.InventoryBudget(items=2), {"Items": [1, 2, 3]}),
            (analyzer.InventoryBudget(bytes_limit=20), {"Content": "x" * 30}),
            (analyzer.InventoryBudget(seconds=0), {}),
        ):
            with self.assertRaises(analyzer.InventoryBudgetExceeded):
                budget.consume(response)
            self.assertTrue(budget.exhausted)

    def test_oversized_inventory_is_reported_incomplete(self):
        client = FakeClient("list_items", [{"Items": list(range(2001))}])
        response = analyzer.paginated_api_call("synthetic", client, "list_items", "Items")
        self.assertTrue(response["truncated"])
        self.assertIn("incomplete", response["error"])
        self.assertNotIn("Items", response)

    def test_privileged_verifier_ignores_tagged_stdlib_shadow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copyfile(Path(integrity.__file__), scripts / "verify_release_integrity.py")
            (scripts / "json.py").write_text("raise RuntimeError('tag-controlled shadow executed')", encoding="utf-8")
            assets = root / "assets"
            assets.mkdir()
            for index in range(5):
                (assets / str(index)).write_bytes(b"synthetic")
            result = subprocess.run(
                [sys.executable, "-I", str(scripts / "verify_release_integrity.py"), "assets", str(assets), "-"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(result.stdout)), 5)

    @unittest.skipIf(os.name == "nt", "POSIX directory descriptor semantics")
    def test_replaced_ancestor_cannot_redirect_publication_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            ancestor = Path(directory) / "ancestor"
            parent = ancestor / "reports"
            parent.mkdir(parents=True, mode=0o700)
            moved = Path(directory) / "moved"
            with analyzer.private_report_file(parent / "report.json") as stream:
                stream.write(b"synthetic private report")
                ancestor.rename(moved)
                parent.mkdir(parents=True, mode=0o700)
                bait = parent / "report.json"
                bait.write_bytes(b"untouched")
            self.assertEqual(bait.read_bytes(), b"untouched")
            self.assertEqual((moved / "reports" / "report.json").read_bytes(), b"synthetic private report")
            self.assertEqual(list((moved / "reports").iterdir()), [moved / "reports" / "report.json"])

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
            ancestor = Path(directory) / "ancestor"
            parent = ancestor / "reports"
            parent.mkdir(parents=True)
            output = parent / "report.json"
            with analyzer.private_report_file(output) as stream:
                staging = next(parent.glob(".govhawk-private-*"))
                with self.assertRaises(PermissionError):
                    staging.rename(parent / "replacement")
                with self.assertRaises(PermissionError):
                    parent.rename(Path(directory) / "replaced-parent")
                with self.assertRaises(PermissionError):
                    ancestor.rename(Path(directory) / "replaced-ancestor")
                stream.write(b"synthetic private report")
            self.assertEqual(output.read_bytes(), b"synthetic private report")
            self.assertEqual(list(parent.iterdir()), [output])

    @unittest.skipUnless(os.name == "nt", "Windows owner security semantics")
    def test_staging_owner_mismatch_is_rejected_before_dacl_adoption(self):
        import csv

        identity = subprocess.run(
            [str(Path(os.environ["SYSTEMROOT"]) / "System32" / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
        )
        sid = next(csv.reader([identity.stdout.strip()]))[1]
        with tempfile.TemporaryDirectory() as directory:
            staging = analyzer.windows_private_report_directory(Path(directory), sid)
            try:
                with self.assertRaisesRegex(PermissionError, "owner differs"):
                    with analyzer.windows_report_directory_lock(staging, "S-1-5-32-545"):
                        self.fail("A mismatched owner must never be adopted")
            finally:
                staging.rmdir()

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
