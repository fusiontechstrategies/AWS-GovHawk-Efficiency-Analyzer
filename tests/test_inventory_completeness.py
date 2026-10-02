"""Offline coverage checks for discarded nested failures and selected work."""

import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from test_analyzer import FakeClient

import AWS_GovCloud_Analyzer as analyzer


class InventoryCompletenessTests(unittest.TestCase):
    def setUp(self):
        analyzer.shutdown_event.clear()
        analyzer.inventory_budgets.clear()
        analyzer.run_inventory_budget = analyzer.InventoryBudget()

    def tearDown(self):
        analyzer.shutdown_event.clear()

    def assert_incomplete(self, service, result):
        self.assertFalse(result["inventory_complete"])
        self.assertTrue(result["incomplete_reasons"])
        coverage = analyzer.inventory_collection_summary([service], {service: result})
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["incomplete_services"], [service])

    def test_ecs_nested_failures_retain_enumerated_cluster_count(self):
        for operation in ("describe_clusters", "list_services"):
            client = FakeClient(
                "list_clusters",
                [{"clusterArns": ["arn:synthetic/cluster"]}],
                {
                    "describe_clusters": {"clusters": [{"status": "ACTIVE"}]},
                    "list_services": {"serviceArns": []},
                },
            )
            client.direct_responses[operation] = {"error": "synthetic access denial"}
            result = analyzer.research_ecs(client)
            self.assertEqual(result["cluster_count"], 1)
            self.assertEqual(result["clusters_analyzed"], 0)
            self.assert_incomplete("ECS", result)

    def test_ecs_unreturned_requested_cluster_is_not_empty_cluster(self):
        client = FakeClient(
            "list_clusters",
            [{"clusterArns": ["arn:synthetic/cluster"]}],
            {
                "describe_clusters": {"clusters": []},
                "list_services": {"serviceArns": []},
            },
        )
        result = analyzer.research_ecs(client)
        self.assert_incomplete("ECS", result)
        self.assertEqual(result["cluster_details"], [])

    def test_budget_wrapper_preserves_operation_validation(self):
        class RawS3:
            meta = SimpleNamespace(method_to_api_mapping={"list_buckets": "ListBuckets"})

            def list_buckets(self, **kwargs):
                return {"Owner": {"ID": "synthetic"}}

        wrapped = analyzer.BudgetedClient(RawS3(), analyzer.InventoryBudget())
        self.assertEqual(wrapped.list_buckets.__name__, "list_buckets")
        self.assert_incomplete("S3", analyzer.research_s3(wrapped, object(), skip_metrics=True))

    def test_nested_sdk_response_shape_is_checked_offline(self):
        from botocore.session import Session

        class RawS3:
            meta = SimpleNamespace(
                method_to_api_mapping={"list_buckets": "ListBuckets"},
                service_model=Session().get_service_model("s3"),
            )

            def list_buckets(self, **kwargs):
                return {"Buckets": [{"Name": 123}]}

        wrapped = analyzer.BudgetedClient(RawS3(), analyzer.InventoryBudget())
        self.assert_incomplete("S3", analyzer.research_s3(wrapped, object(), skip_metrics=True))

    def test_ec2_reservation_missing_instances_is_not_empty_inventory(self):
        result = analyzer.research_ec2(
            FakeClient("describe_instances", [{"Reservations": [{}]}]), object(), skip_metrics=True
        )
        self.assert_incomplete("EC2", result)

    def test_ecs_missing_resource_counts_never_means_empty(self):
        client = FakeClient(
            "list_clusters",
            [{"clusterArns": ["arn:synthetic/cluster"]}],
            {
                "describe_clusters": {"clusters": [{"status": "ACTIVE"}]},
                "list_services": {"serviceArns": []},
            },
        )
        result = analyzer.research_ecs(client)
        self.assert_incomplete("ECS", result)
        self.assertEqual(result["cluster_details"], [])
        client.direct_responses["describe_clusters"]["clusters"][0].update(
            {
                "registeredContainerInstancesCount": 0,
                "runningTasksCount": 0,
            }
        )
        self.assertTrue(analyzer.research_ecs(client)["inventory_complete"])

    def test_missing_public_policy_boolean_is_unknown(self):
        client = FakeClient(
            "list_buckets",
            [{"Buckets": [{"Name": "synthetic"}]}],
            {
                "get_bucket_location": {"LocationConstraint": "us-gov-west-1"},
                "get_bucket_lifecycle_configuration": {"Rules": []},
                "get_bucket_policy_status": {"PolicyStatus": {}},
                "get_bucket_acl": {"Grants": []},
                "get_public_access_block": {"PublicAccessBlockConfiguration": {}},
                "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": []}},
            },
        )
        analyzer.research["region"] = "us-gov-west-1"
        result = analyzer.research_s3(client, object(), skip_metrics=True)
        self.assert_incomplete("S3", result)
        self.assertIsNone(result["bucket_details"][0]["is_public"])

    def test_missing_alarm_state_is_unknown(self):
        result = analyzer.research_cloudwatch(
            FakeClient("describe_alarms", [{"MetricAlarms": [{"AlarmName": "synthetic"}], "CompositeAlarms": []}])
        )
        self.assert_incomplete("CloudWatch", result)
        self.assertEqual(result["alarm_details"][0]["state"], "UNKNOWN")

    def test_inspector_missing_requested_account_is_incomplete(self):
        result = analyzer.research_inspector(
            FakeClient("batch_get_account_status", [{"accounts": [], "failedAccounts": []}])
        )
        self.assert_incomplete("Inspector", result)

    def test_failed_elb_family_retains_successful_family_and_names_failure(self):
        for failed_classic in (False, True):
            classic = FakeClient("describe_load_balancers", [{"LoadBalancerDescriptions": []}])
            v2 = FakeClient("describe_load_balancers", [{"LoadBalancers": []}])
            failed = classic if failed_classic else v2
            failed.pages = [{}]
            result = analyzer.research_elb(classic, v2)
            self.assert_incomplete("ELB", result)
            self.assertIn("ELB:" if failed_classic else "ELBv2:", " ".join(result["incomplete_reasons"]))
            self.assertEqual(result["load_balancer_count"], 0)

    def test_security_hub_access_denied_and_malformed_are_unknown(self):
        for response in ({"error": "AccessDenied"}, {}, {"HubArn": None}, {"ResponseMetadata": {}}):
            client = FakeClient("describe_hub", [response])
            result = analyzer.research_security_hub(client)
            self.assert_incomplete("Security Hub", result)
            self.assertEqual(result["hub_status"], "Unknown")

    def test_trusted_advisor_failed_check_cannot_claim_complete(self):
        client = FakeClient(
            "describe_trusted_advisor_checks",
            [{"checks": [{"id": "synthetic", "name": "test"}]}],
            {
                "describe_trusted_advisor_check_result": {"error": "AccessDenied"},
            },
        )
        result = analyzer.research_trusted_advisor(client)
        self.assertEqual(result["check_count"], 1)
        self.assert_incomplete("Trusted Advisor", result)

    def test_expected_absence_is_not_a_collection_failure(self):
        error = ClientError({"Error": {"Code": "ExpectedAbsent", "Message": "synthetic"}}, "test")

        @analyzer.inventory_collection
        def collector():
            result = analyzer.safe_api_call("test", Mock(side_effect=error), suppress_errors=["ExpectedAbsent"])
            return {"observed": result}

        self.assertTrue(collector()["inventory_complete"])

    def test_failed_metric_and_parallel_collector_contexts_do_not_leak(self):
        @analyzer.inventory_collection
        def failed():
            analyzer.safe_api_call("test", Mock(side_effect=ValueError()))
            return {}

        @analyzer.inventory_collection
        def complete():
            return {"observed": []}

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            bad, good = list(pool.map(lambda f: f(), [failed, complete]))
        self.assertFalse(bad["inventory_complete"])
        self.assertTrue(good["inventory_complete"])

    def test_missing_selected_worker_is_incomplete(self):
        coverage = analyzer.inventory_collection_summary(["ECS", "S3"], {"ECS": {"inventory_complete": True}})
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["missing_services"], ["S3"])

    def run_offline_main(self, interrupt=False):
        @analyzer.inventory_collection
        def collector(client, skip_metrics=False):
            del client, skip_metrics
            if interrupt:
                analyzer.shutdown_event.set()
            else:
                analyzer.safe_api_call("ECS", Mock(side_effect=ValueError()))
            return {"cluster_count": 1, "clusters_analyzed": 0}

        sts = SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012"})
        with (
            patch.dict(analyzer.service_map, {"ECS": (collector, ["ecs"])}, clear=True),
            patch.object(analyzer.boto3, "setup_default_session"),
            patch.object(analyzer, "create_aws_client", return_value=sts),
            patch.object(analyzer, "generate_pdf_report", return_value=Path("synthetic.pdf")) as pdf,
            patch.object(analyzer, "write_json_report", return_value=Path("synthetic.json")) as report,
        ):
            code = analyzer.main(["--services", "ECS", "--output-format", "both"])
        self.assertFalse(pdf.call_args.args[0]["inventory_collection"]["complete"])
        self.assertFalse(report.call_args.args[0]["inventory_collection"]["complete"])
        return code

    def test_noninterrupted_nested_failure_returns_exit_three(self):
        self.assertEqual(self.run_offline_main(), 3)

    def test_interrupted_non_vpc_work_returns_130_and_incomplete_reports(self):
        self.assertEqual(self.run_offline_main(interrupt=True), 130)

    def test_crash_left_staging_is_ignored_at_custom_depth(self):
        root = Path(analyzer.__file__).resolve().parent
        result = subprocess.run(
            ["git", "check-ignore", "custom/nested/.govhawk-private-synthetic/report", ".govhawk-private-test/report"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
