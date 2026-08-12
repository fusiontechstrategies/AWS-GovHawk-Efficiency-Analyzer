import datetime
import logging
import tempfile
import unittest
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import AWS_GovCloud_Analyzer as analyzer


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        del kwargs
        yield from self.pages


class FakeClient:
    def __init__(self, operation_name, pages, direct_responses=None):
        self.operation_name = operation_name
        self.pages = pages
        self.direct_responses = direct_responses or {}

    def __getattr__(self, name):
        if name == self.operation_name:
            return lambda **kwargs: self.pages[0]
        if name in self.direct_responses:
            response = self.direct_responses[name]
            return lambda **kwargs: response(kwargs) if callable(response) else response
        raise AttributeError(name)

    def can_paginate(self, operation_name):
        return operation_name == self.operation_name

    def get_paginator(self, operation_name):
        if operation_name != self.operation_name:
            raise AssertionError(operation_name)
        return FakePaginator(self.pages)


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        boto3.setup_default_session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
            region_name="us-gov-west-1",
        )
        analyzer.research["region"] = "us-gov-west-1"
        analyzer.account_id = "123456789012"

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)

    def setUp(self):
        analyzer.shutdown_event.clear()

    def test_validate_region_accepts_only_govcloud_shape(self):
        analyzer.validate_region("us-gov-west-1")
        analyzer.validate_region("us-gov-future-2")
        with self.assertRaises(ValueError):
            analyzer.validate_region("us-east-1")

    def test_repository_contains_no_em_dash_characters(self):
        project_root = Path(__file__).resolve().parent.parent
        excluded_parts = {".git", ".mypy_cache", ".ruff_cache", ".venv", "output", "tmp", "venv"}
        text_suffixes = {".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
        extensionless_text_files = {".editorconfig", ".gitattributes", ".gitignore", "LICENSE"}

        for path in project_root.rglob("*"):
            if not path.is_file() or excluded_parts.intersection(path.parts):
                continue
            if path.suffix not in text_suffixes and path.name not in extensionless_text_files:
                continue
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", content, str(path.relative_to(project_root)))

    def test_client_errors_redact_account_and_access_key_ids(self):
        synthetic_access_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        error = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": f"Account 123456789012 denied for {synthetic_access_key}",
                }
            },
            "TestOperation",
        )
        message = analyzer.sanitize_error_message(error)
        self.assertEqual(
            message,
            "AccessDeniedException: Account [ACCOUNT_ID] denied for [ACCESS_KEY_ID]",
        )

    def test_resolve_services_is_flexible_and_deduplicates(self):
        self.assertEqual(
            analyzer.resolve_services(["s3,ec2", "security", "hub", "S3"]),
            ["S3", "EC2", "Security Hub"],
        )
        with self.assertRaises(ValueError):
            analyzer.resolve_services(["not-a-service"])

    def test_pagination_combines_all_pages(self):
        client = FakeClient("list_things", [{"Things": [1, 2]}, {"Things": [3]}])
        response = analyzer.paginated_api_call("Test", client, "list_things", "Things")
        self.assertEqual(response["Things"], [1, 2, 3])

    def test_skip_metrics_is_unknown_not_zero(self):
        metric = analyzer.get_cloudwatch_metric(
            object(),
            "AWS/Test",
            "Requests",
            [],
            datetime.datetime.now(datetime.timezone.utc),
            datetime.datetime.now(datetime.timezone.utc),
            skip_metrics=True,
        )
        self.assertIsNone(metric["average"])
        self.assertEqual(metric["status"], "skipped")
        self.assertFalse(analyzer.metric_is_below(metric, 1))

    def test_s3_analyzes_only_buckets_in_the_selected_region(self):
        buckets = [{"Name": "west-bucket"}, {"Name": "east-bucket"}]

        def bucket_location(kwargs):
            return {"LocationConstraint": "us-gov-west-1" if kwargs["Bucket"] == "west-bucket" else "us-gov-east-1"}

        client = FakeClient(
            "list_buckets",
            [{"Buckets": buckets}],
            {
                "get_bucket_location": bucket_location,
                "get_bucket_lifecycle_configuration": {"Rules": []},
                "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                "get_bucket_acl": {"Grants": []},
                "get_public_access_block": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                },
                "get_bucket_encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                },
            },
        )
        result = analyzer.research_s3(client, object(), skip_metrics=True)
        self.assertEqual(result["partition_bucket_count"], 2)
        self.assertEqual(result["bucket_count"], 1)
        self.assertEqual(result["bucket_details"][0]["bucket_name"], "west-bucket")

    def test_lambda_skip_metrics_does_not_create_low_usage_finding(self):
        client = FakeClient(
            "list_functions",
            [{"Functions": [{"FunctionName": "quiet-function", "MemorySize": 2048}]}],
        )
        result = analyzer.research_lambda(client, object(), skip_metrics=True)
        detail = result["function_details"][0]
        self.assertIsNone(detail["invocations_avg"])
        self.assertEqual(detail["recommendations"], [])

    def test_ec2_root_encryption_matches_the_root_device(self):
        instance = {
            "InstanceId": "i-0123456789abcdef0",
            "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "RootDeviceName": "/dev/sda1",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-root"}},
                {"DeviceName": "/dev/sdf", "Ebs": {"VolumeId": "vol-data"}},
            ],
        }

        def volumes(_kwargs):
            return {
                "Volumes": [
                    {"VolumeId": "vol-root", "Encrypted": False},
                    {"VolumeId": "vol-data", "Encrypted": True},
                ]
            }

        client = FakeClient(
            "describe_instances",
            [{"Reservations": [{"Instances": [instance]}]}],
            {"describe_volumes": volumes},
        )
        result = analyzer.research_ec2(client, object(), skip_metrics=True)
        self.assertIs(result["instance_details"][0]["is_root_encrypted"], False)
        self.assertEqual(result["unencrypted_instance_count"], 1)

    def test_iam_does_not_flag_resource_wildcard_without_broad_action(self):
        policies = [
            {
                "PolicyName": "ReadSpecific",
                "Arn": "arn:aws-us-gov:iam::123456789012:policy/ReadSpecific",
                "DefaultVersionId": "v1",
                "AttachmentCount": 1,
            }
        ]
        client = FakeClient(
            "list_policies",
            [{"Policies": policies}],
            {
                "get_policy_version": {
                    "PolicyVersion": {
                        "Document": {
                            "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]
                        }
                    }
                }
            },
        )
        result = analyzer.research_iam(client, skip_metrics=True)
        self.assertFalse(result["policy_details"][0]["is_overly_permissive"])

    def test_pdf_smoke_with_missing_metrics_and_xml_characters(self):
        report = {
            "timestamp": "2026-08-12T12:00:00+00:00",
            "region": "us-gov-west-1",
            "banner": "TEST DATA",
            "services": {
                "S3": {
                    "bucket_count": 1,
                    "buckets_analyzed": 1,
                    "bucket_details": [
                        {
                            "bucket_name": "bucket-<unsafe>&name",
                            "object_count_avg": None,
                            "lifecycle_enabled": False,
                            "is_public": False,
                            "encryption_algorithm": "AES256",
                            "recommendations": [{"description": "Review <retention> & ownership."}],
                        }
                    ],
                    "general_recommendations": [],
                    "total_estimated_savings": 0,
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.pdf"
            analyzer.generate_pdf_report(report, output)
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 1_000)
            self.assertEqual(output.read_bytes()[:4], b"%PDF")

    def test_all_service_entry_points_accept_current_empty_api_shapes(self):
        initial = {
            "S3": [("list_buckets", {"Buckets": [], "Owner": {"DisplayName": "test", "ID": "owner"}}, {})],
            "VPC": [("describe_vpcs", {"Vpcs": []}, {})],
            "Direct Connect": [("describe_connections", {"connections": []}, {})],
            "Backup": [("list_backup_plans", {"BackupPlansList": []}, {})],
            "Lambda": [("list_functions", {"Functions": []}, {})],
            "OpenSearch": [("list_domain_names", {"DomainNames": []}, {})],
            "CloudFormation": [("list_stacks", {"StackSummaries": []}, {})],
            "ECS": [("list_clusters", {"clusterArns": []}, {})],
            "AppStream": [("describe_fleets", {"Fleets": []}, {})],
            "Directory Service": [("describe_directories", {"DirectoryDescriptions": []}, {})],
            "EBS": [("describe_volumes", {"Volumes": []}, {})],
            "EFS": [("describe_file_systems", {"FileSystems": []}, {})],
            "Kinesis": [("list_streams", {"StreamNames": [], "HasMoreStreams": False}, {})],
            "SES": [("list_identities", {"Identities": []}, {})],
            "WAF": [("list_web_acls", {"WebACLs": []}, {"Scope": "REGIONAL"})],
            "KMS": [("list_keys", {"Keys": []}, {})],
            "GuardDuty": [("list_detectors", {"DetectorIds": []}, {})],
            "IAM": [("list_policies", {"Policies": []}, {"Scope": "Local"})],
            "Firewall Manager": [("list_policies", {"PolicyList": []}, {})],
            "EC2": [("describe_instances", {"Reservations": []}, {})],
            "Inspector": [
                ("batch_get_account_status", {"accounts": [], "failedAccounts": []}, {"accountIds": ["123456789012"]})
            ],
            "Security Hub": [
                (
                    "describe_hub",
                    {
                        "HubArn": "arn:aws-us-gov:securityhub:us-gov-west-1:123456789012:hub/default",
                        "SubscribedAt": "2026-01-01T00:00:00Z",
                    },
                    {},
                )
            ],
            "CloudTrail": [("describe_trails", {"trailList": []}, {"includeShadowTrails": False})],
            "CloudWatch": [("describe_alarms", {"MetricAlarms": [], "CompositeAlarms": []}, {})],
            "RDS": [("describe_db_instances", {"DBInstances": []}, {})],
            "CodeCommit": [("list_repositories", {"repositories": []}, {})],
            "ECR": [("describe_repositories", {"repositories": []}, {})],
            "Trusted Advisor": [("describe_trusted_advisor_checks", {"checks": []}, {"language": "en"})],
        }

        for service, (function, client_names) in analyzer.service_map.items():
            clients = []
            stubbers = []
            for client_name in client_names:
                client = boto3.client(client_name, region_name="us-gov-west-1")
                clients.append(client)
                stubbers.append(Stubber(client))
            if service == "ELB":
                stubbers[0].add_response("describe_load_balancers", {"LoadBalancerDescriptions": []}, {})
                stubbers[1].add_response("describe_load_balancers", {"LoadBalancers": []}, {})
            else:
                for operation, response, parameters in initial[service]:
                    stubbers[0].add_response(operation, response, parameters)
            for stubber in stubbers:
                stubber.activate()
            result = function(*clients, skip_metrics=True)
            self.assertNotIn("error", result, service)
            for stubber in stubbers:
                stubber.assert_no_pending_responses()
                stubber.deactivate()


if __name__ == "__main__":
    unittest.main()
