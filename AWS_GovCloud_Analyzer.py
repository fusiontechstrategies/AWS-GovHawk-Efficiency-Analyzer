"""GovHawk: a single-file, read-mostly AWS GovCloud environment analyzer.

The analyzer inventories supported services, evaluates a conservative set of
configuration and utilization signals, and writes a PDF or JSON report. It does
not execute remediation commands. The optional CloudWatch logging feature is the
only mode that creates AWS resources or sends data to an AWS service.

Automated findings are review signals, not a compliance determination or a
guaranteed savings forecast.
"""

# ============================================================================
# Imports
# ============================================================================
import argparse
import datetime
import json
import logging
import os
import re
import shlex
import signal
import stat
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timezone
from pathlib import Path
from time import sleep
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ============================================================================
# Logging Setup
# ============================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("govhawk")

# ============================================================================
# Global State
# ============================================================================
VERSION = "2.0.0"
DEFAULT_REGION = "us-gov-west-1"
DEFAULT_BANNER = "SENSITIVE - REVIEW BEFORE SHARING"
AWS_CLIENT_CONFIG = Config(
    connect_timeout=10,
    read_timeout=60,
    retries={"max_attempts": 10, "mode": "standard"},
    user_agent_extra=f"GovHawk/{VERSION}",
)

research: dict[str, Any] = {
    "timestamp": None,  # Set in main() at analysis start
    "region": DEFAULT_REGION,
    "services": {},
}

# Set in main() after credentials and region are validated.
account_id = "ACCOUNT_ID"
metric_lookback_days = 14

# Graceful shutdown event (thread-safe)
shutdown_event = threading.Event()

# Lock for thread-safe dictionary updates
research_lock = threading.Lock()
client_creation_lock = threading.Lock()


# ============================================================================
# Signal Handler
# ============================================================================
def signal_handler(sig, frame):
    del sig, frame
    logger.info("Ctrl+C detected, initiating graceful shutdown...")
    shutdown_event.set()


# ============================================================================
# Sanitization Helpers
# ============================================================================
def sanitize_for_paragraph(text):
    """Escape XML special chars to prevent ReportLab XML injection."""
    if not isinstance(text, str):
        text = str(text)
    return xml_escape(text, entities={'"': "&quot;", "'": "&#39;"})


def shell_quote(value):
    """Shell-escape a value for safe inclusion in remediation CLI commands."""
    if not isinstance(value, str):
        value = str(value)
    return shlex.quote(value)


def sanitize_error_message(error):
    """Return a useful error summary without tracebacks or request metadata."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        msg = error.response.get("Error", {}).get("Message", "Unknown error")
        return f"{code}: {msg}"
    if isinstance(error, NoCredentialsError):
        return "Credentials not found"
    return type(error).__name__


def validate_region(region):
    """Validate a current or future AWS GovCloud (US) region name."""
    if not re.fullmatch(r"us-gov-[a-z]+-\d+", region):
        raise ValueError(f"Expected an AWS GovCloud region such as us-gov-west-1; received: {region}")


# ============================================================================
# Helper Functions
# ============================================================================
def safe_api_call(service, func, suppress_errors=None, **kwargs):
    if shutdown_event.is_set():
        return {"error": "Shutdown initiated"}
    try:
        return func(**kwargs)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if suppress_errors and error_code in suppress_errors:
            return {"suppressed_error": error_code}
        safe_msg = sanitize_error_message(e)
        logger.error(f"Error calling {service}: {safe_msg}")
        return {"error": safe_msg}
    except NoCredentialsError:
        logger.error(f"Credentials not found for {service}")
        return {"error": "Credentials not found"}
    except BotoCoreError as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Unexpected error in {service}: {safe_msg}")
        return {"error": safe_msg}
    except Exception as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Unexpected error in {service}: {safe_msg}")
        return {"error": safe_msg}


def paginated_api_call(service, client, operation_name, result_keys, **kwargs):
    """Call an AWS list/describe operation and combine every result page."""
    keys = [result_keys] if isinstance(result_keys, str) else list(result_keys)
    try:
        operation = getattr(client, operation_name)
        if not client.can_paginate(operation_name):
            return safe_api_call(service, operation, **kwargs)

        combined: dict[str, Any] = {key: [] for key in keys}
        for page in client.get_paginator(operation_name).paginate(**kwargs):
            for key in keys:
                values = page.get(key, [])
                if isinstance(values, list):
                    combined[key].extend(values)
            if shutdown_event.is_set():
                combined["truncated"] = True
                break
        return combined
    except ClientError as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Error calling {service}: {safe_msg}")
        return {"error": safe_msg}
    except (BotoCoreError, AttributeError) as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Unexpected error in {service}: {safe_msg}")
        return {"error": safe_msg}
    except Exception as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Unexpected error in {service}: {safe_msg}")
        return {"error": safe_msg}


def create_aws_client(service_name, region=None):
    """Create a consistently configured low-level AWS client."""
    return boto3.client(
        service_name,
        region_name=region or str(research["region"]),
        config=AWS_CLIENT_CONFIG,
    )


def get_cloudwatch_metric(
    client, namespace, metric_name, dimensions, start_time, end_time, period=86400, stat="Average", skip_metrics=False
):
    if skip_metrics:
        return {"average": None, "values": [], "status": "skipped"}
    if shutdown_event.is_set():
        return {"error": "Shutdown initiated"}
    try:
        response = client.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {"Namespace": namespace, "MetricName": metric_name, "Dimensions": dimensions},
                        "Period": period,
                        "Stat": stat,
                    },
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
        )
        results = response.get("MetricDataResults", [])
        values = results[0].get("Values", []) if results else []
        if not values:
            return {"average": None, "values": [], "status": "no_data"}
        return {
            "average": sum(values) / len(values),
            "values": values,
            "status": "ok",
            "sample_count": len(values),
        }
    except Exception as e:
        logger.error(f"Error fetching CloudWatch metric {metric_name} for {namespace}")
        return {"error": sanitize_error_message(e)}


def metric_is_below(metric, threshold):
    """Return true only when CloudWatch returned real samples below a threshold."""
    return metric.get("status") == "ok" and metric.get("average") is not None and metric["average"] < threshold


class JsonLogFormatter(logging.Formatter):
    """Small built-in JSON formatter used by the optional CloudWatch handler."""

    def format(self, record):
        return json.dumps(
            {
                "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            },
            ensure_ascii=True,
        )


def setup_cloudwatch_logging(log_group, log_stream, region):
    try:
        client = create_aws_client("logs", region)
        client.create_log_group(logGroupName=log_group)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            logger.warning(f"Failed to create CloudWatch log group: {sanitize_error_message(e)}")
            return
    except Exception as e:
        logger.warning(f"Failed to create CloudWatch log group: {sanitize_error_message(e)}")
        return
    try:
        client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            logger.warning(f"Failed to create CloudWatch log stream: {sanitize_error_message(e)}")
            return
    except Exception as e:
        logger.warning(f"Failed to create CloudWatch log stream: {sanitize_error_message(e)}")
        return

    cw_lock = threading.Lock()
    sequence_token = [None]

    class CloudWatchHandler(logging.Handler):
        def emit(self, record):
            if shutdown_event.is_set():
                return
            try:
                log_entry = self.format(record)
                with cw_lock:
                    kwargs = {
                        "logGroupName": log_group,
                        "logStreamName": log_stream,
                        "logEvents": [
                            {
                                "timestamp": int(datetime.datetime.now(timezone.utc).timestamp() * 1000),
                                "message": log_entry,
                            }
                        ],
                    }
                    if sequence_token[0]:
                        kwargs["sequenceToken"] = sequence_token[0]
                    resp = client.put_log_events(**kwargs)
                    sequence_token[0] = resp.get("nextSequenceToken")
            except Exception:
                pass  # Avoid recursive logging failures

    handler = CloudWatchHandler()
    handler.setFormatter(JsonLogFormatter())
    logger.addHandler(handler)
    logger.info("CloudWatch logging enabled")


# ============================================================================
# Service Analysis Functions
# ============================================================================


def research_s3(client, cw_client, skip_metrics=False):
    logger.info("=== Starting S3 Research ===")
    response = safe_api_call("S3", client.list_buckets)
    if "error" in response:
        return response
    buckets = response.get("Buckets", [])
    logger.info(f"Found {len(buckets)} S3 buckets to analyze")
    end_time = datetime.datetime.now(timezone.utc)
    start_time = end_time - datetime.timedelta(days=metric_lookback_days)
    region = research["region"]

    bucket_details = []
    no_lifecycle_count = 0
    lifecycle_unknown_count = 0
    public_bucket_count = 0
    public_status_unknown_count = 0
    encryption_unknown_count = 0

    for bucket in buckets:
        if shutdown_event.is_set():
            break
        bucket_name = bucket["Name"]
        logger.info(f"Processing S3 bucket: {bucket_name[:20]}...")
        metrics = get_cloudwatch_metric(
            cw_client,
            "AWS/S3",
            "NumberOfObjects",
            [{"Name": "BucketName", "Value": bucket_name}, {"Name": "StorageType", "Value": "AllStorageTypes"}],
            start_time,
            end_time,
            skip_metrics=skip_metrics,
        )
        lifecycle = safe_api_call(
            "S3",
            client.get_bucket_lifecycle_configuration,
            Bucket=bucket_name,
            suppress_errors=["NoSuchLifecycleConfiguration"],
        )
        policy_status = safe_api_call(
            "S3", client.get_bucket_policy_status, Bucket=bucket_name, suppress_errors=["NoSuchBucketPolicy"]
        )
        bucket_acl = safe_api_call("S3", client.get_bucket_acl, Bucket=bucket_name)
        public_access = safe_api_call(
            "S3",
            client.get_public_access_block,
            Bucket=bucket_name,
            suppress_errors=["NoSuchPublicAccessBlockConfiguration"],
        )
        encryption = safe_api_call(
            "S3",
            client.get_bucket_encryption,
            Bucket=bucket_name,
            suppress_errors=["ServerSideEncryptionConfigurationNotFoundError"],
        )

        if "error" in lifecycle:
            lifecycle_enabled = None
        else:
            lifecycle_enabled = any(rule.get("Status") == "Enabled" for rule in lifecycle.get("Rules", []))

        policy_verified = "error" not in policy_status
        policy_public = bool(policy_status.get("PolicyStatus", {}).get("IsPublic")) if policy_verified else False
        public_group_uris = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }
        acl_verified = "error" not in bucket_acl
        acl_public = (
            any(grant.get("Grantee", {}).get("URI") in public_group_uris for grant in bucket_acl.get("Grants", []))
            if acl_verified
            else False
        )
        is_public = True if policy_public or acl_public else (False if policy_verified and acl_verified else None)

        if "error" in public_access:
            public_access_block_enabled = None
        else:
            block_config = public_access.get("PublicAccessBlockConfiguration", {})
            public_access_block_enabled = bool(block_config) and all(
                block_config.get(key, False)
                for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            )

        encryption_rules = (
            encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if isinstance(encryption, dict)
            else []
        )
        encryption_algorithm = None
        if encryption_rules:
            encryption_algorithm = encryption_rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")

        detail = {
            "bucket_name": bucket_name,
            "object_count_avg": metrics.get("average"),
            "metric_status": metrics.get("status", "error"),
            "lifecycle_enabled": lifecycle_enabled,
            "is_public": is_public,
            "public_access_block_enabled": public_access_block_enabled,
            "encryption_algorithm": encryption_algorithm or "Unknown",
            "estimated_savings": 0,
            "recommendations": [],
        }

        if lifecycle_enabled is False:
            detail["recommendations"].append(
                {
                    "description": "No enabled lifecycle rule was detected. Review object age and retention requirements before adding transitions or expirations.",
                    "remediation_steps": [
                        f"aws s3api put-bucket-lifecycle-configuration --bucket {shell_quote(bucket_name)} --lifecycle-configuration file://lifecycle.json --region {shell_quote(region)}",
                        "Example lifecycle.json: {'Rules': [{'ID': 'GlacierRule', 'Status': 'Enabled', 'Filter': {}, 'Transitions': [{'Days': 90, 'StorageClass': 'GLACIER'}]}]}",
                    ],
                }
            )
            no_lifecycle_count += 1
        elif lifecycle_enabled is None:
            detail["recommendations"].append({"description": "Bucket lifecycle configuration could not be verified."})
            lifecycle_unknown_count += 1

        if is_public:
            detail["recommendations"].append(
                {
                    "description": "AWS reports public access through the bucket policy or ACL. Confirm that public access is intentional and authorized.",
                    "remediation_steps": [
                        f"aws s3api put-public-access-block --bucket {shell_quote(bucket_name)} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --region {shell_quote(region)}"
                    ],
                }
            )
            public_bucket_count += 1
        elif is_public is None:
            detail["recommendations"].append(
                {"description": "Bucket policy or ACL public-access status could not be fully verified."}
            )
            public_status_unknown_count += 1

        if public_access_block_enabled is False:
            detail["recommendations"].append(
                {
                    "description": "All four bucket-level S3 Block Public Access controls are not enabled. Review the account-level and bucket-level settings."
                }
            )
        elif public_access_block_enabled is None:
            detail["recommendations"].append(
                {"description": "Bucket-level S3 Block Public Access controls could not be verified."}
            )

        if encryption_algorithm is None:
            detail["recommendations"].append(
                {
                    "description": "Default bucket encryption could not be verified. Confirm the effective encryption configuration and required KMS key policy."
                }
            )
            encryption_unknown_count += 1

        bucket_details.append(detail)

    general_recommendations = [
        {
            "description": "Use S3 Storage Lens or Storage Class Analysis before changing storage classes; object counts alone cannot support a savings estimate."
        }
    ]
    if no_lifecycle_count > 0:
        general_recommendations.append(
            {
                "description": f"{no_lifecycle_count} buckets have no enabled lifecycle rule. Validate retention requirements before changing them."
            }
        )
    if lifecycle_unknown_count > 0:
        general_recommendations.append(
            {"description": f"Lifecycle settings could not be verified for {lifecycle_unknown_count} buckets."}
        )
    if public_bucket_count > 0:
        general_recommendations.append(
            {
                "description": f"{public_bucket_count} buckets were reported as public through policy or ACL evaluation. Review immediately."
            }
        )
    if public_status_unknown_count > 0:
        general_recommendations.append(
            {
                "description": f"Public-access status could not be fully verified for {public_status_unknown_count} buckets."
            }
        )
    if encryption_unknown_count > 0:
        general_recommendations.append(
            {"description": f"Encryption settings could not be verified for {encryption_unknown_count} buckets."}
        )

    logger.info("=== Completed S3 Research ===")
    return {
        "bucket_count": len(buckets),
        "buckets_analyzed": len(bucket_details),
        "public_bucket_count": public_bucket_count,
        "public_status_unknown_count": public_status_unknown_count,
        "lifecycle_unknown_count": lifecycle_unknown_count,
        "encryption_unknown_count": encryption_unknown_count,
        "bucket_details": bucket_details,
        "total_estimated_savings": 0,
        "general_recommendations": general_recommendations,
    }


def research_vpc(client, skip_metrics=False):
    logger.info("=== Starting VPC Research ===")
    response = paginated_api_call("VPC", client, "describe_vpcs", "Vpcs")
    if "error" in response:
        return response
    vpcs = response.get("Vpcs", [])
    logger.info(f"Found {len(vpcs)} VPCs to analyze")
    region = research["region"]

    vpc_details = []
    for vpc in vpcs:
        if shutdown_event.is_set():
            break
        vpc_id = vpc["VpcId"]
        logger.info(f"Processing VPC: {vpc_id}")
        subnets = paginated_api_call(
            "VPC",
            client,
            "describe_subnets",
            "Subnets",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        detail = {
            "vpc_id": vpc_id,
            "cidr_block": vpc.get("CidrBlock", "N/A"),
            "subnet_count": len(subnets.get("Subnets", [])) if isinstance(subnets, dict) else 0,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if detail["subnet_count"] == 0:
            detail["recommendations"].append(
                {
                    "description": "VPC has no subnets. Confirm it has no attached gateways, endpoints, peerings, or other dependencies before considering cleanup.",
                    "remediation_steps": [
                        f"aws ec2 delete-vpc --vpc-id {shell_quote(vpc_id)} --region {shell_quote(region)}"
                    ],
                }
            )
        vpc_details.append(detail)

    logger.info("=== Completed VPC Research ===")
    return {
        "vpc_count": len(vpcs),
        "vpcs_analyzed": len(vpc_details),
        "vpc_details": vpc_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Empty VPCs are an operational cleanup signal; VPCs and subnets themselves do not establish a savings amount."
            }
        ],
    }


def research_direct_connect(client, skip_metrics=False):
    logger.info("=== Starting Direct Connect Research ===")
    response = paginated_api_call("Direct Connect", client, "describe_connections", "connections")
    if "error" in response:
        return response
    connections = response.get("connections", [])
    logger.info(f"Found {len(connections)} Direct Connect connections to analyze")
    region = research["region"]

    connection_details = []
    for conn in connections:
        if shutdown_event.is_set():
            break
        conn_id = conn["connectionId"]
        logger.info(f"Processing Direct Connect connection: {conn_id}")
        detail = {
            "connection_id": conn_id,
            "state": conn.get("connectionState", "N/A"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if conn.get("connectionState") in ["down", "deleted", "rejected", "unknown"]:
            detail["recommendations"].append(
                {
                    "description": "Connection is not active. Review its billing state, virtual interfaces, and resiliency design before deletion.",
                    "remediation_steps": [
                        f"aws directconnect delete-connection --connection-id {shell_quote(conn_id)} --region {shell_quote(region)}"
                    ],
                }
            )
        connection_details.append(detail)

    logger.info("=== Completed Direct Connect Research ===")
    return {
        "connection_count": len(connections),
        "connections_analyzed": len(connection_details),
        "connection_details": connection_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Monitor inactive connections for decommissioning."}],
    }


def research_backup(client, skip_metrics=False):
    logger.info("=== Starting Backup Research ===")
    response = paginated_api_call("Backup", client, "list_backup_plans", "BackupPlansList")
    if "error" in response:
        return response
    plans = response.get("BackupPlansList", [])
    logger.info(f"Found {len(plans)} Backup plans to analyze")
    region = research["region"]

    plan_details = []
    for plan in plans:
        if shutdown_event.is_set():
            break
        plan_id = plan["BackupPlanId"]
        logger.info(f"Processing Backup plan: {plan_id}")
        plan_response = (
            safe_api_call(
                "Backup",
                client.get_backup_plan,
                BackupPlanId=plan_id,
                VersionId=plan.get("VersionId"),
            )
            if plan.get("VersionId")
            else safe_api_call("Backup", client.get_backup_plan, BackupPlanId=plan_id)
        )
        rules = plan_response.get("BackupPlan", {}).get("Rules", []) if isinstance(plan_response, dict) else []
        lifecycle_rule_count = sum(1 for rule in rules if rule.get("Lifecycle"))
        detail = {
            "plan_id": plan_id,
            "name": plan.get("BackupPlanName", "N/A"),
            "rule_count": len(rules),
            "rules_with_lifecycle": lifecycle_rule_count,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if rules and lifecycle_rule_count < len(rules):
            detail["recommendations"].append(
                {
                    "description": "One or more backup rules have no lifecycle configuration. Validate retention and cold-storage requirements before updating the plan.",
                    "remediation_steps": [
                        f"aws backup update-backup-plan --backup-plan-id {shell_quote(plan_id)} --backup-plan file://backup_plan.json --region {shell_quote(region)}"
                    ],
                }
            )
        elif not rules:
            detail["recommendations"].append({"description": "Backup plan rules could not be verified."})
        plan_details.append(detail)

    logger.info("=== Completed Backup Research ===")
    return {
        "backup_plan_count": len(plans),
        "plans_analyzed": len(plan_details),
        "plan_details": plan_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Validate backup retention, Vault Lock, and restore testing against the workload's recovery objectives."
            }
        ],
    }


def research_lambda(client, cw_client, skip_metrics=False):
    logger.info("=== Starting Lambda Research ===")
    response = paginated_api_call("Lambda", client, "list_functions", "Functions")
    if "error" in response:
        return response
    functions = response.get("Functions", [])
    logger.info(f"Found {len(functions)} Lambda functions to analyze")
    end_time = datetime.datetime.now(timezone.utc)
    start_time = end_time - datetime.timedelta(days=metric_lookback_days)
    region = research["region"]

    function_details = []
    for func in functions:
        if shutdown_event.is_set():
            break
        func_name = func["FunctionName"]
        logger.info(f"Processing Lambda function: {func_name[:30]}...")
        invocations = get_cloudwatch_metric(
            cw_client,
            "AWS/Lambda",
            "Invocations",
            [{"Name": "FunctionName", "Value": func_name}],
            start_time,
            end_time,
            stat="Sum",
            skip_metrics=skip_metrics,
        )

        detail = {
            "function_name": func_name,
            "memory_size": func.get("MemorySize", 0),
            "invocations_avg": invocations.get("average"),
            "metric_status": invocations.get("status", "error"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if metric_is_below(invocations, 1):
            detail["recommendations"].append(
                {
                    "description": "Function averaged fewer than one invocation per day in the observation window. Confirm schedules and event sources before considering retirement.",
                    "remediation_steps": [
                        f"aws lambda delete-function --function-name {shell_quote(func_name)} --region {shell_quote(region)}"
                    ],
                }
            )
        function_details.append(detail)

    logger.info("=== Completed Lambda Research ===")
    return {
        "function_count": len(functions),
        "functions_analyzed": len(function_details),
        "function_details": function_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Use Lambda Power Tuning or AWS Compute Optimizer data before changing memory; memory size alone is not an efficiency signal."
            }
        ],
    }


def research_opensearch(client, skip_metrics=False):
    logger.info("=== Starting OpenSearch Research ===")
    response = paginated_api_call("OpenSearch", client, "list_domain_names", "DomainNames")
    if "error" in response:
        return response
    domains = response.get("DomainNames", [])
    logger.info(f"Found {len(domains)} OpenSearch domains to analyze")
    region = research["region"]

    domain_details = []
    for domain in domains:
        if shutdown_event.is_set():
            break
        domain_name = domain["DomainName"]
        logger.info(f"Processing OpenSearch domain: {domain_name[:30]}...")
        detail = {"domain_name": domain_name, "estimated_savings": 0, "recommendations": []}
        detail["recommendations"].append(
            {
                "description": "Review domain usage and consider right-sizing instance types.",
                "remediation_steps": [
                    f"aws opensearch describe-domain --domain-name {shell_quote(domain_name)} --region {shell_quote(region)}"
                ],
            }
        )
        domain_details.append(detail)

    logger.info("=== Completed OpenSearch Research ===")
    return {
        "domain_count": len(domains),
        "domains_analyzed": len(domain_details),
        "domain_details": domain_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Review OpenSearch domains for usage and right-size instance types."}
        ],
    }


def research_cloudformation(client, skip_metrics=False):
    logger.info("=== Starting CloudFormation Research ===")
    response = paginated_api_call("CloudFormation", client, "list_stacks", "StackSummaries")
    if "error" in response:
        return response
    stacks = [stack for stack in response.get("StackSummaries", []) if stack.get("StackStatus") != "DELETE_COMPLETE"]
    logger.info(f"Found {len(stacks)} CloudFormation stacks to analyze")
    region = research["region"]

    stack_details = []
    for stack_item in stacks:
        if shutdown_event.is_set():
            break
        stack_name = stack_item["StackName"]
        logger.info(f"Processing CloudFormation stack: {stack_name[:30]}...")
        resources = paginated_api_call(
            "CloudFormation",
            client,
            "list_stack_resources",
            "StackResourceSummaries",
            StackName=stack_name,
        )
        drift_status = stack_item.get("DriftInformation", {}).get("StackDriftStatus", "NOT_CHECKED")

        detail = {
            "stack_name": stack_name,
            "resource_count": len(resources.get("StackResourceSummaries", [])) if isinstance(resources, dict) else 0,
            "stack_status": stack_item.get("StackStatus", "N/A"),
            "drift_status": drift_status,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if drift_status == "DRIFTED":
            detail["recommendations"].append(
                {
                    "description": "Stack has drifted. Run 'detect-stack-drift' and reconcile manual changes.",
                    "remediation_steps": [
                        f"aws cloudformation detect-stack-drift --stack-name {shell_quote(stack_name)} --region {shell_quote(region)}"
                    ],
                }
            )
        stack_details.append(detail)

    logger.info("=== Completed CloudFormation Research ===")
    return {
        "stack_count": len(stacks),
        "stacks_analyzed": len(stack_details),
        "stack_details": stack_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Drift status reflects the last completed drift check; this analyzer does not start drift detection operations."
            }
        ],
    }


def research_ecs(client, skip_metrics=False):
    logger.info("=== Starting ECS Research ===")
    response = paginated_api_call("ECS", client, "list_clusters", "clusterArns")
    if "error" in response:
        return response
    clusters = response.get("clusterArns", [])
    logger.info(f"Found {len(clusters)} ECS clusters to analyze")
    cluster_details = []

    for cluster_arn in clusters:
        if shutdown_event.is_set():
            break
        cluster_name = cluster_arn.split("/")[-1]
        logger.info(f"Processing ECS cluster: {cluster_name[:30]}...")
        cluster = safe_api_call("ECS", client.describe_clusters, clusters=[cluster_arn])
        if "error" in cluster:
            continue
        services = paginated_api_call("ECS", client, "list_services", "serviceArns", cluster=cluster_arn)
        if "error" in services:
            continue

        cluster_info = cluster.get("clusters", [{}])[0] if cluster.get("clusters") else {}

        detail = {
            "cluster_name": cluster_name,
            "status": cluster_info.get("status", "N/A"),
            "service_count": len(services.get("serviceArns", [])),
            "registered_container_instances": cluster_info.get("registeredContainerInstancesCount", 0),
            "running_task_count": cluster_info.get("runningTasksCount", 0),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if (
            detail["service_count"] == 0
            and detail["running_task_count"] == 0
            and detail["registered_container_instances"] == 0
        ):
            detail["recommendations"].append(
                {
                    "description": "Cluster has no services, running tasks, or registered container instances. Confirm it is unused before deleting the empty cluster."
                }
            )
        cluster_details.append(detail)

    logger.info("=== Completed ECS Research ===")
    return {
        "cluster_count": len(clusters),
        "clusters_analyzed": len(cluster_details),
        "cluster_details": cluster_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Use service-level CPU and memory metrics or Compute Optimizer recommendations before changing ECS task sizing."
            }
        ],
    }


def research_appstream(client, skip_metrics=False):
    logger.info("=== Starting AppStream Research ===")
    response = paginated_api_call("AppStream", client, "describe_fleets", "Fleets")
    if "error" in response:
        return response
    fleets = response.get("Fleets", [])
    logger.info(f"Found {len(fleets)} AppStream fleets to analyze")
    region = research["region"]

    fleet_details = []
    for fleet in fleets:
        if shutdown_event.is_set():
            break
        fleet_name = fleet["Name"]
        logger.info(f"Processing AppStream fleet: {fleet_name[:30]}...")
        detail = {
            "fleet_name": fleet_name,
            "state": fleet.get("State", "N/A"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if fleet.get("State") in {"STOPPED", "STOPPING"}:
            detail["recommendations"].append(
                {
                    "description": "Fleet is stopped. Confirm its schedule, image, and user assignments before deciding whether it should be retained.",
                    "remediation_steps": [
                        f"aws appstream delete-fleet --name {shell_quote(fleet_name)} --region {shell_quote(region)}"
                    ],
                }
            )
        fleet_details.append(detail)

    logger.info("=== Completed AppStream Research ===")
    return {
        "fleet_count": len(fleets),
        "fleets_analyzed": len(fleet_details),
        "fleet_details": fleet_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Monitor fleet usage and scale down inactive fleets."}],
    }


def research_directory_service(client, skip_metrics=False):
    logger.info("=== Starting Directory Service Research ===")
    response = paginated_api_call("Directory Service", client, "describe_directories", "DirectoryDescriptions")
    if "error" in response:
        return response
    directories = response.get("DirectoryDescriptions", [])
    logger.info(f"Found {len(directories)} Directory Service directories to analyze")

    directory_details = []
    for directory in directories:
        if shutdown_event.is_set():
            break
        dir_id = directory["DirectoryId"]
        logger.info(f"Processing Directory: {dir_id}")
        detail = {
            "directory_id": dir_id,
            "name": directory.get("Name", "N/A"),
            "type": directory.get("Type", "N/A"),
            "stage": directory.get("Stage", "N/A"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if directory.get("Stage") in {"Failed", "Impaired", "Inoperable"}:
            detail["recommendations"].append(
                {"description": "Directory is not healthy. Investigate its status before making lifecycle decisions."}
            )
        directory_details.append(detail)

    logger.info("=== Completed Directory Service Research ===")
    return {
        "directory_count": len(directories),
        "directories_analyzed": len(directory_details),
        "directory_details": directory_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Review directory usage and consolidate if possible."}],
    }


def research_ebs(client, cw_client, skip_metrics=False):
    logger.info("=== Starting EBS Research ===")
    response = paginated_api_call("EBS", client, "describe_volumes", "Volumes")
    if "error" in response:
        return response
    volumes = response.get("Volumes", [])
    logger.info(f"Found {len(volumes)} EBS volumes to analyze")
    end_time = datetime.datetime.now(timezone.utc)
    start_time = end_time - datetime.timedelta(days=metric_lookback_days)
    region = research["region"]

    volume_details = []
    unencrypted_count = 0
    for volume in volumes:
        if shutdown_event.is_set():
            break
        volume_id = volume["VolumeId"]
        logger.info(f"Processing EBS volume: {volume_id}")
        attachments = volume.get("Attachments", [])
        read_ops = get_cloudwatch_metric(
            cw_client,
            "AWS/EBS",
            "VolumeReadOps",
            [{"Name": "VolumeId", "Value": volume_id}],
            start_time,
            end_time,
            stat="Sum",
            skip_metrics=skip_metrics,
        )
        write_ops = get_cloudwatch_metric(
            cw_client,
            "AWS/EBS",
            "VolumeWriteOps",
            [{"Name": "VolumeId", "Value": volume_id}],
            start_time,
            end_time,
            stat="Sum",
            skip_metrics=skip_metrics,
        )

        detail = {
            "volume_id": volume_id,
            "state": volume["State"],
            "attached": len(attachments) > 0,
            "size_gb": volume["Size"],
            "volume_type": volume["VolumeType"],
            "is_encrypted": volume.get("Encrypted", False),
            "read_ops_avg": read_ops.get("average"),
            "write_ops_avg": write_ops.get("average"),
            "metric_status": "ok"
            if read_ops.get("status") == write_ops.get("status") == "ok"
            else read_ops.get("status", "error"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if not detail["attached"]:
            detail["recommendations"].append(
                {
                    "description": "Volume is unattached and may still incur storage charges. Verify ownership, backups, and retention before deleting it.",
                    "remediation_steps": [
                        f"aws ec2 create-snapshot --volume-id {shell_quote(volume_id)} --description 'Pre-deletion snapshot' --region {shell_quote(region)}",
                        f"aws ec2 delete-volume --volume-id {shell_quote(volume_id)} --region {shell_quote(region)}",
                    ],
                }
            )
        if detail["volume_type"] == "gp2":
            detail["recommendations"].append(
                {
                    "description": "gp2 volume detected. Compare current burst behavior, throughput, IOPS, and GovCloud pricing with an equivalent gp3 configuration.",
                    "remediation_steps": [
                        f"aws ec2 modify-volume --volume-id {shell_quote(volume_id)} --volume-type gp3 --region {shell_quote(region)}"
                    ],
                }
            )
        if (
            read_ops.get("status") == write_ops.get("status") == "ok"
            and (read_ops["average"] + write_ops["average"]) < 10
        ):
            detail["recommendations"].append(
                {
                    "description": "Volume averaged fewer than 10 read-plus-write operations per day. Review workload cycles and attachment state before archiving or downsizing."
                }
            )
        if not detail["is_encrypted"]:
            detail["recommendations"].append(
                {
                    "description": "Volume is unencrypted. Review encryption requirements and plan a snapshot/copy migration if needed.",
                    "remediation_steps": [
                        f"aws ec2 create-snapshot --volume-id {shell_quote(volume_id)} --region {shell_quote(region)}",
                        "aws ec2 copy-snapshot --source-snapshot-id <SNAPSHOT_ID> --encrypted --region "
                        + shell_quote(region),
                    ],
                }
            )
            unencrypted_count += 1
        volume_details.append(detail)

    logger.info("=== Completed EBS Research ===")
    return {
        "volume_count": len(volumes),
        "volumes_analyzed": len(volume_details),
        "unencrypted_volume_count": unencrypted_count,
        "volume_details": volume_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Use AWS Trusted Advisor to identify orphaned volumes. Configure AWS Backup lifecycle policies."
            },
            {"description": f"{unencrypted_count} volumes unencrypted. Enable encryption for security."},
        ],
    }


def research_efs(client, skip_metrics=False):
    logger.info("=== Starting EFS Research ===")
    response = paginated_api_call("EFS", client, "describe_file_systems", "FileSystems")
    if "error" in response:
        return response
    file_systems = response.get("FileSystems", [])
    logger.info(f"Found {len(file_systems)} EFS file systems to analyze")
    region = research["region"]

    fs_details = []
    for fs in file_systems:
        if shutdown_event.is_set():
            break
        fs_id = fs["FileSystemId"]
        logger.info(f"Processing EFS file system: {fs_id}")
        lifecycle = safe_api_call("EFS", client.describe_lifecycle_configuration, FileSystemId=fs_id)
        policies = lifecycle.get("LifecyclePolicies", [])
        has_ia_or_archive_transition = (
            None
            if "error" in lifecycle
            else any(policy.get("TransitionToIA") or policy.get("TransitionToArchive") for policy in policies)
        )
        detail = {
            "file_system_id": fs_id,
            "size_bytes": fs.get("SizeInBytes", {}).get("Value", 0),
            "encrypted": fs.get("Encrypted", False),
            "lifecycle_policy_count": len(policies),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if has_ia_or_archive_transition is False:
            detail["recommendations"].append(
                {
                    "description": "No transition to EFS Infrequent Access or Archive was detected. Review access patterns and lifecycle requirements.",
                    "remediation_steps": [
                        f"aws efs put-lifecycle-configuration --file-system-id {shell_quote(fs_id)} --lifecycle-policies file://lifecycle.json --region {shell_quote(region)}"
                    ],
                }
            )
        elif has_ia_or_archive_transition is None:
            detail["recommendations"].append({"description": "EFS lifecycle configuration could not be verified."})
        fs_details.append(detail)

    logger.info("=== Completed EFS Research ===")
    return {
        "file_system_count": len(file_systems),
        "file_systems_analyzed": len(fs_details),
        "file_system_details": fs_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Monitor EFS usage and optimize storage classes for infrequently accessed data."}
        ],
    }


def research_kinesis(client, skip_metrics=False):
    logger.info("=== Starting Kinesis Research ===")
    response = paginated_api_call("Kinesis", client, "list_streams", "StreamNames")
    if "error" in response:
        return response
    streams = response.get("StreamNames", [])
    logger.info(f"Found {len(streams)} Kinesis streams to analyze")
    stream_details = []
    for stream in streams:
        if shutdown_event.is_set():
            break
        logger.info(f"Processing Kinesis stream: {stream[:30]}...")
        summary_response = safe_api_call("Kinesis", client.describe_stream_summary, StreamName=stream)
        summary = summary_response.get("StreamDescriptionSummary", {}) if isinstance(summary_response, dict) else {}
        detail = {
            "stream_name": stream,
            "status": summary.get("StreamStatus", "N/A"),
            "mode": summary.get("StreamModeDetails", {}).get("StreamMode", "N/A"),
            "open_shard_count": summary.get("OpenShardCount", "N/A"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if detail["mode"] == "PROVISIONED":
            detail["recommendations"].append(
                {
                    "description": "Provisioned stream detected. Compare incoming/outgoing throughput with shard capacity before changing shard count or stream mode."
                }
            )
        stream_details.append(detail)

    logger.info("=== Completed Kinesis Research ===")
    return {
        "stream_count": len(streams),
        "streams_analyzed": len(stream_details),
        "stream_details": stream_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Monitor stream usage and adjust shard counts for cost optimization."}
        ],
    }


def research_ses(client, skip_metrics=False):
    logger.info("=== Starting SES Research ===")
    response = paginated_api_call("SES", client, "list_identities", "Identities")
    if "error" in response:
        return response
    identities = response.get("Identities", [])
    logger.info(f"Found {len(identities)} SES identities to analyze")
    region = research["region"]

    verification = {}
    for index in range(0, len(identities), 100):
        batch = identities[index : index + 100]
        if not batch:
            continue
        status_response = safe_api_call("SES", client.get_identity_verification_attributes, Identities=batch)
        if isinstance(status_response, dict):
            verification.update(status_response.get("VerificationAttributes", {}))

    identity_details = []
    for identity in identities:
        if shutdown_event.is_set():
            break
        logger.info("Processing SES identity")  # Don't log email addresses
        verification_status = verification.get(identity, {}).get("VerificationStatus", "Unknown")
        detail = {
            "identity": identity,
            "verification_status": verification_status,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if verification_status == "Unknown":
            detail["recommendations"].append({"description": "SES identity verification status could not be verified."})
        elif verification_status != "Success":
            detail["recommendations"].append(
                {
                    "description": f"SES identity verification status is {verification_status}. Complete verification or remove the stale identity after confirming it is unused.",
                    "remediation_steps": [
                        f"aws ses delete-identity --identity {shell_quote(identity)} --region {shell_quote(region)}"
                    ],
                }
            )
        identity_details.append(detail)

    logger.info("=== Completed SES Research ===")
    return {
        "identity_count": len(identities),
        "identities_analyzed": len(identity_details),
        "identity_details": identity_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Review SES identities for usage and remove unused ones."}],
    }


def research_waf(client, skip_metrics=False):
    logger.info("=== Starting WAF Research ===")
    response = paginated_api_call("WAF", client, "list_web_acls", "WebACLs", Scope="REGIONAL")
    if "error" in response:
        return response
    acls = response.get("WebACLs", [])
    logger.info(f"Found {len(acls)} WAFv2 Web ACLs to analyze")

    acl_details = []
    for acl in acls:
        if shutdown_event.is_set():
            break
        acl_id = acl["Id"]
        acl_arn = acl.get("ARN", "")
        logger.info(f"Processing WAFv2 Web ACL: {acl_id}")
        logging_response = safe_api_call(
            "WAF",
            client.get_logging_configuration,
            ResourceArn=acl_arn,
            suppress_errors=["WAFNonexistentItemException"],
        )
        logging_enabled = None if "error" in logging_response else "LoggingConfiguration" in logging_response
        detail = {
            "web_acl_id": acl_id,
            "name": acl.get("Name", "N/A"),
            "logging_enabled": logging_enabled,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if logging_enabled is False:
            detail["recommendations"].append(
                {
                    "description": "WAFv2 logging was not detected. Evaluate a compliant log destination and retention policy."
                }
            )
        elif logging_enabled is None:
            detail["recommendations"].append({"description": "WAFv2 logging configuration could not be verified."})
        acl_details.append(detail)

    logger.info("=== Completed WAF Research ===")
    return {
        "web_acl_count": len(acls),
        "web_acls_analyzed": len(acl_details),
        "web_acl_details": acl_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Review WAFv2 sampled requests, rule labels, and logging before tuning managed or custom rules."
            }
        ],
    }


def research_kms(client, skip_metrics=False):
    logger.info("=== Starting KMS Research ===")
    response = paginated_api_call("KMS", client, "list_keys", "Keys")
    if "error" in response:
        return response
    keys = response.get("Keys", [])
    logger.info(f"Found {len(keys)} KMS keys to analyze")
    region = research["region"]

    key_details = []
    for key in keys:
        if shutdown_event.is_set():
            break
        key_id = key["KeyId"]
        logger.info(f"Processing KMS key: {key_id}")
        metadata_response = safe_api_call("KMS", client.describe_key, KeyId=key_id)
        metadata = metadata_response.get("KeyMetadata", {}) if isinstance(metadata_response, dict) else {}
        eligible_for_rotation = (
            metadata.get("KeyManager") == "CUSTOMER"
            and metadata.get("KeyState") == "Enabled"
            and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
            and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
        )
        rotation_enabled = None
        if eligible_for_rotation:
            rotation = safe_api_call("KMS", client.get_key_rotation_status, KeyId=key_id)
            if isinstance(rotation, dict) and "error" not in rotation:
                rotation_enabled = rotation.get("KeyRotationEnabled", False)
        detail = {
            "key_id": key_id,
            "key_manager": metadata.get("KeyManager", "Unknown"),
            "key_state": metadata.get("KeyState", "Unknown"),
            "rotation_enabled": rotation_enabled,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if eligible_for_rotation and rotation_enabled is False:
            detail["recommendations"].append(
                {
                    "description": "Eligible customer-managed symmetric key does not have automatic rotation enabled. Confirm application compatibility and key policy before enabling it.",
                    "remediation_steps": [
                        f"aws kms enable-key-rotation --key-id {shell_quote(key_id)} --region {shell_quote(region)}"
                    ],
                }
            )
        key_details.append(detail)

    logger.info("=== Completed KMS Research ===")
    return {
        "key_count": len(keys),
        "keys_analyzed": len(key_details),
        "key_details": key_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Review KMS key usage and rotate keys regularly."}],
    }


def research_elb(client, elbv2_client, skip_metrics=False):
    logger.info("=== Starting ELB Research ===")
    classic_response = paginated_api_call("ELB", client, "describe_load_balancers", "LoadBalancerDescriptions")
    v2_response = paginated_api_call("ELBv2", elbv2_client, "describe_load_balancers", "LoadBalancers")
    if "error" in classic_response and "error" in v2_response:
        return {"error": f"Classic ELB: {classic_response['error']}; ELBv2: {v2_response['error']}"}
    classic_load_balancers = classic_response.get("LoadBalancerDescriptions", [])
    v2_load_balancers = v2_response.get("LoadBalancers", [])
    load_balancers = classic_load_balancers + v2_load_balancers
    logger.info(f"Found {len(load_balancers)} ELBs to analyze")

    lb_details = []
    for lb in classic_load_balancers:
        if shutdown_event.is_set():
            break
        lb_name = lb["LoadBalancerName"]
        logger.info(f"Processing Classic Load Balancer: {lb_name[:30]}...")
        detail = {
            "load_balancer_name": lb_name,
            "type": "classic",
            "scheme": lb.get("Scheme", "internet-facing"),
            "estimated_savings": 0,
            "recommendations": [
                {
                    "description": "Classic Load Balancer detected. Evaluate ALB, NLB, or GWLB based on protocol and feature requirements before migrating."
                }
            ],
        }
        lb_details.append(detail)

    for lb in v2_load_balancers:
        if shutdown_event.is_set():
            break
        lb_name = lb["LoadBalancerName"]
        lb_arn = lb["LoadBalancerArn"]
        logger.info(f"Processing ELBv2 load balancer: {lb_name[:30]}...")
        attributes_response = safe_api_call(
            "ELBv2",
            elbv2_client.describe_load_balancer_attributes,
            LoadBalancerArn=lb_arn,
        )
        attributes = (
            {item.get("Key"): item.get("Value") for item in attributes_response.get("Attributes", [])}
            if isinstance(attributes_response, dict)
            else {}
        )
        deletion_protection = (
            None if "error" in attributes_response else attributes.get("deletion_protection.enabled") == "true"
        )
        detail = {
            "load_balancer_name": lb_name,
            "type": lb.get("Type", "application"),
            "scheme": lb.get("Scheme", "N/A"),
            "state": lb.get("State", {}).get("Code", "N/A"),
            "deletion_protection": deletion_protection,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if deletion_protection is False:
            detail["recommendations"].append(
                {
                    "description": "Deletion protection is disabled. Consider enabling it for production load balancers after reviewing deployment workflows."
                }
            )
        elif deletion_protection is None:
            detail["recommendations"].append(
                {"description": "Load balancer deletion-protection status could not be verified."}
            )
        lb_details.append(detail)

    logger.info("=== Completed ELB Research ===")
    return {
        "load_balancer_count": len(load_balancers),
        "load_balancers_analyzed": len(lb_details),
        "load_balancer_details": lb_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Use CloudWatch request, connection, and processed-byte metrics to identify idle or oversized load balancers; inventory alone cannot establish utilization."
            }
        ],
    }


def research_guardduty(client, skip_metrics=False):
    logger.info("=== Starting GuardDuty Research ===")
    response = paginated_api_call("GuardDuty", client, "list_detectors", "DetectorIds")
    if "error" in response:
        return response
    detectors = response.get("DetectorIds", [])
    logger.info(f"Found {len(detectors)} GuardDuty detectors to analyze")

    detector_details = []
    for detector in detectors:
        if shutdown_event.is_set():
            break
        logger.info(f"Processing GuardDuty detector: {detector}")
        detector_response = safe_api_call("GuardDuty", client.get_detector, DetectorId=detector)
        detector_status = detector_response.get("Status", "Unknown")
        detail = {"detector_id": detector, "status": detector_status, "estimated_savings": 0, "recommendations": []}
        if detector_status == "Unknown":
            detail["recommendations"].append({"description": "GuardDuty detector status could not be verified."})
        elif detector_status != "ENABLED":
            detail["recommendations"].append(
                {
                    "description": "GuardDuty detector is not enabled. Confirm the delegated-administrator and regional enablement design."
                }
            )
        detector_details.append(detail)

    logger.info("=== Completed GuardDuty Research ===")
    return {
        "detector_count": len(detectors),
        "detectors_analyzed": len(detector_details),
        "detector_details": detector_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Ensure GuardDuty findings are reviewed and integrated with SIEM."}
        ],
    }


def research_iam(client, skip_metrics=False):
    logger.info("=== Starting IAM Research ===")
    response = paginated_api_call("IAM", client, "list_policies", "Policies", Scope="Local")
    if "error" in response:
        return response
    policies = response.get("Policies", [])
    logger.info(f"Found {len(policies)} IAM policies to analyze")
    policy_details = []

    for policy in policies:
        if shutdown_event.is_set():
            break
        policy_name = policy["PolicyName"]
        logger.info(f"Processing IAM policy: {policy_name[:30]}...")
        policy_doc = safe_api_call(
            "IAM", client.get_policy_version, PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )

        detail = {
            "policy_name": policy_name,
            "attachment_count": policy["AttachmentCount"],
            "is_overly_permissive": False,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if isinstance(policy_doc, dict) and "PolicyVersion" in policy_doc:
            version = policy_doc["PolicyVersion"]
            raw_doc = version.get("Document", {})
            if isinstance(raw_doc, str):
                try:
                    raw_doc = json.loads(raw_doc)
                except json.JSONDecodeError:
                    detail["recommendations"].append(
                        {"description": "Policy document is malformed JSON. Verify configuration."}
                    )
                    policy_details.append(detail)
                    sleep(0.1)
                    continue
            elif not isinstance(raw_doc, dict):
                detail["recommendations"].append(
                    {"description": "Policy document has invalid format. Verify configuration."}
                )
                policy_details.append(detail)
                sleep(0.1)
                continue
            stmts = raw_doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if not isinstance(stmt, dict):
                    continue
                actions = stmt.get("Action", [])
                not_actions = stmt.get("NotAction", [])
                resources = stmt.get("Resource", [])
                actions = [actions] if isinstance(actions, str) else (actions if isinstance(actions, list) else [])
                not_actions = (
                    [not_actions]
                    if isinstance(not_actions, str)
                    else (not_actions if isinstance(not_actions, list) else [])
                )
                resources = (
                    [resources] if isinstance(resources, str) else (resources if isinstance(resources, list) else [])
                )
                broad_action = bool(not_actions) or any(
                    action == "*" or action.endswith(":*") for action in actions if isinstance(action, str)
                )
                broad_resource = "*" in resources
                if stmt.get("Effect") == "Allow" and broad_action and broad_resource:
                    detail["is_overly_permissive"] = True
                    detail["recommendations"].append(
                        {
                            "description": "Policy contains an Allow statement with broad actions and Resource '*'. Review conditions and scope it to least privilege where supported."
                        }
                    )
        else:
            detail["recommendations"].append({"description": "Policy document unavailable. Verify configuration."})
        if detail["attachment_count"] == 0:
            detail["recommendations"].append(
                {
                    "description": "Customer-managed policy has no attachments. Confirm it is not referenced by a permissions boundary or automation before deletion."
                }
            )
        policy_details.append(detail)

    logger.info("=== Completed IAM Research ===")
    return {
        "policy_count": len(policies),
        "policies_analyzed": len(policy_details),
        "policy_details": policy_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Use IAM Access Analyzer to consolidate redundant policies."}],
    }


def research_firewall_manager(client, skip_metrics=False):
    logger.info("=== Starting Firewall Manager Research ===")
    response = paginated_api_call("Firewall Manager", client, "list_policies", "PolicyList")
    if "error" in response:
        return {
            "error": "Firewall Manager access failed. Ensure a default admin is set and verify IAM permissions ('fms:ListPolicies').",
            "general_recommendations": [
                {
                    "description": "Set a default admin for Firewall Manager in AWS Console under 'Firewall Manager > Settings'."
                },
                {"description": "If Firewall Manager is not used, this error can be safely ignored."},
            ],
        }
    policies = response.get("PolicyList", [])
    logger.info(f"Found {len(policies)} Firewall Manager policies to analyze")

    policy_details = []
    for policy in policies:
        if shutdown_event.is_set():
            break
        policy_id = policy["PolicyId"]
        logger.info(f"Processing Firewall Manager policy: {policy_id}")
        detail = {
            "policy_id": policy_id,
            "name": policy.get("PolicyName", "N/A"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        detail["recommendations"].append(
            {"description": "Review policy coverage and optimize for resource protection."}
        )
        policy_details.append(detail)

    logger.info("=== Completed Firewall Manager Research ===")
    return {
        "policy_count": len(policies),
        "policies_analyzed": len(policy_details),
        "policy_details": policy_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Review Firewall Manager policies for coverage and optimization."}],
    }


def research_ec2(client, cw_client, skip_metrics=False):
    logger.info("=== Starting EC2 Research ===")
    response = paginated_api_call("EC2", client, "describe_instances", "Reservations")
    if "error" in response:
        return response
    instances = []
    for reservation in response.get("Reservations", []):
        instances.extend(reservation.get("Instances", []))
    logger.info(f"Found {len(instances)} EC2 instances to analyze")
    end_time = datetime.datetime.now(timezone.utc)
    start_time = end_time - datetime.timedelta(days=metric_lookback_days)
    region = research["region"]

    instance_details = []
    unencrypted_count = 0
    # Collect volume IDs to check encryption properly
    all_volume_ids = set()
    for instance in instances:
        for bd in instance.get("BlockDeviceMappings", []):
            vol_id = bd.get("Ebs", {}).get("VolumeId")
            if vol_id:
                all_volume_ids.add(vol_id)

    # Batch-fetch volume encryption status
    volume_encryption = {}
    sorted_volume_ids = sorted(all_volume_ids)
    for index in range(0, len(sorted_volume_ids), 500):
        vol_response = safe_api_call("EC2", client.describe_volumes, VolumeIds=sorted_volume_ids[index : index + 500])
        if isinstance(vol_response, dict) and "Volumes" in vol_response:
            for vol in vol_response["Volumes"]:
                volume_encryption[vol["VolumeId"]] = vol.get("Encrypted", False)

    for instance in instances:
        if shutdown_event.is_set():
            break
        instance_id = instance["InstanceId"]
        logger.info(f"Processing EC2 instance: {instance_id}")
        state = instance.get("State", {}).get("Name", "N/A")
        cpu = (
            get_cloudwatch_metric(
                cw_client,
                "AWS/EC2",
                "CPUUtilization",
                [{"Name": "InstanceId", "Value": instance_id}],
                start_time,
                end_time,
                skip_metrics=skip_metrics,
            )
            if state == "running"
            else {"average": None, "values": [], "status": "not_applicable"}
        )

        # Match the declared root device to its EBS volume. Instance-store roots
        # have no EBS encryption status and are reported as not applicable.
        root_encrypted = None
        root_device_name = instance.get("RootDeviceName")
        for bd in instance.get("BlockDeviceMappings", []):
            if bd.get("DeviceName") != root_device_name:
                continue
            vol_id = bd.get("Ebs", {}).get("VolumeId")
            if vol_id:
                root_encrypted = volume_encryption.get(vol_id)
            break

        detail = {
            "instance_id": instance_id,
            "instance_type": instance.get("InstanceType", "N/A"),
            "state": state,
            "cpu_utilization_avg": cpu.get("average"),
            "metric_status": cpu.get("status", "error"),
            "is_root_encrypted": root_encrypted,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if detail["state"] == "stopped":
            detail["recommendations"].append(
                {
                    "description": "Instance is stopped. Compute usage is not billed while stopped, but attached EBS volumes and other resources may still incur charges. Confirm ownership before termination.",
                    "remediation_steps": [
                        f"aws ec2 terminate-instances --instance-ids {shell_quote(instance_id)} --region {shell_quote(region)}"
                    ],
                }
            )
        if detail["state"] == "running" and metric_is_below(cpu, 20):
            detail["recommendations"].append(
                {
                    "description": "Average CPU utilization was below 20% during the observation window. Review memory, network, disk, burst credits, and peak percentiles before rightsizing."
                }
            )
        if detail["is_root_encrypted"] is False:
            detail["recommendations"].append(
                {
                    "description": "EBS root volume is unencrypted. Review encryption requirements and plan a snapshot/copy or image-based migration."
                }
            )
            unencrypted_count += 1
        instance_details.append(detail)

    logger.info("=== Completed EC2 Research ===")
    return {
        "instance_count": len(instances),
        "instances_analyzed": len(instance_details),
        "unencrypted_instance_count": unencrypted_count,
        "instance_details": instance_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {
                "description": "Use AWS Compute Optimizer and workload-aware peak metrics before rightsizing; average CPU alone is insufficient."
            },
            {
                "description": f"{unencrypted_count} instances have an unencrypted EBS root volume. Review encryption requirements."
            },
        ],
    }


def research_inspector(client, skip_metrics=False):
    logger.info("=== Starting Inspector Research ===")
    response = safe_api_call("Inspector", client.batch_get_account_status, accountIds=[account_id])
    if "error" in response:
        return response
    accounts = response.get("accounts", [])
    account_status = accounts[0] if accounts else {}
    status = account_status.get("state", {}).get("status", "UNKNOWN")
    resource_state = account_status.get("resourceState", {})
    resource_details = []
    for resource_type, state_info in sorted(resource_state.items()):
        resource_details.append(
            {
                "name": resource_type.upper(),
                "status": state_info.get("status", "UNKNOWN"),
                "estimated_savings": 0,
                "recommendations": [],
            }
        )
    recommendations = []
    if status != "ENABLED":
        recommendations.append(
            {
                "description": "Amazon Inspector is not fully enabled for this account and region. Review delegated administration and desired resource coverage."
            }
        )

    logger.info("=== Completed Inspector Research ===")
    return {
        "account_status": status,
        "resource_type_count": len(resource_details),
        "resource_details": resource_details,
        "total_estimated_savings": 0,
        "general_recommendations": recommendations
        or [
            {
                "description": "Amazon Inspector is enabled. Review coverage gaps, suppressions, and unresolved critical/high findings."
            }
        ],
    }


def research_security_hub(client, skip_metrics=False):
    logger.info("=== Starting Security Hub Research ===")
    response = safe_api_call("Security Hub", client.describe_hub)
    if "error" in response:
        # Security Hub not enabled or access denied
        return {
            "hub_status": "Not enabled or inaccessible",
            "total_estimated_savings": 0,
            "general_recommendations": [
                {
                    "description": "Security Hub may not be enabled. Review whether centralized regional security monitoring is required."
                },
                {"description": "Integrate Security Hub with SIEM and review findings regularly."},
            ],
        }

    logger.info("=== Completed Security Hub Research ===")
    return {
        "hub_status": "Enabled",
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Integrate Security Hub with SIEM and review findings regularly."}],
    }


def research_cloudtrail(client, skip_metrics=False):
    logger.info("=== Starting CloudTrail Research ===")
    response = safe_api_call("CloudTrail", client.describe_trails, includeShadowTrails=False)
    if "error" in response:
        return response
    trails = response.get("trailList", [])
    logger.info(f"Found {len(trails)} CloudTrail trails to analyze")
    region = research["region"]

    trail_details = []
    non_logging_count = 0

    for trail in trails:
        if shutdown_event.is_set():
            break
        trail_name = trail["Name"]
        logger.info(f"Processing CloudTrail trail: {trail_name[:30]}...")

        # Fetch actual logging status via get_trail_status
        is_logging = None
        trail_status = safe_api_call("CloudTrail", client.get_trail_status, Name=trail_name)
        if isinstance(trail_status, dict) and "error" not in trail_status:
            is_logging = trail_status.get("IsLogging", False)

        detail = {"trail_name": trail_name, "is_logging": is_logging, "estimated_savings": 0, "recommendations": []}
        if is_logging is False:
            detail["recommendations"].append(
                {
                    "description": "Trail is not logging. Confirm the audit logging design and required destinations before enabling it.",
                    "remediation_steps": [
                        f"aws cloudtrail start-logging --name {shell_quote(trail_name)} --region {shell_quote(region)}"
                    ],
                }
            )
            non_logging_count += 1
        elif is_logging is None:
            detail["recommendations"].append({"description": "Trail logging status could not be verified."})
        trail_details.append(detail)

    logger.info("=== Completed CloudTrail Research ===")
    return {
        "trail_count": len(trails),
        "trails_analyzed": len(trail_details),
        "non_logging_count": non_logging_count,
        "trail_details": trail_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Ensure all trails are logging and integrated with CloudWatch Logs."},
            {"description": f"{non_logging_count} trails not logging. Enable for compliance."},
        ],
    }


def research_cloudwatch(client, skip_metrics=False):
    logger.info("=== Starting CloudWatch Research ===")
    response = paginated_api_call("CloudWatch", client, "describe_alarms", ["MetricAlarms", "CompositeAlarms"])
    if "error" in response:
        return response
    alarms = response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
    logger.info(f"Found {len(alarms)} CloudWatch alarms to analyze")

    alarm_details = []
    for alarm in alarms:
        if shutdown_event.is_set():
            break
        alarm_name = alarm["AlarmName"]
        logger.info(f"Processing CloudWatch alarm: {alarm_name[:30]}...")

        # Use the StateValue from the alarm object directly (not a nonexistent metric)
        state_value = alarm.get("StateValue", "OK")

        detail = {"alarm_name": alarm_name, "state": state_value, "estimated_savings": 0, "recommendations": []}
        if state_value == "ALARM":
            detail["recommendations"].append(
                {"description": "Alarm is in ALARM state. Review thresholds or underlying issues."}
            )
        alarm_details.append(detail)

    logger.info("=== Completed CloudWatch Research ===")
    return {
        "alarm_count": len(alarms),
        "alarms_analyzed": len(alarm_details),
        "alarm_details": alarm_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Review alarms for false positives and ensure notifications are configured."}
        ],
    }


def research_rds(client, cw_client, skip_metrics=False):
    logger.info("=== Starting RDS Research ===")
    response = paginated_api_call("RDS", client, "describe_db_instances", "DBInstances")
    if "error" in response:
        return response
    instances = response.get("DBInstances", [])
    logger.info(f"Found {len(instances)} RDS instances to analyze")
    end_time = datetime.datetime.now(timezone.utc)
    start_time = end_time - datetime.timedelta(days=metric_lookback_days)

    instance_details = []
    unencrypted_count = 0
    for instance in instances:
        if shutdown_event.is_set():
            break
        instance_id = instance["DBInstanceIdentifier"]
        logger.info(f"Processing RDS instance: {instance_id[:30]}...")
        cpu = get_cloudwatch_metric(
            cw_client,
            "AWS/RDS",
            "CPUUtilization",
            [{"Name": "DBInstanceIdentifier", "Value": instance_id}],
            start_time,
            end_time,
            skip_metrics=skip_metrics,
        )
        connections = get_cloudwatch_metric(
            cw_client,
            "AWS/RDS",
            "DatabaseConnections",
            [{"Name": "DBInstanceIdentifier", "Value": instance_id}],
            start_time,
            end_time,
            skip_metrics=skip_metrics,
        )

        detail = {
            "instance_id": instance_id,
            "instance_class": instance["DBInstanceClass"],
            "status": instance.get("DBInstanceStatus", "N/A"),
            "multi_az": instance["MultiAZ"],
            "is_encrypted": instance.get("StorageEncrypted", False),
            "cpu_utilization_avg": cpu.get("average"),
            "connections_avg": connections.get("average"),
            "metric_status": "ok"
            if cpu.get("status") == connections.get("status") == "ok"
            else cpu.get("status", "error"),
            "estimated_savings": 0,
            "recommendations": [],
        }
        if metric_is_below(cpu, 20) and metric_is_below(connections, 5):
            detail["recommendations"].append(
                {
                    "description": "Average CPU was below 20% and average connections below 5 during the observation window. Review memory, I/O, storage, peaks, and workload schedules before rightsizing or retirement."
                }
            )
        if not detail["is_encrypted"]:
            detail["recommendations"].append(
                {
                    "description": "DB instance storage is unencrypted. Review encryption requirements and plan a snapshot-based migration if needed."
                }
            )
            unencrypted_count += 1
        instance_details.append(detail)

    logger.info("=== Completed RDS Research ===")
    return {
        "db_instance_count": len(instances),
        "instances_analyzed": len(instance_details),
        "unencrypted_instance_count": unencrypted_count,
        "instance_details": instance_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Enable automated backups with 7-14 day retention. Monitor read replicas."},
            {"description": f"{unencrypted_count} instances unencrypted. Enable encryption."},
        ],
    }


def research_codecommit(client, skip_metrics=False):
    logger.info("=== Starting CodeCommit Research ===")
    response = paginated_api_call("CodeCommit", client, "list_repositories", "repositories")
    if "error" in response:
        return response
    repositories = response.get("repositories", [])
    logger.info(f"Found {len(repositories)} CodeCommit repositories to analyze")

    repo_details = []
    for repo in repositories:
        if shutdown_event.is_set():
            break
        repo_name = repo["repositoryName"]
        logger.info(f"Processing CodeCommit repository: {repo_name[:30]}...")
        metadata_response = safe_api_call("CodeCommit", client.get_repository, repositoryName=repo_name)
        metadata = metadata_response.get("repositoryMetadata", {}) if isinstance(metadata_response, dict) else {}
        last_modified = metadata.get("lastModifiedDate")
        if isinstance(last_modified, datetime.datetime):
            if last_modified.tzinfo is None:
                last_modified = last_modified.replace(tzinfo=timezone.utc)
            last_modified_text = last_modified.isoformat()
            inactive_days = (datetime.datetime.now(timezone.utc) - last_modified).days
        else:
            last_modified_text = "Unknown"
            inactive_days = None
        detail = {
            "repository_name": repo_name,
            "last_modified": last_modified_text,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if inactive_days is not None and inactive_days > 365:
            detail["recommendations"].append(
                {
                    "description": f"Repository metadata has not changed for {inactive_days} days. Confirm clone/branch activity and retention requirements before archiving."
                }
            )
        repo_details.append(detail)

    logger.info("=== Completed CodeCommit Research ===")
    return {
        "repository_count": len(repositories),
        "repositories_analyzed": len(repo_details),
        "repository_details": repo_details,
        "total_estimated_savings": 0,
        "general_recommendations": [{"description": "Review repositories for activity and archive unused ones."}],
    }


def research_ecr(client, skip_metrics=False):
    logger.info("=== Starting ECR Research ===")
    response = paginated_api_call("ECR", client, "describe_repositories", "repositories")
    if "error" in response:
        return response
    repositories = response.get("repositories", [])
    logger.info(f"Found {len(repositories)} ECR repositories to analyze")

    repo_details = []
    for repo in repositories:
        if shutdown_event.is_set():
            break
        repo_name = repo["repositoryName"]
        logger.info(f"Processing ECR repository: {repo_name[:30]}...")
        lifecycle = safe_api_call(
            "ECR",
            client.get_lifecycle_policy,
            repositoryName=repo_name,
            suppress_errors=["LifecyclePolicyNotFoundException"],
        )
        lifecycle_enabled = None if "error" in lifecycle else "lifecyclePolicyText" in lifecycle
        detail = {
            "repository_name": repo_name,
            "image_tag_mutability": repo.get("imageTagMutability", "N/A"),
            "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
            "lifecycle_policy_enabled": lifecycle_enabled,
            "estimated_savings": 0,
            "recommendations": [],
        }
        if lifecycle_enabled is False:
            detail["recommendations"].append(
                {
                    "description": "No ECR lifecycle policy was detected. Review image retention, deployment rollback, and legal hold requirements before adding one."
                }
            )
        elif lifecycle_enabled is None:
            detail["recommendations"].append({"description": "ECR lifecycle policy status could not be verified."})
        if not detail["scan_on_push"]:
            detail["recommendations"].append(
                {
                    "description": "Basic scan-on-push is disabled. Review the account's enhanced scanning or other vulnerability-scanning coverage before changing it."
                }
            )
        repo_details.append(detail)

    logger.info("=== Completed ECR Research ===")
    return {
        "repository_count": len(repositories),
        "repositories_analyzed": len(repo_details),
        "repository_details": repo_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Review ECR repositories for unused images and enable lifecycle policies."}
        ],
    }


def research_trusted_advisor(client, skip_metrics=False):
    logger.info("=== Starting Trusted Advisor Research ===")
    response = safe_api_call("Trusted Advisor", client.describe_trusted_advisor_checks, language="en")
    if "error" in response:
        return {
            "error": "Trusted Advisor access failed. Verify IAM permissions and ensure Trusted Advisor is enabled.",
            "general_recommendations": [
                {"description": "Enable Trusted Advisor in AWS Console and verify permissions."}
            ],
        }
    checks = response.get("checks", [])
    logger.info(f"Found {len(checks)} Trusted Advisor checks to analyze")

    check_details = []
    for check in checks:
        if shutdown_event.is_set():
            break
        check_id = check["id"]
        logger.info(f"Processing Trusted Advisor check: {check['name'][:30]}...")
        result = safe_api_call("Trusted Advisor", client.describe_trusted_advisor_check_result, checkId=check_id)
        recommendations = []
        if isinstance(result, dict) and "result" in result:
            flagged = result["result"].get("flaggedResources", [])
            if flagged:
                recommendations.append(
                    {
                        "description": f"{len(flagged)} resources were flagged by '{check['name']}'. Review the check metadata and each resource before remediation."
                    }
                )
        detail = {
            "check_name": check["name"],
            "check_id": check_id,
            "status": result.get("result", {}).get("status", "N/A") if isinstance(result, dict) else "N/A",
            "flagged_resources": len(result.get("result", {}).get("flaggedResources", []))
            if isinstance(result, dict)
            else 0,
            "estimated_savings": 0,
            "recommendations": recommendations,
        }
        check_details.append(detail)

    logger.info("=== Completed Trusted Advisor Research ===")
    return {
        "check_count": len(checks),
        "checks_analyzed": len(check_details),
        "check_details": check_details,
        "total_estimated_savings": 0,
        "general_recommendations": [
            {"description": "Review Trusted Advisor findings for cost, security, and performance optimizations."}
        ],
    }


# ============================================================================
# Service Map
# ============================================================================
service_map = {
    "S3": (research_s3, ["s3", "cloudwatch"]),
    "VPC": (research_vpc, ["ec2"]),
    "Direct Connect": (research_direct_connect, ["directconnect"]),
    "Backup": (research_backup, ["backup"]),
    "Lambda": (research_lambda, ["lambda", "cloudwatch"]),
    "OpenSearch": (research_opensearch, ["opensearch"]),
    "CloudFormation": (research_cloudformation, ["cloudformation"]),
    "ECS": (research_ecs, ["ecs"]),
    "AppStream": (research_appstream, ["appstream"]),
    "Directory Service": (research_directory_service, ["ds"]),
    "EBS": (research_ebs, ["ec2", "cloudwatch"]),
    "EFS": (research_efs, ["efs"]),
    "Kinesis": (research_kinesis, ["kinesis"]),
    "SES": (research_ses, ["ses"]),
    "WAF": (research_waf, ["wafv2"]),
    "KMS": (research_kms, ["kms"]),
    "ELB": (research_elb, ["elb", "elbv2"]),
    "GuardDuty": (research_guardduty, ["guardduty"]),
    "IAM": (research_iam, ["iam"]),
    "Firewall Manager": (research_firewall_manager, ["fms"]),
    "EC2": (research_ec2, ["ec2", "cloudwatch"]),
    "Inspector": (research_inspector, ["inspector2"]),
    "Security Hub": (research_security_hub, ["securityhub"]),
    "CloudTrail": (research_cloudtrail, ["cloudtrail"]),
    "CloudWatch": (research_cloudwatch, ["cloudwatch"]),
    "RDS": (research_rds, ["rds", "cloudwatch"]),
    "CodeCommit": (research_codecommit, ["codecommit"]),
    "ECR": (research_ecr, ["ecr"]),
    "Trusted Advisor": (research_trusted_advisor, ["support"]),
}


def research_service(service_name, research_func, client_names, skip_metrics=False):
    if shutdown_event.is_set():
        return
    try:
        with client_creation_lock:
            clients = [create_aws_client(client_name) for client_name in client_names]
        result = research_func(*clients, skip_metrics=skip_metrics)
        with research_lock:
            research["services"][service_name] = result
        if isinstance(result, dict) and "error" in result:
            logger.error(f"Failed to research {service_name}")
        else:
            logger.info(f"Researched {service_name} successfully")
    except Exception as e:
        safe_msg = sanitize_error_message(e)
        logger.error(f"Failed to research {service_name}: {safe_msg}")
        with research_lock:
            research["services"][service_name] = {"error": safe_msg}


# ============================================================================
# PDF Report Generation
# ============================================================================


class HorizontalRule(Flowable):
    def __init__(self, width="100%", thickness=0.5, color=None, hAlign="CENTER"):
        Flowable.__init__(self)
        self.width_percent = None
        if isinstance(width, str) and width.endswith("%"):
            self.width_percent = float(width[:-1]) / 100.0
            self.abs_width = None
        else:
            self.abs_width = width
        self.thickness = thickness
        self.color = color or colors.HexColor("#CCCCCC")
        self._height = self.thickness
        self.hAlign = hAlign

    def wrap(self, availWidth, availHeight):
        self.frame_width = availWidth
        return (availWidth, self._height)

    def draw(self):
        self.canv.saveState()
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        if self.abs_width is not None:
            draw_width = self.abs_width
        elif self.width_percent is not None:
            draw_width = self.frame_width * self.width_percent
        else:
            draw_width = self.frame_width
        if self.hAlign == "CENTER":
            x_offset = (self.frame_width - draw_width) / 2.0
        elif self.hAlign == "RIGHT":
            x_offset = self.frame_width - draw_width
        else:
            x_offset = 0
        y_pos = self._height / 2.0
        self.canv.line(x_offset, y_pos, x_offset + draw_width, y_pos)
        self.canv.restoreState()


def load_local_image(local_filename=None):
    """Validate an explicitly supplied report logo path."""
    if not local_filename:
        return None
    image_path = Path(local_filename).expanduser().resolve()
    if image_path.suffix.lower() not in {".jpg", ".jpeg", ".png"}:
        logger.warning("Report logo must be a PNG or JPEG file")
        return None
    if not image_path.is_file():
        logger.warning(f"Report logo not found: {image_path}")
        return None
    return str(image_path)


def _draw_page_header(canvas, doc, include_page_number):
    canvas.saveState()
    page_width, page_height = doc.pagesize
    banner = str(getattr(doc, "report_banner", "")).strip()
    if banner:
        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(colors.HexColor("#8A3B12"))
        canvas.drawCentredString(page_width / 2.0, page_height - 0.5 * inch, banner[:100])
    if include_page_number:
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.black)
        canvas.drawCentredString(page_width / 2.0, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


def first_page_header(canvas, doc):
    _draw_page_header(canvas, doc, include_page_number=False)


def later_pages_header_footer(canvas, doc):
    _draw_page_header(canvas, doc, include_page_number=True)


def create_pdf_styles():
    styles = getSampleStyleSheet()
    styles["Normal"].allowWidows = 0
    styles["Normal"].allowOrphans = 0
    styles["Normal"].leading = 12
    styles["BodyText"].allowWidows = 0
    styles["BodyText"].allowOrphans = 0
    styles["BodyText"].leading = 12
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["h1"],
            fontSize=24,
            alignment=TA_CENTER,
            spaceBefore=0.2 * inch,
            spaceAfter=0.1 * inch,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubTitle",
            parent=styles["h2"],
            fontName="Helvetica",
            fontSize=16,
            alignment=TA_CENTER,
            spaceAfter=0.2 * inch,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ExecTitle",
            parent=styles["h1"],
            fontSize=20,
            alignment=TA_LEFT,
            spaceBefore=0.3 * inch,
            spaceAfter=0.05 * inch,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ServiceTitle",
            parent=styles["h2"],
            fontSize=18,
            alignment=TA_LEFT,
            spaceBefore=0.3 * inch,
            spaceAfter=0.05 * inch,
            keepWithNext=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ItemTitle",
            parent=styles["h3"],
            fontSize=14,
            alignment=TA_LEFT,
            spaceBefore=0.2 * inch,
            spaceAfter=0.1 * inch,
            keepWithNext=1,
        )
    )
    styles["Normal"].fontName = "Helvetica"
    styles["BodyText"].fontName = "Helvetica"
    styles.add(ParagraphStyle(name="NormalRight", parent=styles["Normal"], alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="SmallNormal", parent=styles["Normal"], fontSize=9, leading=11))
    styles.add(
        ParagraphStyle(
            name="BulletPoint",
            parent=styles["Normal"],
            leftIndent=0.25 * inch,
            bulletIndent=0.1 * inch,
            spaceBefore=3,
            spaceAfter=3,
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(name="Recommendation", parent=styles["BulletPoint"], textColor=colors.HexColor("#D9534F"))
    )
    styles.add(
        ParagraphStyle(name="ErrorText", parent=styles["Normal"], fontName="Helvetica-Bold", textColor=colors.red)
    )
    styles["ErrorText"].allowWidows = 0
    styles["ErrorText"].allowOrphans = 0
    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=10,
            alignment=TA_CENTER,
            textColor=colors.whitesmoke,
            backColor=colors.HexColor("#003366"),
        )
    )
    styles.add(ParagraphStyle(name="TableCell", parent=styles["SmallNormal"]))
    styles["TableCell"].allowWidows = 0
    styles["TableCell"].allowOrphans = 0
    styles.add(ParagraphStyle(name="TableCellRight", parent=styles["TableCell"], alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="TableCellCenter", parent=styles["TableCell"], alignment=TA_CENTER))
    styles.add(
        ParagraphStyle(
            name="RecommendationCell", parent=styles["TableCell"], textColor=colors.HexColor("#D9534F"), spaceAfter=2
        )
    )
    styles.add(ParagraphStyle(name="ExecThemeTitle", parent=styles["SmallNormal"], fontName="Helvetica-Bold"))
    return styles


def _safe_para(text, style):
    """Create a Paragraph with XML-safe text."""
    return Paragraph(sanitize_for_paragraph(text), style)


def _labeled_para(label, value, style):
    """Create a paragraph with a safe bold label and safe plain value."""
    return Paragraph(
        f"<b>{sanitize_for_paragraph(label)}:</b> {sanitize_for_paragraph(value)}",
        style,
    )


def _format_metric(value, decimals=2, suffix=""):
    if value is None:
        return "Not collected"
    try:
        return f"{float(value):.{decimals}f}{suffix}"
    except (TypeError, ValueError):
        return str(value)


def _get_rec_description(rec):
    """Extract description from a recommendation (dict or string)."""
    if isinstance(rec, dict):
        return rec.get("description", "")
    return str(rec)


def build_title_page(story, data, styles):
    report_timestamp_str = data.get("timestamp", "N/A")
    try:
        ts = report_timestamp_str
        if isinstance(ts, str) and ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        report_datetime = datetime.datetime.fromisoformat(ts)
        formatted_timestamp = report_datetime.strftime("%Y-%m-%d %H:%M:%S %Z")
        if not report_datetime.tzinfo:
            formatted_timestamp += " (UTC implied)"
    except (ValueError, TypeError, AttributeError):
        formatted_timestamp = str(report_timestamp_str)

    img_path = load_local_image(data.get("logo_path"))

    story.append(Spacer(1, 0.75 * inch))
    if img_path:
        logo_image = Image(img_path, width=2 * inch, height=2 * inch, kind="bound", hAlign="CENTER")
        story.append(logo_image)
        story.append(Spacer(1, 0.4 * inch))
    else:
        story.append(Spacer(1, 0.75 * inch))

    story.append(Paragraph("GovHawk AWS GovCloud Analysis Report", styles["ReportTitle"]))
    story.append(Spacer(1, 0.05 * inch))
    story.append(HorizontalRule(width="70%", thickness=1, color=colors.HexColor("#444444")))
    story.append(Spacer(1, 0.2 * inch))

    generated_at = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Report Generated: {sanitize_for_paragraph(generated_at)}", styles["SubTitle"]))
    story.append(Paragraph(f"Source Data Timestamp: {sanitize_for_paragraph(formatted_timestamp)}", styles["SubTitle"]))
    story.append(Paragraph(f"AWS Region: {sanitize_for_paragraph(data.get('region', 'N/A'))}", styles["SubTitle"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "Automated findings are review signals, not a compliance determination or guaranteed savings forecast. "
            "The report banner is user-selected and does not itself classify the data.",
            styles["SmallNormal"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.append(PageBreak())


def generate_executive_summary(story, data, styles):
    story.append(Paragraph("Executive Summary", styles["ExecTitle"]))
    story.append(HorizontalRule(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1, 0.15 * inch))

    services_data = data.get("services", {})
    total_services_analyzed = 0
    services_with_errors = []
    cost_recs = 0
    security_recs = 0
    operational_recs = 0
    cost_examples = []
    security_examples = []
    operational_examples = []
    resource_counts = {"S3 Buckets": 0, "EC2 Instances": 0, "RDS Instances": 0, "Lambda Functions": 0, "EBS Volumes": 0}

    for svc_name, svc_info in services_data.items():
        if not isinstance(svc_info, dict):
            services_with_errors.append(f"{svc_name} (unexpected format)")
            continue
        if "error" in svc_info:
            services_with_errors.append(svc_name)
            continue
        total_services_analyzed += 1
        if svc_name == "S3":
            resource_counts["S3 Buckets"] = svc_info.get("bucket_count", 0)
        elif svc_name == "EC2":
            resource_counts["EC2 Instances"] = svc_info.get("instance_count", 0)
        elif svc_name == "RDS":
            resource_counts["RDS Instances"] = svc_info.get("db_instance_count", 0)
        elif svc_name == "Lambda":
            resource_counts["Lambda Functions"] = svc_info.get("function_count", 0)
        elif svc_name == "EBS":
            resource_counts["EBS Volumes"] = svc_info.get("volume_count", 0)

        # Count recommendations by theme
        all_recs = []
        for key in svc_info:
            if key.endswith("_details") and isinstance(svc_info[key], list):
                for item in svc_info[key]:
                    if isinstance(item, dict):
                        all_recs.extend(item.get("recommendations", []))
        all_recs.extend(svc_info.get("general_recommendations", []))

        for rec in all_recs:
            description = _get_rec_description(rec).strip()
            desc = description.lower()
            if any(
                t in desc
                for t in [
                    "cost",
                    "saving",
                    "delete",
                    "consolidat",
                    "downsize",
                    "archive",
                    "migrate to gp3",
                    "review unattached",
                    "unattached",
                    "rightsiz",
                    "older objects to glacier",
                    "lifecycle polic",
                    "storage class",
                ]
            ):
                cost_recs += 1
                if description and description not in cost_examples:
                    cost_examples.append(description)
            if any(
                t in desc
                for t in [
                    "security",
                    "iam",
                    "permission",
                    "waf",
                    "guardduty",
                    "kms",
                    "compliance",
                    "audit",
                    "logging",
                    "encryption",
                    "vulnerability",
                ]
            ):
                security_recs += 1
                if description and description not in security_examples:
                    security_examples.append(description)
            if any(t in desc for t in ["optimize", "lifecycle", "monitor", "performance", "drift", "memory setting"]):
                operational_recs += 1
                if description and description not in operational_examples:
                    operational_examples.append(description)

    report_timestamp_str = data.get("timestamp", "N/A")
    try:
        ts = report_timestamp_str
        if isinstance(ts, str) and ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        rd = datetime.datetime.fromisoformat(ts)
        fmt_ts = rd.strftime("%Y-%m-%d %H:%M:%S %Z")
        if not rd.tzinfo:
            fmt_ts += " (UTC implied)"
    except (ValueError, TypeError, AttributeError):
        fmt_ts = str(data.get("timestamp", "N/A"))

    story.append(
        Paragraph(
            f"This report summarizes an automated analysis of the AWS GovCloud environment for region "
            f"<b>{sanitize_for_paragraph(data.get('region', 'N/A'))}</b>, based on data collected around "
            f"<b>{sanitize_for_paragraph(fmt_ts)}</b>. The analysis reviewed <b>{len(services_data)}</b> "
            f"configured AWS services, with <b>{total_services_analyzed}</b> successfully providing detailed "
            f"data and <b>{len(services_with_errors)}</b> encountering issues during data retrieval or processing.",
            styles["Normal"],
        )
    )

    if services_with_errors:
        story.append(Spacer(1, 0.05 * inch))
        story.append(
            Paragraph(
                f"Services with analysis errors or unexpected data format: <b>{sanitize_for_paragraph(', '.join(services_with_errors))}</b>. "
                f"Details, if available, are provided in their respective sections.",
                styles["Normal"],
            )
        )

    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("<b>Key Resource Counts (from successfully analyzed services):</b>", styles["ItemTitle"]))
    rc_items = [_safe_para(f"- {k}: {v}", styles["SmallNormal"]) for k, v in resource_counts.items() if v and v > 0]
    if rc_items:
        story.extend(rc_items)
    else:
        story.append(Paragraph("No significant resource counts to display.", styles["SmallNormal"]))

    story.append(Spacer(1, 0.1 * inch))
    story.append(
        Paragraph("<b>Primary Recommendation Themes (aggregated across all findings):</b>", styles["ItemTitle"])
    )

    themes = []
    if cost_recs > 0:
        examples = "; ".join(example[:160] for example in cost_examples[:2])
        themes.append(
            Paragraph(
                f"- <font name='Helvetica-Bold'>Cost Optimization ({cost_recs} recommendations):</font> "
                f"Examples from this run: {sanitize_for_paragraph(examples)}",
                styles["SmallNormal"],
            )
        )
    if security_recs > 0:
        examples = "; ".join(example[:160] for example in security_examples[:2])
        themes.append(
            Paragraph(
                f"- <font name='Helvetica-Bold'>Security &amp; Governance ({security_recs} recommendations):</font> "
                f"Examples from this run: {sanitize_for_paragraph(examples)}",
                styles["SmallNormal"],
            )
        )
    if operational_recs > 0:
        examples = "; ".join(example[:160] for example in operational_examples[:2])
        themes.append(
            Paragraph(
                f"- <font name='Helvetica-Bold'>Operational Excellence ({operational_recs} recommendations):</font> "
                f"Examples from this run: {sanitize_for_paragraph(examples)}",
                styles["SmallNormal"],
            )
        )
    if themes:
        story.extend(themes)
    else:
        story.append(Paragraph("No major recommendation themes were automatically aggregated.", styles["SmallNormal"]))

    story.append(Spacer(1, 0.1 * inch))
    story.append(
        Paragraph(
            "This executive summary provides a high-level overview. Detailed findings and specific recommendations "
            "for each analyzed service are presented in the subsequent sections. AWS GovCloud billing data is held "
            "in the associated standard AWS account, so this report does not query Cost Explorer or calculate dollar savings.",
            styles["Normal"],
        )
    )
    story.append(PageBreak())


def format_details_table(service_name, details_list, styles):
    if not details_list or not isinstance(details_list, list):
        return None
    headers_map = {
        "S3": ["Bucket Name", "Avg. Objects", "Policy", "Public", "SSE", "Recommendations"],
        "EC2": ["Instance ID", "Type", "State", "Avg. CPU", "Root enc.", "Recommendations"],
        "EBS": ["Volume ID", "Size (GB)", "Type", "In Use", "Avg. Daily I/O", "Recommendations"],
        "Lambda": ["Function Name", "Memory (MB)", "Avg. Invocations", "Recommendations"],
        "RDS": ["DB Instance ID", "Class", "Multi AZ", "Avg. CPU", "Avg. Conns", "Recommendations"],
        "CloudFormation": ["Stack Name", "Count", "Drift Status", "Recommendations"],
    }
    default_headers = ["Identifier", "Key Details", "Recommendations"]
    headers = headers_map.get(service_name, default_headers)
    data_table = [[Paragraph(h, styles["TableHeader"]) for h in headers]]
    col_widths_map = {
        "S3": [1.3 * inch, 0.65 * inch, 0.55 * inch, 0.65 * inch, 0.65 * inch, 3.2 * inch],
        "EC2": [1.1 * inch, 0.85 * inch, 0.6 * inch, 0.65 * inch, 0.75 * inch, 3.05 * inch],
        "EBS": [1.2 * inch, 0.55 * inch, 0.55 * inch, 0.55 * inch, 0.8 * inch, 3.35 * inch],
        "Lambda": [1.8 * inch, 0.9 * inch, 0.9 * inch, 2.9 * inch],
        "RDS": [1.15 * inch, 0.9 * inch, 0.65 * inch, 0.7 * inch, 0.75 * inch, 2.85 * inch],
        "CloudFormation": [1.8 * inch, 0.7 * inch, 0.9 * inch, 3.1 * inch],
    }
    total_width = letter[0] - 1.5 * inch
    default_col_width = total_width / len(headers) if headers else total_width
    col_widths = col_widths_map.get(service_name, [default_col_width] * len(headers))

    for item in details_list:
        if not isinstance(item, dict):
            continue

        # Build recommendations flowable
        recs_list = item.get("recommendations", [])
        recs_flowable_items = []
        for rec in recs_list:
            rec_text = _get_rec_description(rec)
            recs_flowable_items.append(Paragraph(f"- {sanitize_for_paragraph(rec_text)}", styles["RecommendationCell"]))
        recs_flowable = recs_flowable_items if recs_flowable_items else Paragraph("None", styles["TableCellCenter"])

        row = []
        if service_name == "S3":
            lifecycle_enabled = item.get("lifecycle_enabled")
            lifecycle_text = "Unknown" if lifecycle_enabled is None else ("Yes" if lifecycle_enabled else "No")
            is_public = item.get("is_public")
            public_text = "Unknown" if is_public is None else ("Yes" if is_public else "No")
            row = [
                _safe_para(item.get("bucket_name", "N/A"), styles["TableCell"]),
                _safe_para(_format_metric(item.get("object_count_avg"), decimals=0), styles["TableCellCenter"]),
                _safe_para(lifecycle_text, styles["TableCellCenter"]),
                _safe_para(public_text, styles["TableCellCenter"]),
                _safe_para(item.get("encryption_algorithm", "Unknown"), styles["TableCellCenter"]),
                recs_flowable,
            ]
        elif service_name == "EC2":
            root_encrypted = item.get("is_root_encrypted")
            root_encrypted_text = "N/A" if root_encrypted is None else ("Yes" if root_encrypted else "No")
            row = [
                _safe_para(item.get("instance_id", "N/A"), styles["TableCell"]),
                _safe_para(item.get("instance_type", "N/A"), styles["TableCellCenter"]),
                _safe_para(item.get("state", "N/A"), styles["TableCellCenter"]),
                _safe_para(_format_metric(item.get("cpu_utilization_avg"), suffix="%"), styles["TableCellCenter"]),
                _safe_para(root_encrypted_text, styles["TableCellCenter"]),
                recs_flowable,
            ]
        elif service_name == "EBS":
            read_ops = item.get("read_ops_avg")
            write_ops = item.get("write_ops_avg")
            average_io = read_ops + write_ops if read_ops is not None and write_ops is not None else None
            row = [
                _safe_para(item.get("volume_id", "N/A"), styles["TableCell"]),
                _safe_para(str(item.get("size_gb", "N/A")), styles["TableCellCenter"]),
                _safe_para(item.get("volume_type", "N/A"), styles["TableCellCenter"]),
                _safe_para("Yes" if item.get("attached") else "No", styles["TableCellCenter"]),
                _safe_para(_format_metric(average_io), styles["TableCellCenter"]),
                recs_flowable,
            ]
        elif service_name == "Lambda":
            row = [
                _safe_para(item.get("function_name", "N/A"), styles["TableCell"]),
                _safe_para(str(item.get("memory_size", "N/A")), styles["TableCellCenter"]),
                _safe_para(_format_metric(item.get("invocations_avg"), decimals=0), styles["TableCellCenter"]),
                recs_flowable,
            ]
        elif service_name == "RDS":
            row = [
                _safe_para(item.get("instance_id", "N/A"), styles["TableCell"]),
                _safe_para(item.get("instance_class", "N/A"), styles["TableCellCenter"]),
                _safe_para("Yes" if item.get("multi_az") else "No", styles["TableCellCenter"]),
                _safe_para(_format_metric(item.get("cpu_utilization_avg"), suffix="%"), styles["TableCellCenter"]),
                _safe_para(_format_metric(item.get("connections_avg"), decimals=0), styles["TableCellCenter"]),
                recs_flowable,
            ]
        elif service_name == "CloudFormation":
            row = [
                _safe_para(item.get("stack_name", "N/A"), styles["TableCell"]),
                _safe_para(str(item.get("resource_count", "N/A")), styles["TableCellCenter"]),
                _safe_para(str(item.get("drift_status", "N/A")).replace("_", " "), styles["TableCellCenter"]),
                recs_flowable,
            ]
        else:
            # Generic fallback for other services
            name_key = next(
                (
                    k
                    for k in [
                        "name",
                        "Name",
                        "id",
                        "Id",
                        "bucket_name",
                        "instance_id",
                        "volume_id",
                        "function_name",
                        "stack_name",
                        "domain_name",
                        "distribution_id",
                        "cluster_name",
                        "fleet_name",
                        "directory_id",
                        "file_system_id",
                        "stream_name",
                        "identity",
                        "web_acl_id",
                        "key_id",
                        "load_balancer_name",
                        "detector_id",
                        "policy_name",
                        "template_arn",
                        "trail_name",
                        "alarm_name",
                        "repository_name",
                        "check_name",
                    ]
                    if k in item
                ),
                None,
            )
            if not name_key:
                name_key = next(
                    (k for k, v in item.items() if isinstance(v, str) and k != "recommendations"), "identifier"
                )
            identifier_text = str(item.get(name_key, "N/A"))[:70]
            identifier = _safe_para(identifier_text, styles["TableCell"])
            details_parts = []
            for k, v in item.items():
                if k not in [name_key, "recommendations", "estimated_savings", "remediation_steps"] and not isinstance(
                    v, (list, dict)
                ):
                    details_parts.append(
                        f"<b>{sanitize_for_paragraph(k.replace('_', ' ').title())}:</b> {sanitize_for_paragraph(str(v)[:50])}"
                    )
            key_details = Paragraph("<br/>".join(details_parts) if details_parts else "N/A", styles["TableCell"])
            row = [identifier, key_details, recs_flowable]
            while len(row) < len(headers):
                row.insert(1, Paragraph("N/A", styles["TableCellCenter"]))
            row = row[: len(headers)]

        if row:
            data_table.append(row)

    if len(data_table) > 1:
        table = Table(data_table, repeatRows=1, colWidths=col_widths if len(col_widths) == len(headers) else None)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), styles["TableHeader"].fontName),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F0F8FF")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#AAAAAA")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ]
            )
        )
        return table
    return None


def generate_service_details(story, data, styles):
    services_data = data.get("services", {})
    sorted_service_names = sorted(services_data.keys())

    # Keys that are already rendered elsewhere
    skip_keys = {"general_recommendations", "error", "total_estimated_savings"}

    for service_name in sorted_service_names:
        service_info = services_data[service_name]
        has_details = isinstance(service_info, dict) and any(
            (key.endswith("_details") or key.endswith("_detail")) and bool(value) for key, value in service_info.items()
        )
        story.append(CondPageBreak((3.0 if has_details else 1.5) * inch))
        story.append(_safe_para(f"Service: {service_name}", styles["ServiceTitle"]))
        story.append(HorizontalRule(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 0.15 * inch))

        if not isinstance(service_info, dict):
            story.append(Paragraph("Unexpected data format.", styles["ErrorText"]))
            continue

        if "error" in service_info:
            story.append(Paragraph("<u>Error During Analysis:</u>", styles["ItemTitle"]))
            story.append(_safe_para(str(service_info["error"]), styles["ErrorText"]))
            gen_recs = service_info.get("general_recommendations", [])
            if gen_recs:
                story.append(Spacer(1, 0.05 * inch))
                story.append(Paragraph("<b>Troubleshooting:</b>", styles["ItemTitle"]))
                story.extend(_safe_para(f"- {_get_rec_description(r)}", styles["SmallNormal"]) for r in gen_recs)
            story.append(Spacer(1, 0.2 * inch))
            continue

        # Overview: counts and status fields
        overview_paras = []
        for k, v in service_info.items():
            if any(tk in k for tk in ["_count", "_analyzed", "_status"]) and isinstance(v, (int, float, str, bool)):
                overview_paras.append(_labeled_para(k.replace("_", " ").title(), v, styles["SmallNormal"]))
        if overview_paras:
            story.append(Paragraph("<u>Overview:</u>", styles["ItemTitle"]))
            story.extend(overview_paras)
            story.append(Spacer(1, 0.1 * inch))

        # Detail tables
        detail_keys = [k for k in service_info if k.endswith("_details") or k.endswith("_detail")]
        for detail_key in detail_keys:
            details = service_info.get(detail_key)
            if not details:
                continue
            story.append(CondPageBreak(1.5 * inch))
            story.append(
                Paragraph(
                    f"<u>{sanitize_for_paragraph(detail_key.replace('_', ' ').title())}:</u>", styles["ItemTitle"]
                )
            )
            story.append(Spacer(1, 0.05 * inch))
            if isinstance(details, list):
                table = format_details_table(service_name, details, styles)
                story.append(table if table else Paragraph("No details.", styles["SmallNormal"]))
            elif isinstance(details, dict):
                for k_item, v_item in details.items():
                    if k_item == "recommendations" and isinstance(v_item, list) and v_item:
                        story.append(Paragraph("<b>Recommendations:</b>", styles["SmallNormal"]))
                        story.extend(
                            _safe_para(f"- {_get_rec_description(r)}", styles["Recommendation"]) for r in v_item
                        )
                    elif not isinstance(v_item, (list, dict)):
                        story.append(_labeled_para(k_item.replace("_", " ").title(), v_item, styles["SmallNormal"]))
            story.append(Spacer(1, 0.1 * inch))

        # General recommendations
        gen_recs = service_info.get("general_recommendations", [])
        if gen_recs:
            story.append(Paragraph("<u>General Recommendations:</u>", styles["ItemTitle"]))
            story.append(Spacer(1, 0.05 * inch))
            story.extend(_safe_para(f"- {_get_rec_description(r)}", styles["SmallNormal"]) for r in gen_recs)
            story.append(Spacer(1, 0.1 * inch))

        # Additional information (misc keys not already processed)
        other_paras = []
        for key, value in service_info.items():
            if key in skip_keys:
                continue
            if key in detail_keys:
                continue
            if any(tk in key for tk in ["_count", "_analyzed", "_status", "Rate"]):
                continue
            if isinstance(value, dict) and value:
                other_paras.append(_labeled_para(key.replace("_", " ").title(), "", styles["SmallNormal"]))
                other_paras.extend(
                    _safe_para(f"- {k_sub.replace('_', ' ').title()}: {str(v_sub)[:200]}", styles["SmallNormal"])
                    for k_sub, v_sub in value.items()
                )
            elif isinstance(value, list) and value:
                other_paras.append(_labeled_para(key.replace("_", " ").title(), "", styles["SmallNormal"]))
                other_paras.extend(_safe_para(f"- {str(i)[:200]}", styles["SmallNormal"]) for i in value)
            elif isinstance(value, (str, int, float, bool)):
                other_paras.append(
                    _labeled_para(key.replace("_", " ").title(), str(value)[:200], styles["SmallNormal"])
                )
        if other_paras:
            story.append(Paragraph("<u>Additional Information:</u>", styles["ItemTitle"]))
            story.append(Spacer(1, 0.05 * inch))
            story.extend(other_paras)
            story.append(Spacer(1, 0.1 * inch))

        story.append(Spacer(1, 0.1 * inch))


def generate_pdf_report(report_data, output_pdf_path):
    styles = create_pdf_styles()
    output_path = Path(output_pdf_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    doc = SimpleDocTemplate(
        str(temporary_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=1.0 * inch,
        bottomMargin=1.0 * inch,
    )
    doc.report_banner = str(report_data.get("banner", DEFAULT_BANNER))
    story: list[Any] = []
    build_title_page(story, report_data, styles)
    generate_executive_summary(story, report_data, styles)
    generate_service_details(story, report_data, styles)
    try:
        doc.build(story, onFirstPage=first_page_header, onLaterPages=later_pages_header_footer)
        os.replace(temporary_path, output_path)
        logger.info(f"PDF report generated successfully: {output_path}")
        return str(output_path)
    except Exception as e:
        logger.error(f"Error building PDF: {sanitize_error_message(e)}")
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def write_json_report(report_data, output_json_path):
    """Write the report data atomically as UTF-8 JSON."""
    output_path = Path(output_json_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as report_file:
            json.dump(report_data, report_file, indent=2, sort_keys=True, ensure_ascii=False)
            report_file.write("\n")
        os.replace(temporary_path, output_path)
        logger.info(f"JSON report generated successfully: {output_path}")
        return str(output_path)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def harden_output_permissions(output_path):
    """Apply owner-only mode bits where the operating system honors them."""
    try:
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
        if os.name == "nt":
            logger.warning(
                "Windows chmod does not enforce an owner-only ACL; protect the output directory with NTFS permissions."
            )
        return True
    except OSError as e:
        logger.warning(f"Could not set restrictive mode bits on report output: {type(e).__name__}")
        return False


# ============================================================================
# CLI and Main
# ============================================================================


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Inventory and review an AWS GovCloud (US) environment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"GovHawk {VERSION}")
    parser.add_argument("--list-services", action="store_true", help="List supported services and exit")
    parser.add_argument(
        "--services", nargs="*", help="Services to analyze; names are case-insensitive and may be comma-separated"
    )
    parser.add_argument("--region", default=DEFAULT_REGION, help="AWS GovCloud region")
    parser.add_argument("--profile", help="AWS shared-configuration profile to use")
    parser.add_argument(
        "--skip-metrics",
        action="store_true",
        help="Skip CloudWatch utilization metrics without creating low-usage findings",
    )
    parser.add_argument(
        "--lookback-days", type=int, default=14, help="CloudWatch metric observation window (1-90 days)"
    )
    parser.add_argument("--workers", type=int, default=5, help="Parallel service workers (1-16)")
    parser.add_argument("--output-dir", help="Report directory; defaults to an output folder next to this script")
    parser.add_argument("--output-format", choices=["pdf", "json", "both"], default="pdf", help="Report format")
    parser.add_argument("--banner", default=DEFAULT_BANNER, help="Header banner; pass an empty string for no banner")
    parser.add_argument("--logo", help="Optional PNG or JPEG logo for the report title page")
    parser.add_argument(
        "--log-to-cloudwatch",
        action="store_true",
        help="Create/use a log group and stream and send run logs to CloudWatch",
    )
    parser.add_argument(
        "--cloudwatch-log-group", default="GovHawkLogs", help="CloudWatch Logs group used with --log-to-cloudwatch"
    )
    parser.add_argument("--debug", action="store_true", help="Enable verbose local diagnostics")
    return parser.parse_args(argv)


def _service_key(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def resolve_services(requested):
    """Resolve case-insensitive, comma-separated, and unquoted multiword names."""
    if not requested:
        return list(service_map.keys())

    tokens: list[str] = []
    for value in requested:
        tokens.extend(part for part in value.split(",") if part)

    aliases = {_service_key(name): name for name in service_map}
    resolved = []
    unknown = []
    index = 0
    while index < len(tokens):
        match = None
        consumed = 0
        for width in range(min(3, len(tokens) - index), 0, -1):
            candidate = " ".join(tokens[index : index + width]).strip()
            canonical = aliases.get(_service_key(candidate))
            if canonical:
                match = canonical
                consumed = width
                break
        if match:
            if match not in resolved:
                resolved.append(match)
            index += consumed
        else:
            unknown.append(tokens[index])
            index += 1

    if unknown:
        raise ValueError(f"Unsupported service name(s): {', '.join(unknown)}")
    return resolved


def main(argv=None):
    global account_id, metric_lookback_days

    args = parse_args(argv)
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    if args.list_services:
        print("\n".join(service_map))
        return 0

    try:
        validate_region(args.region)
        if not 1 <= args.lookback_days <= 90:
            raise ValueError("--lookback-days must be between 1 and 90")
        if not 1 <= args.workers <= 16:
            raise ValueError("--workers must be between 1 and 16")
        if len(args.banner) > 100:
            raise ValueError("--banner must be 100 characters or fewer")
        target_services = resolve_services(args.services)
    except ValueError as e:
        logger.error(str(e))
        return 2

    shutdown_event.clear()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)

    metric_lookback_days = args.lookback_days
    research.clear()
    research.update(
        {
            "tool_version": VERSION,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "region": args.region,
            "metric_lookback_days": metric_lookback_days,
            "metrics_collected": not args.skip_metrics,
            "banner": args.banner,
            "services": {},
        }
    )

    try:
        boto3.setup_default_session(profile_name=args.profile, region_name=args.region)
        sts_client = create_aws_client("sts", args.region)
        caller_identity = sts_client.get_caller_identity()
        account_id = caller_identity["Account"]
        research["account_id_suffix"] = account_id[-4:]
    except Exception as e:
        logger.error(f"Unable to validate AWS credentials with STS: {sanitize_error_message(e)}")
        return 2

    if args.log_to_cloudwatch:
        logger.warning(
            "CloudWatch logging is enabled; this mode creates or uses a log group and stream and sends log events to AWS."
        )
        setup_cloudwatch_logging(
            log_group=args.cloudwatch_log_group,
            log_stream=f"govhawk_{datetime.datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            region=args.region,
        )

    logger.info(f"Starting AWS GovCloud analysis for {len(target_services)} services...")
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="govhawk") as executor:
        futures = {
            executor.submit(
                research_service, service_name, research_func, client_names, args.skip_metrics
            ): service_name
            for service_name, (research_func, client_names) in service_map.items()
            if service_name in target_services
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Thread execution error for {futures[future]}: {sanitize_error_message(e)}")
            if shutdown_event.is_set():
                for pending in futures:
                    pending.cancel()
                break

    if not research["services"]:
        logger.error("No service results were collected; no report was created")
        return 130 if shutdown_event.is_set() else 1

    timestamp = datetime.datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else Path(__file__).resolve().parent / "output"
    base_name = f"govhawk_report_{timestamp}"
    report_data = dict(research)
    report_data["logo_path"] = args.logo
    output_paths = []

    try:
        if args.output_format in {"pdf", "both"}:
            output_paths.append(generate_pdf_report(report_data, output_dir / f"{base_name}.pdf"))
        if args.output_format in {"json", "both"}:
            json_data = dict(report_data)
            json_data.pop("logo_path", None)
            output_paths.append(write_json_report(json_data, output_dir / f"{base_name}.json"))
        for output_path in output_paths:
            harden_output_permissions(output_path)
    except Exception as e:
        logger.error(f"Report generation failed: {sanitize_error_message(e)}")
        return 1

    print("\nSENSITIVE DATA NOTICE: Reports may contain account and infrastructure metadata.")
    print("Protect, classify, retain, and distribute each report according to your organization's requirements.")
    for output_path in output_paths:
        print(f"Report saved to: {output_path}")

    logger.info("AWS GovCloud environment analysis completed")
    return 130 if shutdown_event.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
