# IAM Permissions

GovHawk is read-mostly. Normal analysis calls list, describe, get, and
CloudWatch metric APIs. The optional `--log-to-cloudwatch` mode is the only mode
that creates AWS resources or sends data to an AWS service.

The policy below is a reviewable starter policy for all 29 supported services.
It is not a universal least-privilege policy. Apply organization SCPs,
permission boundaries, resource restrictions, session policies, and regional
controls as required by your environment.

## Analysis operations

| Area | Required actions |
| --- | --- |
| Identity validation | `sts:GetCallerIdentity` |
| Metrics and alarms | `cloudwatch:GetMetricData`, `cloudwatch:DescribeAlarms` |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetLifecycleConfiguration`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration` |
| VPC and EC2 | `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeInstances`, `ec2:DescribeVolumes` |
| Direct Connect | `directconnect:DescribeConnections` |
| AWS Backup | `backup:ListBackupPlans`, `backup:GetBackupPlan` |
| Lambda | `lambda:ListFunctions` |
| OpenSearch Service | `es:ListDomainNames` |
| CloudFormation | `cloudformation:ListStacks`, `cloudformation:ListStackResources` |
| ECS | `ecs:ListClusters`, `ecs:DescribeClusters`, `ecs:ListServices` |
| AppStream 2.0 | `appstream:DescribeFleets` |
| Directory Service | `ds:DescribeDirectories` |
| EFS | `elasticfilesystem:DescribeFileSystems`, `elasticfilesystem:DescribeLifecycleConfiguration` |
| Kinesis Data Streams | `kinesis:ListStreams`, `kinesis:DescribeStreamSummary` |
| SES | `ses:ListIdentities`, `ses:GetIdentityVerificationAttributes` |
| AWS WAF | `wafv2:ListWebACLs`, `wafv2:GetLoggingConfiguration` |
| KMS | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` |
| Elastic Load Balancing | `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeLoadBalancerAttributes` |
| GuardDuty | `guardduty:ListDetectors`, `guardduty:GetDetector` |
| IAM | `iam:ListPolicies`, `iam:GetPolicyVersion` |
| Firewall Manager | `fms:ListPolicies` |
| Amazon Inspector | `inspector2:BatchGetAccountStatus` |
| Security Hub | `securityhub:DescribeHub` |
| CloudTrail | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| RDS | `rds:DescribeDBInstances` |
| CodeCommit | `codecommit:ListRepositories`, `codecommit:GetRepository` |
| ECR | `ecr:DescribeRepositories`, `ecr:GetLifecyclePolicy` |
| Trusted Advisor | `support:DescribeTrustedAdvisorChecks`, `support:DescribeTrustedAdvisorCheckResult` |

Trusted Advisor API availability depends on the AWS Support plan. Some services
also require the service to be enabled. GovHawk records partial or unavailable
results when an API is unsupported or permission is denied.

## Starter policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GovHawkReadOnlyAnalysis",
      "Effect": "Allow",
      "Action": [
        "appstream:DescribeFleets",
        "backup:GetBackupPlan",
        "backup:ListBackupPlans",
        "cloudformation:ListStackResources",
        "cloudformation:ListStacks",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "codecommit:GetRepository",
        "codecommit:ListRepositories",
        "directconnect:DescribeConnections",
        "ds:DescribeDirectories",
        "ec2:DescribeInstances",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "ecs:DescribeClusters",
        "ecs:ListClusters",
        "ecs:ListServices",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeLifecycleConfiguration",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeLoadBalancers",
        "es:ListDomainNames",
        "fms:ListPolicies",
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "iam:GetPolicyVersion",
        "iam:ListPolicies",
        "inspector2:BatchGetAccountStatus",
        "kinesis:DescribeStreamSummary",
        "kinesis:ListStreams",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "lambda:ListFunctions",
        "rds:DescribeDBInstances",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:ListAllMyBuckets",
        "securityhub:DescribeHub",
        "ses:GetIdentityVerificationAttributes",
        "ses:ListIdentities",
        "sts:GetCallerIdentity",
        "support:DescribeTrustedAdvisorCheckResult",
        "support:DescribeTrustedAdvisorChecks",
        "wafv2:GetLoggingConfiguration",
        "wafv2:ListWebACLs"
      ],
      "Resource": "*"
    }
  ]
}
```

## Optional CloudWatch Logs permissions

Add the following statement only when `--log-to-cloudwatch` is approved. These
are write permissions and are not needed for normal analysis.

```json
{
  "Sid": "GovHawkOptionalCloudWatchLogging",
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ],
  "Resource": "*"
}
```

Restrict the `Resource` to the approved log group and stream ARNs when your
deployment model permits it. Configure retention, encryption, access, and data
handling before enabling the option with real environment data.
