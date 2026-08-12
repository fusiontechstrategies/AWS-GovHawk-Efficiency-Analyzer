# GovHawk AWS GovCloud Efficiency Analyzer

GovHawk is a single-file Python tool that inventories an AWS GovCloud (US)
region and produces a review-ready PDF, JSON report, or both. It collects
resource counts, selected CloudWatch metrics, configuration signals, and
conservative recommendations across 29 AWS services.

The executable remains one file: `AWS_GovCloud_Analyzer.py`. The other files in
this repository provide documentation, tests, dependency declarations, and
continuous-integration support.

## Important boundaries

- Findings are review signals, not a compliance certification, security audit,
  or guaranteed savings forecast.
- The analyzer does not execute remediation commands.
- Normal analysis uses read APIs. `--log-to-cloudwatch` is an explicit exception:
  it creates or reuses a log group and stream and sends log events to AWS.
- Reports can contain account and infrastructure metadata. The default banner is
  `SENSITIVE - REVIEW BEFORE SHARING`; it does not classify the report. Use a
  `CUI` banner only when an authorized classification decision supports it.
- GovHawk is an independent project. It is not affiliated with or endorsed by
  Amazon Web Services or the United States Government.

GovCloud billing data is available through the associated standard AWS account,
not GovCloud credentials, so this tool deliberately does not query Cost Explorer
or invent dollar savings. CloudFront is also not available inside the GovCloud
partition, so it is outside the analyzer's regional inventory scope. See the
[AWS GovCloud billing guidance](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/usage-and-payment.html)
and [CloudFront/GovCloud guidance](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/setting-up-cloudfront.html).

## Supported services

AppStream, AWS Backup, CloudFormation, CloudTrail, CloudWatch, CodeCommit,
Direct Connect, Directory Service, EBS, EC2, ECR, ECS, EFS, Elastic Load
Balancing (Classic and v2), Firewall Manager, GuardDuty, IAM, Amazon Inspector,
Kinesis Data Streams, KMS, Lambda, OpenSearch Service, RDS, S3, Security Hub,
SES, Trusted Advisor, VPC, and AWS WAF.

GovHawk uses the current WAFv2 and Inspector2 APIs. AWS ended WAF Classic support
on September 30, 2025 and Inspector Classic support on May 20, 2026. See the
[AWS WAF API notice](https://docs.aws.amazon.com/waf/latest/APIReference/Welcome.html)
and [Inspector migration notice](https://docs.aws.amazon.com/inspector/v1/userguide/inspector-migration.html).

## Requirements

- Python 3.10 or later
- AWS GovCloud credentials for the target account
- Network access to the relevant GovCloud service endpoints
- Permissions for the list, describe, get, and CloudWatch metric operations used
  by the selected services

Trusted Advisor API access depends on the account's support plan. Optional
CloudWatch logging additionally requires `logs:CreateLogGroup`,
`logs:CreateLogStream`, and `logs:PutLogEvents`.

## Install

Create and activate a virtual environment, then install the runtime dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS or Linux, activate with `source .venv/bin/activate`.

## Run

Analyze all 29 services in `us-gov-west-1`:

```powershell
python AWS_GovCloud_Analyzer.py
```

Use a named AWS profile and create PDF plus JSON output:

```powershell
python AWS_GovCloud_Analyzer.py --profile govcloud --output-format both
```

Analyze selected services. Names are case-insensitive; comma-separated and
quoted multiword names are supported:

```powershell
python AWS_GovCloud_Analyzer.py --services S3 EC2 RDS
python AWS_GovCloud_Analyzer.py --services s3,ec2,"Security Hub"
```

Skip utilization metrics without producing false low-usage findings:

```powershell
python AWS_GovCloud_Analyzer.py --skip-metrics
```

Analyze the other GovCloud region with a 30-day metric window:

```powershell
python AWS_GovCloud_Analyzer.py --region us-gov-east-1 --lookback-days 30
```

Apply an authorized report banner and optional organization logo:

```powershell
python AWS_GovCloud_Analyzer.py --banner "CUI" --logo C:\path\to\logo.png
```

List supported services or display all options:

```powershell
python AWS_GovCloud_Analyzer.py --list-services
python AWS_GovCloud_Analyzer.py --help
```

## Output and data handling

Reports are written to `output/` beside the script unless `--output-dir` is
specified. Generated filenames use UTC timestamps:

```text
govhawk_report_YYYYMMDD_HHMMSS.pdf
govhawk_report_YYYYMMDD_HHMMSS.json
```

On POSIX systems, GovHawk applies owner read/write mode bits. Windows `chmod`
does not create an owner-only NTFS ACL, so protect the output directory with
appropriate NTFS permissions. Generated reports, temporary files, local logos,
credentials, and environment files are excluded by `.gitignore`.

## Recommendation safety

Some JSON findings include example AWS CLI remediation commands. They are text
only and may be destructive if copied and executed. Always validate ownership,
dependencies, backup/restore readiness, change approval, and the target account
and region before using a command.

Metrics use a configurable observation window and distinguish skipped or missing
data from a real zero. Rightsizing recommendations require actual samples, and
their wording calls for memory, network, storage, peak, and workload review.

## Development

Install development tools and run the checks:

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check AWS_GovCloud_Analyzer.py tests
mypy AWS_GovCloud_Analyzer.py --ignore-missing-imports
```

The tests validate argument handling, pagination, missing-metric behavior, EC2
root-volume encryption logic, IAM policy heuristics, PDF generation, and all 29
service entry points against botocore's current API models without contacting AWS.

## Current limitations

- One GovCloud account and one region are analyzed per run.
- No billing, price, or dollar-savings calculation is performed.
- CloudFront and associated-standard-account resources are out of scope.
- Findings do not replace AWS Config, Security Hub controls, Compute Optimizer,
  formal compliance assessment, or workload-owner review.
- Live-account behavior still depends on permissions, enabled services, support
  plan, service quotas, and the size of the environment.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md) before publishing or
accepting contributions.
