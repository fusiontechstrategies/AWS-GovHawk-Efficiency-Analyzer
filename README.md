# GovHawk: AWS GovCloud Efficiency Analyzer

[![CI](https://github.com/fusiontechstrategies/AWS-GovHawk-Efficiency-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/fusiontechstrategies/AWS-GovHawk-Efficiency-Analyzer/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB)
![AWS GovCloud](https://img.shields.io/badge/AWS-GovCloud-FF9900)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> One file. One command. A clearer view of potential waste, security blind
> spots, and operational risk across 29 AWS GovCloud services.

GovHawk inventories an AWS GovCloud (US) region and produces a review-ready PDF,
JSON report, or both. It collects resource counts, selected CloudWatch metrics,
configuration signals, and conservative recommendations without automatically
changing the environment.

The executable remains one file: `AWS_GovCloud_Analyzer.py`. The other files in
this repository provide documentation, tests, dependency declarations, and
continuous-integration support.

## Why GovHawk

- Cover 29 GovCloud services without installing a framework or deploying an
  agent.
- Distinguish missing metrics from genuine zero usage to reduce misleading
  findings.
- Give technical teams structured JSON and stakeholders a polished PDF from the
  same run.
- Keep recommendations evidence-based, review-only, and free of invented dollar
  savings.

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

Version 2.0.0 is the current release candidate. No tag or GitHub release exists
yet. Until the tested standalone runtime, deterministic ZIP, SPDX SBOM,
checksums, release evidence, and provenance are available together, evaluate
the protected repository source rather than a similarly named download. See
[RELEASING.md](RELEASING.md) for the exact gates.

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

See [IAM_PERMISSIONS.md](IAM_PERMISSIONS.md) for the exact API operations and a
reviewable starter policy. Tailor that policy to your account boundaries and
organization controls before use.

Trusted Advisor API access depends on the account's support plan. Optional
CloudWatch logging additionally requires `logs:CreateLogGroup`,
`logs:CreateLogStream`, and `logs:PutLogEvents`.

## Install

Create and activate a virtual environment, then install the exact runtime dependencies:

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
python AWS_GovCloud_Analyzer.py --version
```

The list, help, and version commands do not contact AWS and are the safest first
checks before configuring an authorized account path.

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
S3 discovery is partition-wide, but GovHawk verifies each bucket location and
includes only buckets in the selected region.

## Development

Install development tools and run the checks:

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check AWS_GovCloud_Analyzer.py scripts tests
ruff format --check AWS_GovCloud_Analyzer.py scripts tests
mypy AWS_GovCloud_Analyzer.py --ignore-missing-imports
bandit -q -r AWS_GovCloud_Analyzer.py scripts
pip-audit -r requirements.txt
```

The tests validate argument handling, pagination, missing-metric behavior, EC2
root-volume encryption logic, IAM policy heuristics, PDF generation, and all 29
service entry points against botocore's current API models without contacting AWS.

The 2.0.0 release path builds the exact standalone runtime, deterministic source
and documentation ZIP, SPDX 2.3 dependency SBOM, SHA-256 checksums, and
commit-bound evidence twice and requires identical bytes. A tag pointing to a
verified protected-main commit can create only a draft release. The first tag
also remains blocked on the live controls in
[PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md).

## Current limitations

- One GovCloud account and one region are analyzed per run.
- No billing, price, or dollar-savings calculation is performed.
- CloudFront and associated-standard-account resources are out of scope.
- Findings do not replace AWS Config, Security Hub controls, Compute Optimizer,
  formal compliance assessment, or workload-owner review.
- Live-account behavior still depends on permissions, enabled services, support
  plan, service quotas, and the size of the environment.

## License

GovHawk is licensed under the [Apache License 2.0](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md), and
[PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md) before accepting
contributions or creating a tagged release. Release validation details are in
[TESTING.md](TESTING.md) and [RELEASING.md](RELEASING.md).
