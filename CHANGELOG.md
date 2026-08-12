# Changelog

All notable changes to GovHawk are documented here.

## [2.0.0] - 2026-08-12

### Changed

- Updated WAF Classic to WAFv2 and Inspector Classic to Inspector2.
- Limited the default inventory to 29 services available through GovCloud
  credentials; removed invalid GovCloud CloudFront and Cost Explorer calls.
- Added pagination across supported list and describe operations.
- Distinguished skipped or missing CloudWatch data from a real zero.
- Replaced unsupported savings numbers with evidence-based review language.
- Corrected EC2 root-volume encryption detection and stopped-instance wording.
- Expanded Elastic Load Balancing coverage to Classic ELB plus ALB/NLB/GWLB.
- Improved S3 public-access evaluation, ECR lifecycle checks, KMS rotation
  eligibility, GuardDuty status, Backup lifecycle checks, and other service
  signals.
- Added case-insensitive service selection, profiles, output formats, lookback
  and worker controls, custom output directory, banner, logo, and version/list
  commands.
- Replaced the hard-coded CUI marking with a user-selected banner and clear
  classification disclaimer.
- Made PDF and JSON writes atomic and made report-generation failures fatal.
- Replaced the external JSON logger dependency with a built-in formatter.

### Added

- Offline unit/API-model tests for all 29 service entry points.
- Public-repository documentation, security guidance, CI, dependency updates,
  and report-focused ignore rules.
- Apache License 2.0, explicit IAM permission guidance, repository ownership
  rules, dependency auditing, security linting, and expanded Python CI coverage.
- Current boto3, botocore, ReportLab, mypy, and Ruff dependency baselines.

## [1.0.0] - 2026-04-07

- Original single-file analyzer baseline.
