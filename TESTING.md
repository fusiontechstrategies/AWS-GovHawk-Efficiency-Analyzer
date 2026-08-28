# Testing

Tests use local synthetic data, fake clients, and botocore API models. No live report or organization-specific data is stored in the repository.

## 2.0.0 release-readiness validation

The protected workflow covers Python 3.10, 3.12, and 3.14 on Linux. Local boundary validation uses the same three versions on Windows. Hosted and local gates must pass before release approval.

### Functional and report coverage

- Argument and GovCloud-region validation
- Flexible service selection and duplicate removal
- Paginator aggregation
- Missing or skipped metric states that do not become false zero-usage findings
- S3 regional filtering
- Lambda low-usage handling
- EC2 root-volume encryption matching
- IAM wildcard heuristics
- Synthetic PDF generation with missing metrics and XML control characters
- Current empty API shapes for all 29 service entry points
- Account and access-key redaction in client errors
- Repository punctuation policy

### Release coverage

- Runtime, tag, changelog, notes, and dependency identity agreement
- Exact five-asset output
- Exact runtime bytes in standalone and ZIP forms
- Canonical ZIP path, order, timestamp, permission, creator, encryption, metadata, and content checks
- SPDX 2.3 dependency inventory for the exact three direct runtime pins
- SHA-256 checksum and commit-bound evidence validation
- Repeat builds with identical bytes
- Fail-closed version, epoch, and existing-output tests

### Security and quality gates

- Ruff lint and format checks
- mypy type analysis
- Bandit static security analysis
- runtime and development dependency audits
- dependency review
- CodeQL for Python and GitHub Actions
- Semgrep, Trivy, and full-history Gitleaks through the pinned reusable scanner workflow

## Live-account boundary

Prior approved read-only validation covered both `us-gov-west-1` and `us-gov-east-1` with metrics and CloudWatch logging disabled. The first release remains blocked until the documented starter IAM policy is validated in an approved non-production account. Optional CloudWatch logging requires separate destination, encryption, access, and retention approval before any real-data demonstration.

These checks are evidence for exercised code paths. They do not prove that every account, service state, permission boundary, quota, support plan, organization control, or workload will behave identically.
