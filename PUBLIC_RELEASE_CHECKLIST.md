# Public Release Checklist

Completed items reflect the public-source review on August 12, 2026. Remaining
items apply before creating the first tagged release.

- [x] Add the Apache License 2.0.
- [x] Confirm the repository owner, project name, GitHub issues, and private
      vulnerability-reporting channels.
- [x] Enable GitHub private vulnerability reporting.
- [x] Review all files and Git history for credentials, account IDs, resource
      names, reports, screenshots, organization branding, CUI, and other
      controlled or proprietary information.
- [x] Run Gitleaks against the working tree and full Git history.
- [x] Run tests, Ruff, mypy, Bandit, and pip-audit from a clean Python 3.12
      virtual environment.
- [x] Run read-only validation in both `us-gov-west-1` and `us-gov-east-1`
      using approved credentials, with metrics and CloudWatch logging disabled.
- [x] Review synthetic PDF layout and validate live PDF and JSON structure,
      error redaction, banner behavior, and output cleanup.
- [x] Document every AWS API permission in `IAM_PERMISSIONS.md`.
- [x] Keep optional CloudWatch logging disabled during live validation.
- [x] Pin the three direct runtime dependencies and add deterministic
      standalone, source ZIP, SPDX 2.3, checksum, and commit-evidence assets.
- [x] Add exact five-asset enforcement, repeat-build comparison, GitHub
      provenance, and a tag-only workflow that can create only a draft.
- [x] Pass offline release-asset tests without using AWS credentials or live
      account data.
- [ ] Validate the documented starter IAM policy in an approved non-production
      account before creating the first tagged release.
- [ ] Approve a CloudWatch Logs destination, encryption, access, and retention
      policy before demonstrating optional logging with real data.
- [ ] Create the initial release tag after the remaining tagged-release gates
      are complete.

Do not add a real report or organization seal as a sample artifact. Use synthetic
screenshots or fixtures if public examples are needed.
