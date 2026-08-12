# Public Release Checklist

Complete these items before making the repository public.

- [ ] Choose and add a license. No open-source license has been selected yet.
- [ ] Confirm the repository owner, copyright holder, project name, and public
      contact channels.
- [ ] Enable GitHub private vulnerability reporting.
- [ ] Review all files and Git history for credentials, account IDs, resource
      names, reports, screenshots, organization branding, CUI, and other
      controlled or proprietary information.
- [ ] Run a secret scanner against the working tree and full Git history.
- [ ] Run the unit tests, Ruff, and mypy from a clean virtual environment.
- [ ] Test a least-privilege run in both `us-gov-west-1` and `us-gov-east-1`
      using non-production accounts or approved environments.
- [ ] Review generated PDF and JSON outputs for expected redaction, banner,
      classification, permissions, and retention behavior.
- [ ] Confirm every AWS API and required permission in the README.
- [ ] Confirm optional CloudWatch logging has an approved destination and
      retention policy before demonstrating it with real data.
- [ ] Create the initial release tag only after the live-environment validation
      and license decision are complete.

Do not add a real report or organization seal as a sample artifact. Use synthetic
screenshots or fixtures if public examples are needed.
