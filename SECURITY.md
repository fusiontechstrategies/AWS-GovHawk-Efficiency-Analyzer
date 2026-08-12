# Security Policy

## Supported version

Security fixes are applied to the latest released version of GovHawk.

## Reporting a vulnerability

Do not open a public issue containing a vulnerability, AWS account data,
resource identifiers, credentials, report output, or classified information.
Use GitHub's private vulnerability reporting feature from the repository's
Security tab. If that feature is unavailable, contact the repository owner
through an established private channel without attaching sensitive environment
data.

Include a minimal synthetic reproduction, affected version, impact, and proposed
mitigation when possible.

## Sensitive outputs

GovHawk reports can reveal account and infrastructure metadata. Generated PDF and
JSON files are ignored by Git, but `.gitignore` is not a security boundary.
Protect the output directory, review every staged file before committing, and
follow the owning organization's classification, retention, and distribution
requirements.

The `--log-to-cloudwatch` option sends run logs to AWS and creates or reuses a
log group and stream. Leave it disabled unless the destination and retention
policy are approved.
