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

Each invocation removes and closes its CloudWatch handler, including failed or
interrupted runs. A later invocation must opt in separately.

Reports are written through exclusive regular-file descriptors in a private
staging directory. POSIX reports have mode 0600 before content is written, and
publication and cleanup use pinned directory descriptors even if an ancestor
is replaced. On Windows, the staging directory is created with an owner-only
protected NTFS DACL in its creation-time security descriptor. There is no
intermediate inherited-ACL directory before protection is applied.
The parent and staging directory are held through non-reparse Win32 handles
without delete sharing. The staging DACL is applied to the open handle, and the
report remains open through hard-link publication so pathname replacement cannot
redirect a sensitive write. A conflicting directory handle aborts generation.
Protection setup failure aborts generation. Existing final entries, including
links, are never overwritten. POSIX output parents must belong to the current
user and must not be writable by other users.

## Collection limits and incomplete coverage

Each AWS service is limited to 1,000 operation calls, 2,000 list entries,
4 MiB of retained response data, and 300 seconds of collection time. A whole
run is limited to 12,000 calls, 30,000 entries, 32 MiB, and 900 seconds.
Calls already in progress remain subject to configured SDK timeouts and retries;
these are collection budgets, not hard process termination deadlines. Limits
stop further calls and reject oversized responses. A budget-limited run marks
JSON coverage incomplete, adds a PDF warning, and exits with code 3. Missing
inventory must not be interpreted as evidence that resources are absent or safe.
Use separately scoped runs for large environments.

SES remediation is emitted as an argument list, not a portable shell command.
Keep identity values as data when using an SDK or an approved command runner.
Release jobs invoke verifiers in Python isolated mode so tagged modules cannot
shadow standard-library imports. Signed source review and release environment
controls remain necessary to authorize the verifier code itself.

All service results include `inventory_complete` and bounded `incomplete_reasons`.
Nested query failures and partial service families remain incomplete even when
other resources were collected successfully. Selected services without results
and interrupted work also make the run incomplete. JSON and PDF use the same
coverage decision. Interrupted runs retain exit code 130; other incomplete runs
exit with code 3.

Private `.govhawk-private-*` staging directories are ignored at every depth,
including custom output paths. A crash can leave a protected staging directory
behind. Review its ownership and contents under your retention policy before
manual cleanup; do not add it to a commit. Git ignore rules are only an accidental
disclosure guard, not access control.
