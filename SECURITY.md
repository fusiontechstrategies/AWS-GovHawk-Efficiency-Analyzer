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

Private POSIX report creation is supported on local Linux ext2/3/4, XFS,
Btrfs, tmpfs and overlayfs. Descriptor-based filesystem checks refuse unknown,
network and FUSE ACL semantics; Darwin report creation is refused until its
effective ACL semantics can be verified. Extended access or default ACLs on any
pinned ancestor, staging directory or report file abort generation. The checks
run before content is written and again before publication. Ordinary analysis
does not require this filesystem contract until it creates a report.

On Windows, every guarded ancestor has a retained immediate child through
publication, and staging has the open report. Non-delete-shared handles prevent
removal of those children. The directories therefore cannot become empty, a
requirement for assigning a reparse point. Directory write sharing remains
necessary for NTFS hard-link publication; owner, DACL and reparse attributes are
revalidated before writing and publication. A preauthorized writer test uses a
synthetic owned fixture and the actual reparse request, with an empty acceptance
control. No host root is changed. A principal retaining historical WRITE_DAC or
trusted administrative authority can alter permissions after the operation ends;
continued report retention still requires an owner-controlled location.

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
# Report parents, logging and immutable smoke checks

On Windows, output-directory owners and DACLs are inspected by retained non-reparse handles. Existing caller directory ACLs are never rewritten. Current-user, SYSTEM, Administrators and TrustedInstaller authority forms the local operating-system trust boundary. OWNER RIGHTS is accepted only after that actual owner has been checked. Shared child-mutation, deletion, reparse and ACL/owner-control grants are refused conservatively. A canonical physical volume root is identified through its volume-GUID handle path, rather than a user-controlled pathname; its child-deletion and ACL/owner-control authority remains checked. All ordinary path components and final output parents retain mutation checks. A broadly writable temporary directory may be refused; select a private directory with trusted ancestry.

Ordinary AWS errors expose only a bounded error code. Service-supplied human-readable messages, resource names, principal identities and request metadata are excluded from both local logs and optional CloudWatch Logs. Full service messages are not retained through an implicit debug mode.

Release assets and their manifest are finalized and uploaded before any mutable privileged smoke-test package installation. Bubblewrap installation and candidate execution happen in a separate read-only consumer job, which cannot supply replacement artifact IDs, manifests or release bytes. Attestation and draft creation consume the producer's immutable handoff and require the consumer to pass.

Privileged release promotion runs from protected main independently of the
selected tag. Its trusted helper authenticates the producer's run/artifact
identity and reconstructs all five subjects from tagged source data. Each
OIDC/write job repeats exact verification, and draft uploads receive digest
readback verification. Tagged helpers never execute in those jobs. The main-only
release environment requires a reviewer; an authorized administrator can
explicitly bypass that approval and remains within the trusted operator boundary.

Resource progress events omit identifier values at DEBUG as well as INFO.
Report and logo paths are not sent to logs. A logger filter and the CloudWatch
formatter redact recognizable structured identifiers and absolute paths and
discard traceback/stack attachments before rendering diagnostic records.
