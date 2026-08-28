# Release process

GovHawk releases come from a reviewed, fully tested commit on protected `main`. The runtime, changelog, release notes, dependency pins, tag, release assets, checksums, SBOM, and evidence must describe the same stable version.

Creating a tag and publishing a GitHub release each require an explicit maintainer decision. The tag workflow can create only a draft. It contains no publication command for PyPI or another package registry.

## Exact asset contract

For version `X.Y.Z`, a GitHub release contains only:

1. `AWS-GovHawk-Efficiency-Analyzer-vX.Y.Z.py`
2. `AWS-GovHawk-Efficiency-Analyzer-vX.Y.Z.zip`
3. `AWS-GovHawk-Efficiency-Analyzer-vX.Y.Z.spdx.json`
4. `SHA256SUMS.txt`
5. `release-evidence.json`

The standalone and ZIP runtime are byte-identical to `AWS_GovCloud_Analyzer.py` in the tagged commit. The stored ZIP has a fixed allowlist, canonical order, timestamps, ownership, permissions, and member metadata. The SPDX 2.3 document records the exact direct runtime dependencies. SHA-256 covers the runtime, ZIP, and SBOM. Machine-readable evidence binds those assets and every ZIP member to the exact source commit.

Every release asset receives GitHub build-provenance attestation. Existing release assets are never replaced.

## Release-readiness gates

1. Start from current protected `main`.
2. Confirm runtime `VERSION`, changelog heading, and `.github/release-notes/vX.Y.Z.md` agree.
3. Run all offline tests on Python 3.10, 3.12, and 3.14.
4. Pass Ruff, formatting, mypy, Bandit, dependency audits, CodeQL, Semgrep, Trivy, dependency review, and full-history Gitleaks.
5. Build the exact five assets twice with the candidate commit and commit time, then require identical filenames and bytes.
6. Run `--version`, `--help`, and `--list-services` from the standalone asset.
7. Inspect every ZIP path, byte, timestamp, mode, and metadata field; verify checksums, SBOM dependencies, and commit-bound evidence.
8. Generate and inspect synthetic PDF and JSON evidence without using a real account, report, logo, identifier, or organization seal.
9. Confirm the documented starter IAM policy has been validated in an approved non-production account.
10. Keep optional CloudWatch logging disabled unless its destination, encryption, access, and retention controls have separate approval.

## Candidate command

Use a new output directory and the exact 40-character candidate commit:

```powershell
$candidateCommit = git rev-parse HEAD
$candidateEpoch = git show -s --format=%ct HEAD

python scripts\prepare_release.py `
  --version 2.0.0 `
  --tag v2.0.0 `
  --source-commit $candidateCommit `
  --source-date-epoch $candidateEpoch `
  --output-directory release-assets
```

The builder rejects a development or mismatched version, malformed commit, mismatched tag, missing release notes, non-pinned runtime dependency, missing or linked source file, unsafe package path, existing output directory, noncanonical ZIP, or unexpected final asset.

## Draft creation

Tag creation is maintainer-controlled. The tag must be `vX.Y.Z` and resolve to the approved protected-main commit. That target commit must have a valid GitHub verification record and be reachable from protected `main`.

Pushing the tag starts `.github/workflows/release.yml`. The workflow:

1. Resolves the tag to its exact commit.
2. Confirms the commit is reachable from protected `main` and GitHub-verified.
3. Refuses to continue if a release already exists for the tag.
4. Builds the exact five assets twice and compares every byte.
5. Exercises the exact standalone runtime.
6. Attests every asset with GitHub provenance.
7. Creates a non-prerelease draft from committed versioned notes.
8. Confirms the draft contains exactly the five approved assets.

The workflow has no manual trigger and no release-publication command.

## Publication review

Before publishing the draft:

- confirm the starter IAM policy gate is complete in an approved non-production account
- confirm optional CloudWatch logging was not used, or has separately approved destination, encryption, access, and retention controls
- confirm the tag and draft target the approved verified commit
- download all five assets into a new directory
- recompute every SHA-256 digest and verify every provenance attestation
- confirm the standalone and ZIP runtime bytes match tagged source
- inspect the complete portable ZIP allowlist and metadata
- confirm the SPDX dependency set and commit-bound evidence
- run `--version`, `--help`, and `--list-services` from the downloaded standalone asset
- rerun the complete offline test and synthetic report checks
- confirm there are zero open code-scanning, Dependabot, or secret-scanning alerts, except any narrowly documented accepted exception
- confirm the release notes preserve the review-only, sensitive-report, authorization, and optional-write boundaries

Publish only after every check passes. Then repeat the public download, digest, provenance, runtime, ZIP, and synthetic validation against the public URLs.

## Registry publication remains separate

This repository has no PyPI or other registry publication workflow. Any future package-registry work requires a separate identity, packaging, trusted-publisher, protected-environment, and clean-install review. Never add a long-lived registry token merely to simplify publication.
