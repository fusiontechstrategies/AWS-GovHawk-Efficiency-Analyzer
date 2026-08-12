# Contributing

Thank you for helping improve GovHawk.

## Design constraint

The runnable analyzer must remain a single Python file:
`AWS_GovCloud_Analyzer.py`. Tests, documentation, and repository automation may
remain in separate files. Avoid splitting runtime behavior into a package unless
the project owner explicitly changes this constraint.

## Before opening a pull request

1. Create a virtual environment and install `requirements-dev.txt`.
2. Make focused changes that preserve read-mostly behavior.
3. Add or update tests for behavior changes.
4. Run:

   ```text
   python -m unittest discover -s tests -v
   ruff check AWS_GovCloud_Analyzer.py tests
   mypy AWS_GovCloud_Analyzer.py --ignore-missing-imports
   ```

5. Render a representative PDF when report code changes and visually inspect
   every page for clipping, overlap, unreadable tables, and broken characters.
6. Update `CHANGELOG.md` for user-visible changes.

## Safety and privacy

- Never commit generated reports, account exports, credentials, resource names,
  screenshots from real environments, organization logos, or classified data.
- Use botocore stubs or synthetic values in tests.
- Do not add an API call that changes AWS state under normal analysis.
- If an opt-in feature writes to AWS, disclose it in the CLI help and README and
  keep it disabled by default.
- Do not label a heuristic as a compliance failure or assign dollar savings
  without authoritative evidence and explicit calculation inputs.

## Pull request notes

Describe the behavior changed, test evidence, AWS documentation consulted, and
any new permissions or data-handling implications. Keep remediation commands
review-only and call out destructive examples clearly.
