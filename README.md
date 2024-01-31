# secrets-scan

Scan a directory (or the files tracked by git) for likely secrets: API keys, tokens,
private keys and high-entropy strings. No dependencies, nothing leaves your machine.

Work in progress. Planned: provider-specific patterns, an entropy detector, an allowlist
file, baselines for existing findings, and JSON / SARIF output.

    npx secrets-scan [PATH...]

Exit status: 0 when nothing was found, 1 when secrets were found, 2 on errors.
Restrict the scan with `--include GLOB` and `--exclude GLOB` (both repeatable):

    secrets-scan . --exclude vendor --exclude '*.snap' --include '*.env'

Patterns without a `/` match names anywhere; patterns with a `/` start at the scanned
directory; `**` crosses directories.
## Allowlist

Findings that are fine can be listed in `.secrets-allowlist` (or `--allowlist FILE`), one entry
per line, `#` for comments:

    path: docs/examples/**         # every finding in these files
    regex: ^AKIAIOSFODNN7EXAMPLE$  # findings whose secret text matches
## Inline ignores

Silence a single finding with a comment in the file itself:

    const key = "AKIAIOSFODNN7EXAMPLE"; // secrets-scan:ignore
    # secrets-scan:ignore-next-line
    password = "not-a-real-password"

and a whole file with `secrets-scan:ignore-file` anywhere in it.
