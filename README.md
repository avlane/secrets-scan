# secrets-scan

Scan a directory (or the files tracked by git) for likely secrets: API keys, tokens,
private keys and high-entropy strings. No dependencies, nothing leaves your machine. Needs Node.js 20 or newer.

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

    path: docs/examples/**                      # every finding in these files
    regex: ^AKIAIOSFODNN7EXAMPLE$               # findings whose secret text matches
    rule: generic-secret-assignment @ test/**   # one rule, optionally only in some files
    fingerprint: 3fa9c1d2e4b5a6978c0d1e2f3a4b5c6d   # one finding, from --format json

Any entry may end with `expires=2026-01-31`; after that day it is ignored (and a warning
says so), so temporary exceptions don't become permanent.
## Inline ignores

Silence a single finding with a comment in the file itself:

    const key = "AKIAIOSFODNN7EXAMPLE"; // secrets-scan:ignore
    # secrets-scan:ignore-next-line
    password = "not-a-real-password"

and a whole file with `secrets-scan:ignore-file` anywhere in it.
## Scanning what git tracks

`secrets-scan --git` scans exactly the files `git ls-files` lists - no untracked build output,
no ignored files - which is usually what a CI job wants.
## Baselines

To adopt secrets-scan on a project that already contains findings, record them once and fail
only on new ones:

    secrets-scan --write-baseline .secrets-baseline.json
    secrets-scan --baseline .secrets-baseline.json

The baseline stores hashes (rule + path + secret), never the secrets, and survives line
number changes.
## Output formats

`--format text` (default), `--format json`, and `--format sarif` for GitHub code scanning
and IDE viewers:

    secrets-scan --format sarif > results.sarif

Secrets are masked in every format unless you pass `--show-secrets`; SARIF never contains them.
## Pre-commit

`secrets-scan --staged` scans the content staged in git's index (not the working tree), which
is what a pre-commit hook needs:

    #!/bin/sh
    exec npx secrets-scan --staged
## Standard input

`secrets-scan --stdin --stdin-filename deploy/prod.env < file` (or the path `-`) scans text
piped in, for example the output of `git show` or a template renderer.
