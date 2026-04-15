# secrets-scan

Finds likely secrets - API keys, tokens, private keys, passwords in URLs, high-entropy strings -
in a directory, in the files git tracks, in what is staged for commit, or in the lines a pull
request adds. No dependencies, nothing leaves your machine. Needs Node.js 20 or newer.

    $ npx secrets-scan
    src/deploy.js:14:21  github-token  [high]  GitHub token: ghp_************
    config/prod.env:3:12  generic-secret-assignment  [medium]  Hard-coded credential: Tr0u*********
    secrets-scan: 2 potential secrets in 2 files (1 high, 1 medium); scanned 87 files

Matches are masked in every report (`--show-secrets` shows them). The exit status is 0 when
nothing was found, 1 when something was, 2 on errors.

> A scanner like this is a net, not a guarantee. It finds the credentials that look like
> credentials. Treat anything it reports as leaked until proven otherwise, and rotate it.

## Choosing what to scan

| | |
| --- | --- |
| `secrets-scan [PATH...]` | walk the directories (default `.`), skipping `.git`, `node_modules`, binary files, lock files, `*.min.js` and source maps |
| `--git` | only the files `git ls-files` lists |
| `--staged` | the content staged in git's index - for a pre-commit hook |
| `--diff REF` | only the lines added since `REF` (e.g. `origin/main`) - for pull requests |
| `--stdin` | text piped in (`--stdin-filename NAME` to label it) |
| `--include GLOB`, `--exclude GLOB` | restrict the files; `vendor`, `*.snap` match names anywhere, `docs/gen` is anchored, `**` crosses directories |
| `--max-size 1M` | skip bigger files (reported in the summary) |
| `--no-default-skips` | scan lock files, minified bundles and source maps too |

UTF-16 files (as written by PowerShell) are decoded; binary files are skipped.
Unreadable files and directories are warnings, never silence; `--verbose` lists everything skipped.

## What it detects

`secrets-scan --list-rules` lists them, `--explain RULE` describes one.

* **Provider credentials** (severity high): AWS access key ids, GitHub tokens, Slack tokens and
  webhooks, Stripe, Google API keys and service account files, npm, PyPI, SendGrid, Twilio,
  Mailgun, Shopify, DigitalOcean, Databricks, Sentry, Square, Discord webhooks, Azure storage
  keys, private key blocks, passwords in URLs.
* **Generic** (medium): `password = "..."`-style assignments, JSON Web Tokens whose header
  decodes, and high-entropy strings.

Choose rules with `--only ID` / `--disable ID`; `--min-severity medium` hides the rest.

### Keeping false positives low

* Placeholders are ignored: `changeme`, `your_password_here`, `xxxxxxxx`, `${DB_PASSWORD}`,
  `process.env.TOKEN`, `{{ vault_password }}`, the `...EXAMPLE` keys from AWS's documentation.
* Identifier-like values (`validation_failed_message`) are not passwords.
* The entropy detector skips UUIDs, `sha512-...` integrity hashes and inline base64 data, only
  reports hex strings after a word like `secret`, `token` or `key`, and requires other tokens to mix
  lower case, upper case and digits. The price is that a random hex string with no hint around it
  is not found.
* Minified lines longer than `--max-line-length` only get the specific rules.

## Silencing findings

In the file itself, in whatever comment syntax it uses:

    const key = "AKIAIOSFODNN7EXAMPLE"; // secrets-scan:ignore
    # secrets-scan:ignore-next-line
    password = "not-a-real-password"

(`secrets-scan:ignore-file` anywhere skips the whole file.) For everything else use
`.secrets-allowlist` (or `--allowlist FILE`), one entry per line:

    path: docs/examples/**                      # every finding in these files
    regex: ^AKIAIOSFODNN7EXAMPLE$               # findings whose secret text matches
    rule: generic-secret-assignment @ test/**   # one rule, optionally only in some files
    fingerprint: 3fa9c1d2e4b5a6978c0d1e2f3a4b5c6d   # one finding, from --format json
    path: legacy/**   expires=2026-12-31        # temporary: stops applying after the date

## Adopting it on an existing project: baselines

    secrets-scan --write-baseline .secrets-baseline.json     # record what exists today
    secrets-scan --baseline .secrets-baseline.json            # fail only on new findings

The baseline holds hashes (rule, path, secret), never the secrets; it survives line number
changes, and the summary tells you when entries have gone stale. Or skip baselines and scan
only new lines: `secrets-scan --diff origin/main`.

## Output

`--format text` (default), `json`, `sarif` (GitHub code scanning, IDEs) or `github` (annotations in
a workflow run). `--output FILE` writes the report to a file; the summary line goes to stderr
(`--quiet` drops it). `--color auto|always|never` honours `NO_COLOR`.

## CI and hooks

* Pre-commit: [examples/pre-commit](examples/pre-commit) runs `secrets-scan --staged`.
* Pull requests: [examples/github-actions.yml](examples/github-actions.yml) annotates added lines.
* Whole repository: `npx secrets-scan --git --min-severity medium`.

## Limits

Only the current content is scanned, not git history. Patterns cover the formats the providers
document; custom or rotated formats need a rule of their own (or the entropy detector). A secret
split over several lines is only found if its first line matches.

## Development

    npm test

The tests build their fake credentials from pieces (`test/fakes.js`), so scanning this repository
finds nothing; CI runs `secrets-scan --git` on itself.
