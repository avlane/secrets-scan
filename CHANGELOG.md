# Changelog

## 1.0.0

First stable release. The command line, exit statuses (0 clean, 1 findings, 2 error), the
JSON and SARIF report layouts and the allowlist / baseline file formats are now stable.

Highlights of 0.x:

- Rules for the common providers, private keys, JWTs, passwords in URLs, hard-coded credential
  assignments and a Shannon entropy detector, tuned to keep false positives low.
- Sources: directories, `--git`, `--staged`, `--diff REF`, `--stdin`; UTF-16 files; large files and
  very long lines handled.
- Allowlist (paths, regexes, rules, fingerprints, expiry dates), inline `secrets-scan:ignore`
  comments and baselines.
- Output: text, JSON, SARIF, GitHub annotations; `--output FILE`.
- Requires Node.js 20 or newer (18 until May 2025).
