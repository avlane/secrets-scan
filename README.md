# secrets-scan

Scan a directory (or the files tracked by git) for likely secrets: API keys, tokens,
private keys and high-entropy strings. No dependencies, nothing leaves your machine.

Work in progress. Planned: provider-specific patterns, an entropy detector, an allowlist
file, baselines for existing findings, and JSON / SARIF output.
