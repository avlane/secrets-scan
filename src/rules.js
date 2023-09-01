/**
 * Detection rules.
 *
 * A rule has an `id`, a `severity` (high, medium or low), a human readable
 * `description`, and a `pattern` that is matched against one line at a time.
 * `group` says which capture group holds the secret itself (default: the whole match).
 */
export const RULES = [
  {
    id: "aws-access-key-id",
    description: "AWS access key ID",
    severity: "high",
    pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b/,
    group: 1,
  },
  {
    id: "private-key",
    description: "Private key block",
    severity: "high",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
  },
  {
    id: "github-token",
    description: "GitHub token",
    severity: "high",
    pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/,
    group: 1,
  },
];
