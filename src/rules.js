/**
 * Detection rules.
 *
 * A rule has an `id`, a `severity` (high, medium or low), a human readable
 * `description`, and a `pattern` that is matched against one line at a time.
 * `group` says which capture group holds the secret itself (default: the whole match).
 * An optional `validate(secret, line)` can reject a match, e.g. a placeholder value.
 */
const PLACEHOLDER_WORDS = [
  "example", "changeme", "change_me", "change-me", "placeholder", "your_", "your-", "dummy",
  "sample", "redacted", "todo", "fixme",
];

/** Values that obviously are not real credentials: examples, masks, repeated characters. */
export function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_WORDS.some((word) => lower.includes(word))) return true;
  if (/^(.)\1+$/.test(value)) return true;
  if (/^[*#x.-]+$/i.test(value)) return true;
  // snake_case, kebab-case or dotted words: translation keys and identifiers, not passwords
  if (/^[a-z]+(?:[_.-][a-z]+)+$/.test(value)) return true;
  return false;
}

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
  {
    id: "slack-token",
    description: "Slack token",
    severity: "high",
    pattern: /\b(xox[abprs]-[A-Za-z0-9-]{10,72})\b/,
    group: 1,
  },
  {
    id: "slack-webhook",
    description: "Slack incoming webhook URL",
    severity: "high",
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{20,})/,
    group: 1,
  },
  {
    id: "generic-secret-assignment",
    description: "Hard-coded credential",
    severity: "medium",
    pattern: /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i,
    group: 1,
    validate: (value) => !looksLikePlaceholder(value),
  },
];
export const ENTROPY_RULE = {
  id: "high-entropy-string",
  description: "High-entropy string",
  severity: "medium",
};

/** Every rule that can produce a finding, for reports that describe them (SARIF). */
export function ruleCatalog() {
  return [...RULES, ENTROPY_RULE].map(({ id, description, severity }) => ({ id, description, severity }));
}
