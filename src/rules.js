/**
 * Detection rules.
 *
 * A rule has an `id`, a `severity` (high, medium or low), a human readable
 * `description`, and a `pattern` that is matched against one line at a time.
 * `group` says which capture group holds the secret itself (default: the whole match).
 * An optional `validate(secret, line)` can reject a match, e.g. a placeholder value.
 * `slow` rules are skipped on very long lines (minified code, data blobs).
 */
const PLACEHOLDER_WORDS = [
  "example", "changeme", "change_me", "change-me", "placeholder", "your_", "your-", "dummy",
  "sample", "redacted", "todo", "fixme",
];

// Syntax for "the value comes from somewhere else": ${VAR}, $VAR, $(cmd), {{ var }}, <value>,
// %(name)s, %s, process.env.X, os.environ[...], ENV["X"], getenv(...)
const TEMPLATE_REFERENCE = /^\s*(?:\$\{.*\}|\$\(.*\)|\$[A-Za-z_]\w*|\{\{.*\}\}|<[^>]*>|%\(\w+\)s|%[sd]|\[[^\]]*\])\s*$|process\.env|os\.environ|\bENV\[|getenv\(|\bsecrets\.\w+/;

/** Values that obviously are not real credentials: examples, masks, repeated characters, references. */
export function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_WORDS.some((word) => lower.includes(word))) return true;
  if (TEMPLATE_REFERENCE.test(value)) return true;
  if (/x{4,}/i.test(value) || /\*{3,}/.test(value)) return true;
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) return true; // MY_ENV_VARIABLE_NAME
  if (/^(.)\1+$/.test(value)) return true;
  if (/^[*#x.-]+$/i.test(value)) return true;
  // snake_case, kebab-case or dotted words: translation keys and identifiers, not passwords
  if (/^[a-z]+(?:[_.-][a-z]+)+$/.test(value)) return true;
  return false;
}

const DUMMY_PASSWORDS = new Set(["password", "pass", "passwd", "secret", "user", "admin", "root", "test", "guest", "pwd"]);
const TEMPLATE_START = /^[$<{%]/;

export const SEVERITIES = ["low", "medium", "high"];

export const RULES = [
  {
    id: "aws-access-key-id",
    description: "AWS access key ID",
    severity: "high",
    pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b/,
    group: 1,
    // The keys printed in AWS's own documentation all end in EXAMPLE.
    validate: (key) => !key.endsWith("EXAMPLE"),
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
    id: "stripe-key",
    description: "Stripe live API key",
    severity: "high",
    pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b/,
    group: 1,
  },
  {
    id: "stripe-webhook-secret",
    description: "Stripe webhook signing secret",
    severity: "high",
    pattern: /\b(whsec_[0-9a-zA-Z]{32,})\b/,
    group: 1,
  },
  {
    id: "google-api-key",
    description: "Google API key",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/,
    group: 1,
  },
  {
    id: "gcp-service-account",
    description: "Google Cloud service account key file",
    severity: "high",
    pattern: /("type"\s*:\s*"service_account")/,
    group: 1,
  },
  {
    id: "npm-token",
    description: "npm access token",
    severity: "high",
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/,
    group: 1,
  },
  {
    id: "sendgrid-key",
    description: "SendGrid API key",
    severity: "high",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/,
    group: 1,
  },
  {
    id: "twilio-api-key",
    description: "Twilio API key",
    severity: "high",
    pattern: /\b(SK[0-9a-f]{32})\b/,
    group: 1,
  },
  {
    id: "mailgun-key",
    description: "Mailgun API key",
    severity: "high",
    pattern: /\b(key-[0-9a-f]{32})\b/,
    group: 1,
  },
  {
    id: "pypi-token",
    description: "PyPI upload token",
    severity: "high",
    pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})(?![A-Za-z0-9_-])/,
    group: 1,
  },
  {
    id: "shopify-token",
    description: "Shopify access token",
    severity: "high",
    pattern: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/,
    group: 1,
  },
  {
    id: "digitalocean-token",
    description: "DigitalOcean personal access token",
    severity: "high",
    pattern: /\b(dop_v1_[a-f0-9]{64})\b/,
    group: 1,
  },
  {
    id: "databricks-token",
    description: "Databricks access token",
    severity: "high",
    pattern: /\b(dapi[a-h0-9]{32})\b/,
    group: 1,
  },
  {
    id: "sentry-auth-token",
    description: "Sentry auth token",
    severity: "high",
    pattern: /\b(sntrys_[A-Za-z0-9+/=_-]{40,})/,
    group: 1,
  },
  {
    id: "square-token",
    description: "Square access token or OAuth secret",
    severity: "high",
    pattern: /\b(sq0(?:atp|csp)-[0-9A-Za-z_-]{22,43})(?![0-9A-Za-z_-])/,
    group: 1,
  },
  {
    id: "discord-webhook",
    description: "Discord webhook URL",
    severity: "high",
    pattern: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,})/,
    group: 1,
  },
  {
    id: "azure-storage-key",
    description: "Azure storage account key",
    severity: "high",
    pattern: /AccountKey=([A-Za-z0-9+/]{86}==)/,
    group: 1,
  },
  {
    id: "jwt",
    description: "JSON Web Token",
    severity: "medium",
    pattern: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])/,
    group: 1,
    // The header must decode to JSON with an "alg" member, which random text rarely does.
    validate: (token) => {
      try {
        const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
        return typeof header.alg === "string";
      } catch {
        return false;
      }
    },
  },
  {
    id: "url-credentials",
    description: "Password in a URL",
    severity: "high",
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:([^\s@/'"]{3,})@[^\s/'"]+/gi,
    group: 1,
    validate: (password) => !looksLikePlaceholder(password) && !TEMPLATE_START.test(password) && !DUMMY_PASSWORDS.has(password.toLowerCase()),
  },
  {
    id: "generic-secret-assignment",
    description: "Hard-coded credential",
    severity: "medium",
    pattern: /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i,
    group: 1,
    validate: (value) => !looksLikePlaceholder(value),
    slow: true,
  },
];
/**
 * The rules to run for `--only` / `--disable` (lists of rule ids), and whether the
 * entropy detector is among them. Throws on an unknown id.
 */
export function selectRules({ only = [], disable = [] } = {}) {
  const known = new Set([...RULES.map((r) => r.id), ENTROPY_RULE.id]);
  for (const id of [...only, ...disable]) {
    if (!known.has(id)) throw new Error(`unknown rule '${id}' (see --list-rules)`);
  }
  const enabled = (id) => (only.length === 0 || only.includes(id)) && !disable.includes(id);
  return { rules: RULES.filter((rule) => enabled(rule.id)), entropy: enabled(ENTROPY_RULE.id) };
}

const VERIFY_FIRST = new Set(["generic-secret-assignment", "high-entropy-string", "jwt"]);

/** Text for `--explain RULE`, or null if there is no such rule. */
export function explainRule(id) {
  const rule = id === ENTROPY_RULE.id ? { ...ENTROPY_RULE, pattern: null } : RULES.find((r) => r.id === id);
  if (!rule) return null;
  const lines = [`${rule.id} (${rule.severity})`, `  ${rule.description}`, ""];
  if (rule.pattern) {
    lines.push("Matches:", `  ${rule.pattern}`, "");
  } else {
    lines.push(
      "Matches:",
      "  Quoted or assigned text of 20+ base64 or hex characters whose Shannon entropy is high",
      "  (hex above 3.0 bits per character, base64 above 4.5). Hex strings are only reported",
      "  after a word like secret, token or key; other tokens must mix upper case, lower case",
      "  and digits. UUIDs, package integrity hashes and inline base64 data are skipped.",
      "",
    );
  }
  lines.push("What to do:");
  if (VERIFY_FIRST.has(rule.id)) {
    lines.push("  Check whether the value is a real credential. If it is, move it to a secret manager or", "  an environment variable and rotate it; if it was ever pushed, treat it as leaked.");
  } else {
    lines.push("  Revoke the credential at the provider and issue a new one. Deleting it from the code", "  is not enough once it has been pushed or shared.");
  }
  lines.push(
    "",
    "If it is a false positive:",
    "  - this line:          add a comment containing  secrets-scan:ignore",
    `  - this rule in docs:  rule: ${rule.id} @ docs/**   (in .secrets-allowlist)`,
    "  - one finding:        fingerprint: <value from --format json>   (in .secrets-allowlist)",
    `  - this rule everywhere: --disable ${rule.id}`,
  );
  return lines.join("\n") + "\n";
}

export const ENTROPY_RULE = {
  id: "high-entropy-string",
  description: "High-entropy string",
  severity: "medium",
};

/** Every rule that can produce a finding, for reports that describe them (SARIF). */
export function ruleCatalog() {
  return [...RULES, ENTROPY_RULE].map(({ id, description, severity }) => ({ id, description, severity }));
}
