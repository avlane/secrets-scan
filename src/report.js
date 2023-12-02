/** Replace most of a secret with asterisks so reports can be shared. */
export function redact(secret) {
  if (secret.length <= 8) return "*".repeat(secret.length);
  return secret.slice(0, 4) + "*".repeat(Math.min(secret.length - 4, 12));
}

/** What to print for a finding's secret: masked unless the user asked to see it. */
export function display(secret, showSecrets) {
  return showSecrets ? secret : redact(secret);
}

export function summarize(findings) {
  const bySeverity = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;
  return { total: findings.length, bySeverity };
}

export function formatJson(findings, { showSecrets = false, version = "0.0.0" } = {}) {
  const document = {
    version: 1,
    tool: { name: "secrets-scan", version },
    summary: summarize(findings),
    findings: findings.map((f) => ({
      rule: f.ruleId,
      severity: f.severity,
      message: f.message,
      path: f.path,
      line: f.line,
      column: f.column,
      endColumn: f.endColumn,
      match: display(f.secret, showSecrets),
      fingerprint: f.fingerprint,
    })),
  };
  return JSON.stringify(document, null, 2) + "\n";
}

export function formatText(findings, { showSecrets = false } = {}) {
  if (findings.length === 0) return "";
  return findings
    .map((f) => `${f.path}:${f.line}:${f.column}  ${f.ruleId}  [${f.severity}]  ${f.message}: ${display(f.secret, showSecrets)}\n`)
    .join("");
}
