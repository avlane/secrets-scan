/** Replace most of a secret with asterisks so reports can be shared. */
export function redact(secret) {
  if (secret.length <= 8) return "*".repeat(secret.length);
  return secret.slice(0, 4) + "*".repeat(Math.min(secret.length - 4, 12));
}

export function formatText(findings) {
  if (findings.length === 0) return "";
  return findings
    .map((f) => `${f.path}:${f.line}:${f.column}  ${f.ruleId}  [${f.severity}]  ${f.message}: ${redact(f.secret)}\n`)
    .join("");
}
