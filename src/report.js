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

const ANSI = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m",
};

function paint(text, style, enabled) {
  return enabled ? `${ANSI[style]}${text}${ANSI.reset}` : text;
}

/** Colors on when asked for, or when writing to a terminal and NO_COLOR is not set. */
export function useColor(mode, stream, env) {
  if (mode === "always") return true;
  if (mode === "never" || env.NO_COLOR) return false;
  return Boolean(stream.isTTY);
}

const SARIF_LEVEL = { high: "error", medium: "warning", low: "note" };
const SARIF_SEVERITY = { high: "8.0", medium: "5.0", low: "3.0" };

/**
 * SARIF 2.1.0, the format GitHub code scanning and most IDE viewers understand.
 * Messages never contain the secret; the fingerprint lets viewers track a finding
 * across commits.
 */
export function formatSarif(findings, { version = "0.0.0", catalog = [] } = {}) {
  const indexOf = new Map(catalog.map((rule, index) => [rule.id, index]));
  const document = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "secrets-scan",
          version,
          rules: catalog.map((rule) => ({
            id: rule.id,
            name: rule.id,
            shortDescription: { text: rule.description },
            defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
            properties: { "security-severity": SARIF_SEVERITY[rule.severity] },
          })),
        },
      },
      results: findings.map((f) => ({
        ruleId: f.ruleId,
        ...(indexOf.has(f.ruleId) ? { ruleIndex: indexOf.get(f.ruleId) } : {}),
        level: SARIF_LEVEL[f.severity],
        message: { text: `${f.message} found in ${f.path}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.path, uriBaseId: "%SRCROOT%" },
            region: { startLine: f.line, startColumn: f.column, endColumn: f.endColumn },
          },
        }],
        partialFingerprints: { "secretsScan/v1": f.fingerprint },
      })),
    }],
  };
  return JSON.stringify(document, null, 2) + "\n";
}

export function formatText(findings, { showSecrets = false, color = false } = {}) {
  if (findings.length === 0) return "";
  return findings
    .map((f) => {
      const where = paint(`${f.path}:${f.line}:${f.column}`, "bold", color);
      const severity = paint(`[${f.severity}]`, f.severity, color);
      return `${where}  ${f.ruleId}  ${severity}  ${f.message}: ${paint(display(f.secret, showSecrets), "dim", color)}\n`;
    })
    .join("");
}

/** One line for stderr: how much was scanned and what was found. */
export function formatSummary(findings, filesScanned, { baselined = 0, skippedLarge = 0, stale = 0 } = {}) {
  const files = `${filesScanned} file${filesScanned === 1 ? "" : "s"}`;
  const known = (baselined > 0 ? `; ${baselined} known in the baseline ignored` : "")
    + (skippedLarge > 0 ? `; ${skippedLarge} larger than --max-size skipped` : "")
    + (stale > 0 ? `; ${stale} baseline ${stale === 1 ? "entry" : "entries"} no longer match (refresh with --write-baseline)` : "");
  if (findings.length === 0) {
    const none = baselined > 0 ? "no new secrets found" : "no secrets found";
    return `secrets-scan: ${none} (scanned ${files}${known})\n`;
  }
  const { bySeverity } = summarize(findings);
  const parts = ["high", "medium", "low"].filter((s) => bySeverity[s] > 0).map((s) => `${bySeverity[s]} ${s}`);
  const filesWithFindings = new Set(findings.map((f) => f.path)).size;
  const noun = findings.length === 1 ? "potential secret" : "potential secrets";
  return `secrets-scan: ${findings.length} ${noun} in ${filesWithFindings} file${filesWithFindings === 1 ? "" : "s"} (${parts.join(", ")}); scanned ${files}${known}\n`;
}
