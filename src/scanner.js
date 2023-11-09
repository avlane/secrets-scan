import fs from "node:fs";

import { findHighEntropyStrings } from "./entropy.js";
import { looksBinary } from "./walk.js";

const ENTROPY_RULE_ID = "high-entropy-string";

/**
 * Scan text and return the findings, one per matching line and rule.
 * Positions are 1-based.
 */
export function scanText(text, filePath, rules, { entropy = true } = {}) {
  const findings = [];
  const lines = text.split(/\r\n|\n|\r/);
  lines.forEach((line, index) => {
    const lineFindings = [];
    for (const rule of rules) {
      const match = rule.pattern.exec(line);
      if (!match) continue;
      const secret = match[rule.group ?? 0];
      if (rule.validate && !rule.validate(secret, line)) continue;
      const column = match.index + match[0].indexOf(secret) + 1;
      lineFindings.push({
        ruleId: rule.id,
        severity: rule.severity,
        message: rule.description,
        path: filePath,
        line: index + 1,
        column,
        endColumn: column + secret.length,
        secret,
      });
    }
    if (entropy) {
      for (const { token, index: offset } of findHighEntropyStrings(line)) {
        const column = offset + 1;
        const endColumn = column + token.length;
        // A provider rule already explained this text.
        if (lineFindings.some((f) => f.column < endColumn && column < f.endColumn)) continue;
        lineFindings.push({
          ruleId: ENTROPY_RULE_ID,
          severity: "medium",
          message: "High-entropy string",
          path: filePath,
          line: index + 1,
          column,
          endColumn,
          secret: token,
        });
      }
    }
    findings.push(...lineFindings);
  });
  return findings;
}

/** Read and scan one file; returns [] for binary files. */
export function scanFile(absolutePath, relativePath, rules, options) {
  const buffer = fs.readFileSync(absolutePath);
  if (looksBinary(buffer)) return [];
  return scanText(buffer.toString("utf8"), relativePath, rules, options);
}
