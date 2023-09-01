import fs from "node:fs";

import { looksBinary } from "./walk.js";

/**
 * Scan text and return the findings, one per matching line and rule.
 * Positions are 1-based.
 */
export function scanText(text, filePath, rules) {
  const findings = [];
  const lines = text.split(/\r\n|\n|\r/);
  lines.forEach((line, index) => {
    for (const rule of rules) {
      const match = rule.pattern.exec(line);
      if (!match) continue;
      const secret = match[rule.group ?? 0];
      const column = match.index + match[0].indexOf(secret) + 1;
      findings.push({
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
  });
  return findings;
}

/** Read and scan one file; returns [] for binary files. */
export function scanFile(absolutePath, relativePath, rules) {
  const buffer = fs.readFileSync(absolutePath);
  if (looksBinary(buffer)) return [];
  return scanText(buffer.toString("utf8"), relativePath, rules);
}
