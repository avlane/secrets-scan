import fs from "node:fs";

import { findHighEntropyStrings } from "./entropy.js";
import { fingerprint } from "./fingerprint.js";
import { looksBinary } from "./walk.js";

const ENTROPY_RULE_ID = "high-entropy-string";

// Comments that silence findings. Put them in whatever comment syntax the file uses:
//   const key = "..."; // secrets-scan:ignore
//   # secrets-scan:ignore-next-line
//   secrets-scan:ignore-file   (anywhere in the file)
const IGNORE_LINE = "secrets-scan:ignore";
const IGNORE_NEXT_LINE = "secrets-scan:ignore-next-line";
const IGNORE_FILE = "secrets-scan:ignore-file";

/**
 * Scan text and return the findings, one per matching line and rule.
 * Positions are 1-based.
 */
export function scanText(text, filePath, rules, { entropy = true } = {}) {
  const findings = [];
  if (text.includes(IGNORE_FILE)) return findings;
  const lines = text.split(/\r\n|\n|\r/);
  let ignoreNext = false;
  lines.forEach((line, index) => {
    if (line.includes(IGNORE_NEXT_LINE)) {
      ignoreNext = true;
      return;
    }
    if (ignoreNext) {
      ignoreNext = false;
      return;
    }
    if (line.includes(IGNORE_LINE)) return;
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
        fingerprint: fingerprint(rule.id, filePath, secret),
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
          fingerprint: fingerprint(ENTROPY_RULE_ID, filePath, token),
        });
      }
    }
    findings.push(...lineFindings);
  });
  return findings;
}

/** Scan the bytes of a file; returns [] for binary content. */
export function scanBuffer(buffer, relativePath, rules, options) {
  if (looksBinary(buffer)) return [];
  return scanText(buffer.toString("utf8"), relativePath, rules, options);
}

/** Read and scan one file. */
export function scanFile(absolutePath, relativePath, rules, options) {
  return scanBuffer(fs.readFileSync(absolutePath), relativePath, rules, options);
}
