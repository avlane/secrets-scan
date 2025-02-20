import fs from "node:fs";

/**
 * A baseline records the findings that already exist, so that a project can adopt the
 * scanner today and only fail on new secrets. It stores fingerprints (hashes), never the
 * secrets themselves.
 */
export function createBaseline(findings) {
  const entries = findings
    .map((f) => ({ fingerprint: f.fingerprint, rule: f.ruleId, path: f.path, line: f.line }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line));
  return { version: 1, findings: entries };
}

export function writeBaseline(file, findings) {
  fs.writeFileSync(file, JSON.stringify(createBaseline(findings), null, 2) + "\n");
}

export function readBaseline(file) {
  let document;
  try {
    document = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`cannot read baseline ${file}: ${error instanceof SyntaxError ? "not valid JSON" : error.message}`);
  }
  if (document?.version !== 1 || !Array.isArray(document.findings)) {
    throw new Error(`cannot read baseline ${file}: not a secrets-scan baseline (version 1)`);
  }
  return document;
}

/**
 * Split findings into those that are new and those the baseline already knows. Each
 * baseline entry covers one finding, so a second copy of the same secret in the same
 * file is new. `stale` counts baseline entries that match nothing any more (the
 * secret was removed or moved), a hint to refresh the file.
 */
export function applyBaseline(findings, baseline) {
  const remaining = new Map();
  for (const entry of baseline.findings) {
    remaining.set(entry.fingerprint, (remaining.get(entry.fingerprint) ?? 0) + 1);
  }
  const fresh = [];
  const known = [];
  for (const finding of findings) {
    const left = remaining.get(finding.fingerprint) ?? 0;
    if (left > 0) {
      remaining.set(finding.fingerprint, left - 1);
      known.push(finding);
    } else {
      fresh.push(finding);
    }
  }
  let stale = 0;
  for (const left of remaining.values()) stale += left;
  return { fresh, known, stale };
}
