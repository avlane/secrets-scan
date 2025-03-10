import fs from "node:fs";

import { compileGlob } from "./glob.js";

export const DEFAULT_ALLOWLIST_NAME = ".secrets-allowlist";

/**
 * An allowlist says which findings are fine. One entry per line, "#" starts a comment:
 *
 *     path: docs/examples/**                  # every finding in these files
 *     regex: ^AKIAIOSFODNN7EXAMPLE$           # findings whose secret text matches
 *     rule: generic-secret-assignment @ test/**   # one rule, optionally only in some files
 *     fingerprint: 3fa9c1...                  # one specific finding (see --format json)
 *
 * Any entry can end with `expires=YYYY-MM-DD`: after that day it stops applying, so
 * temporary exceptions cannot be forgotten.
 */
export function parseAllowlist(text, source = DEFAULT_ALLOWLIST_NAME, now = new Date()) {
  const allowlist = emptyAllowlist();
  text.split(/\r?\n/).forEach((raw, index) => {
    let line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (line === "") return;
    const where = `${source}:${index + 1}`;

    const expiry = /\s+expires=(\S+)$/.exec(line);
    if (expiry) {
      line = line.slice(0, expiry.index).trim();
      const end = new Date(`${expiry[1]}T23:59:59Z`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(expiry[1]) || Number.isNaN(end.getTime())) {
        throw new Error(`${where}: expires= needs a date like 2026-01-31, got "${expiry[1]}"`);
      }
      if (now > end) {
        allowlist.expired.push({ where, entry: line, date: expiry[1] });
        return;
      }
    }

    const colon = line.indexOf(":");
    const kind = colon < 0 ? "" : line.slice(0, colon).trim();
    const value = colon < 0 ? "" : line.slice(colon + 1).trim();
    if (value === "") throw new Error(`${where}: expected "kind: value", got "${line}"`);
    switch (kind) {
      case "path":
        allowlist.paths.push(compileGlob(value));
        break;
      case "regex":
        try {
          allowlist.regexes.push(new RegExp(value));
        } catch (error) {
          throw new Error(`${where}: invalid regular expression: ${error.message}`);
        }
        break;
      case "rule": {
        const [id, glob] = value.split(/\s+@\s+/);
        allowlist.rules.push({ id: id.trim(), glob: glob ? compileGlob(glob.trim()) : null, where });
        break;
      }
      case "fingerprint":
        if (!/^[0-9a-f]{32}$/.test(value)) throw new Error(`${where}: a fingerprint is 32 hex digits`);
        allowlist.fingerprints.add(value);
        break;
      default:
        throw new Error(`${where}: unknown entry "${kind}" (use path, regex, rule or fingerprint)`);
    }
  });
  return allowlist;
}

function emptyAllowlist() {
  return { paths: [], regexes: [], rules: [], fingerprints: new Set(), expired: [] };
}

export function loadAllowlist(file, source = file, now) {
  return parseAllowlist(fs.readFileSync(file, "utf8"), source, now);
}

export const EMPTY_ALLOWLIST = emptyAllowlist();

export function isAllowed(finding, allowlist) {
  if (allowlist.fingerprints.has(finding.fingerprint)) return true;
  if (allowlist.paths.some((glob) => glob.test(finding.path))) return true;
  if (allowlist.rules.some((rule) => rule.id === finding.ruleId && (!rule.glob || rule.glob.test(finding.path)))) return true;
  return allowlist.regexes.some((regex) => regex.test(finding.secret));
}
