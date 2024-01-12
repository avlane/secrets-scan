import fs from "node:fs";

import { compileGlob } from "./glob.js";

export const DEFAULT_ALLOWLIST_NAME = ".secrets-allowlist";

/**
 * An allowlist says which findings are fine. One entry per line, "#" starts a comment:
 *
 *     path: docs/examples/**         # ignore everything in these files
 *     regex: ^AKIAIOSFODNN7EXAMPLE$  # ignore secrets whose text matches
 */
export function parseAllowlist(text, source = DEFAULT_ALLOWLIST_NAME) {
  const allowlist = { paths: [], regexes: [] };
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (line === "") return;
    const colon = line.indexOf(":");
    const kind = colon < 0 ? "" : line.slice(0, colon).trim();
    const value = colon < 0 ? "" : line.slice(colon + 1).trim();
    const where = `${source}:${index + 1}`;
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
      default:
        throw new Error(`${where}: unknown entry "${kind}" (use path or regex)`);
    }
  });
  return allowlist;
}

export function loadAllowlist(file) {
  return parseAllowlist(fs.readFileSync(file, "utf8"), file);
}

export const EMPTY_ALLOWLIST = { paths: [], regexes: [] };

export function isAllowed(finding, allowlist) {
  if (allowlist.paths.some((glob) => glob.test(finding.path))) return true;
  return allowlist.regexes.some((regex) => regex.test(finding.secret));
}
