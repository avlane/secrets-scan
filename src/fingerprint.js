import { createHash } from "node:crypto";

/**
 * A stable identity for a finding that does not depend on its line number: the rule,
 * the file and the secret itself, hashed so that baselines never store the secret.
 */
export function fingerprint(ruleId, filePath, secret) {
  return createHash("sha256").update(`${ruleId}\0${filePath}\0${secret}`).digest("hex").slice(0, 32);
}
