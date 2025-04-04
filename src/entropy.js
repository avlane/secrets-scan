/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(text) {
  if (text.length === 0) return 0;
  const counts = new Map();
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const DEFAULT_LIMITS = { hex: 3.0, base64: 4.5, minLength: 20 };

const HEX = /^[0-9a-fA-F]+$/;
const BASE64 = /^[A-Za-z0-9+/_=-]+$/;

/** "hex", "base64" or null for text that is neither. */
export function charsetOf(token) {
  if (HEX.test(token)) return "hex";
  if (BASE64.test(token)) return "base64";
  return null;
}

export function isHighEntropy(token, limits = DEFAULT_LIMITS) {
  if (token.length < limits.minLength) return false;
  const charset = charsetOf(token);
  if (charset === null) return false;
  return shannonEntropy(token) > limits[charset];
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INTEGRITY = /^sha(?:1|256|384|512)-/;

/**
 * Text that has the shape of a secret but is known not to be one: UUIDs, the
 * "sha512-..." integrity hashes of package managers and inline base64 data.
 */
export function isKnownNonSecret(token, line, index) {
  if (UUID.test(token) || INTEGRITY.test(token) || token.includes("EXAMPLE")) return true;
  return line.slice(Math.max(0, index - 8), index).endsWith("base64,");
}

// Candidate tokens: runs of base64/hex characters between quotes, spaces, = or :.
const CANDIDATE = /(?<=["'`=:\s(,]|^)([A-Za-z0-9+/_-]{20,}={0,2})(?=["'`\s),;]|$)/g;

// Words that suggest the text after them is a credential.
const SECRET_CONTEXT = /secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|apikey|auth|credential|private[_-]?key|salt|signature|bearer|access[_-]?key|\bkeys?\b/i;

export function hasSecretContext(line, index) {
  return SECRET_CONTEXT.test(line.slice(0, index));
}

/** How many of lower case, upper case and digits (or symbols) the token uses. */
function characterClasses(token) {
  return [/[a-z]/, /[A-Z]/, /[0-9]/].filter((pattern) => pattern.test(token)).length;
}

/**
 * Yield {token, index} for every high-entropy token on a line.
 *
 * Plain high entropy is a weak signal: git commit ids, content hashes, ObjectIds and
 * long identifiers all have it. Without a nearby word like "secret", "token" or
 * "key", a token is only reported if it is not hex (hashes, ids) and uses lower
 * case, upper case and digits like generated credentials do.
 */
export function* findHighEntropyStrings(line, limits = DEFAULT_LIMITS) {
  for (const match of line.matchAll(CANDIDATE)) {
    const token = match[1];
    if (!isHighEntropy(token, limits) || isKnownNonSecret(token, line, match.index)) continue;
    if (!hasSecretContext(line, match.index)) {
      if (charsetOf(token) === "hex") continue;
      if (characterClasses(token) < 3) continue;
    }
    yield { token, index: match.index };
  }
}
