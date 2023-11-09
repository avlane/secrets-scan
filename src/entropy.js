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

// Candidate tokens: runs of base64/hex characters between quotes, spaces, = or :.
const CANDIDATE = /(?<=["'`=:\s(,]|^)([A-Za-z0-9+/_=-]{20,})(?=["'`\s),;]|$)/g;

/** Yield {token, index} for every high-entropy token on a line. */
export function* findHighEntropyStrings(line, limits = DEFAULT_LIMITS) {
  for (const match of line.matchAll(CANDIDATE)) {
    if (isHighEntropy(match[1], limits)) yield { token: match[1], index: match.index };
  }
}
