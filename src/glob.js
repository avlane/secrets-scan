/**
 * Path globs, in the spirit of .gitignore.
 *
 * - A pattern without "/" matches the name of any file or directory ("*.min.js", "dist").
 * - A pattern with "/" is anchored at the scan root ("docs/generated", "src/**\/*.snap"),
 *   and also matches everything below a directory it names.
 * - "*" and "?" do not cross "/", "**" does. A trailing "/" restricts a pattern to directories.
 */
function translate(pattern) {
  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const char = pattern[i];
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        i += 2;
        if (pattern[i] === "/") {
          i += 1;
          out += "(?:.*/)?";
        } else {
          out += ".*";
        }
      } else {
        i += 1;
        out += "[^/]*";
      }
    } else if (char === "?") {
      i += 1;
      out += "[^/]";
    } else if (char === "[") {
      const end = pattern.indexOf("]", i + 2);
      if (end < 0) {
        out += "\\[";
        i += 1;
      } else {
        let body = pattern.slice(i + 1, end).replace(/\\/g, "\\\\");
        if (body.startsWith("!")) body = "^" + body.slice(1);
        out += `[${body}]`;
        i = end + 1;
      }
    } else {
      out += char.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
      i += 1;
    }
  }
  return out;
}

export function compileGlob(text) {
  let pattern = text.trim();
  // "./vendor" and "./**/*.snap" mean the same as "vendor" and "**/*.snap" relative to the root
  while (pattern.startsWith("./")) pattern = pattern.slice(2);
  if (pattern === "") return null;
  const directoryOnly = pattern.endsWith("/");
  if (directoryOnly) pattern = pattern.slice(0, -1);
  const anchored = pattern.includes("/");
  pattern = pattern.replace(/^\//, "");
  const source = translate(pattern);
  if (anchored) {
    const regex = new RegExp(`^${source}(?:/.*)?$`);
    return { text, test: (relativePath) => regex.test(relativePath) };
  }
  const regex = new RegExp(`^${source}$`);
  return {
    text,
    test(relativePath, isDirectory = false) {
      const segments = relativePath.split("/");
      // For a directory-only pattern the last segment of a file path is not a directory.
      const limit = directoryOnly && !isDirectory ? segments.length - 1 : segments.length;
      return segments.slice(0, limit).some((segment) => regex.test(segment));
    },
  };
}

/** A matcher for a list of glob patterns; `matches(path, isDirectory)` is true if any matches. */
export function createMatcher(patterns) {
  const globs = patterns.map(compileGlob).filter(Boolean);
  return {
    size: globs.length,
    matches: (relativePath, isDirectory = false) => globs.some((g) => g.test(relativePath, isDirectory)),
  };
}
