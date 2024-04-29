import fs from "node:fs";
import path from "node:path";

export const DEFAULT_IGNORED_DIRS = [".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv"];

// Files with these extensions are never text, so they are skipped without being read.
const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz",
  ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".woff", ".woff2", ".ttf", ".otf",
  ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wasm", ".so", ".dll", ".exe", ".dylib", ".o",
  ".a", ".pyc",
]);

// Generated files are full of hashes and long tokens that are not secrets.
export const DEFAULT_SKIPPED_FILES = [
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
  "Cargo.lock", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum",
  "*.min.js", "*.min.css", "*.map", ".secrets-baseline.json",
];

export function hasBinaryExtension(file) {
  return BINARY_EXTENSIONS.has(path.extname(file).toLowerCase());
}

/** A NUL byte in the first 8 KB is a reliable sign of a binary file. */
export function looksBinary(buffer) {
  return buffer.subarray(0, 8000).includes(0);
}

/**
 * Yield the path of every regular file below `root`, in a stable order.
 * Symbolic links are not followed. `exclude` and `include` are glob matchers (see
 * glob.js): excluded directories are not entered, and when `include` is given only
 * the files it matches are yielded.
 */
export function* walk(root, { ignoredDirs = DEFAULT_IGNORED_DIRS, include = null, exclude = null } = {}) {
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const subdirs = [];
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const relative = path.relative(root, full).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (ignoredDirs.includes(entry.name)) continue;
        if (exclude?.matches(relative, true)) continue;
        subdirs.push(full);
      } else if (entry.isFile()) {
        if (exclude?.matches(relative)) continue;
        if (include && include.size > 0 && !include.matches(relative)) continue;
        yield full;
      }
    }
    for (const subdir of subdirs.reverse()) stack.push(subdir);
  }
}
