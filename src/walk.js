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

export function hasBinaryExtension(file) {
  return BINARY_EXTENSIONS.has(path.extname(file).toLowerCase());
}

/** A NUL byte in the first 8 KB is a reliable sign of a binary file. */
export function looksBinary(buffer) {
  return buffer.subarray(0, 8000).includes(0);
}

/**
 * Yield the path of every regular file below `root`, in a stable order.
 * Symbolic links are not followed.
 */
export function* walk(root, { ignoredDirs = DEFAULT_IGNORED_DIRS } = {}) {
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
      if (entry.isDirectory()) {
        if (!ignoredDirs.includes(entry.name)) subdirs.push(full);
      } else if (entry.isFile()) {
        yield full;
      }
    }
    for (const subdir of subdirs.reverse()) stack.push(subdir);
  }
}
