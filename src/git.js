import { execFileSync } from "node:child_process";

export class GitError extends Error {}

function git(cwd, args, name = args[0]) {
  try {
    return execFileSync("git", args, {
      cwd,
      maxBuffer: 512 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    if (error.code === "ENOENT") throw new GitError("git is not installed or not on the PATH");
    const detail = error.stderr?.toString().trim().split("\n")[0];
    throw new GitError(`git ${name} failed${detail ? `: ${detail}` : ""}`);
  }
}

function splitNul(buffer) {
  return buffer.toString("utf8").split("\0").filter((name) => name !== "");
}

/**
 * The lines added since `ref`, as Map(path -> Map(line number -> text)). Paths are relative
 * to the directory the diff was made in. Only added lines are listed: that is what a
 * pull request introduces.
 */
export function parseDiff(output) {
  const files = new Map();
  let current = null;
  let inHeader = false;
  let line = 0;
  for (const text of output.split("\n")) {
    if (text.startsWith("diff --git ")) {
      inHeader = true;
      current = null;
    } else if (inHeader && text.startsWith("+++ ")) {
      const name = text.slice(4).replace(/\t.*$/, "");
      current = name === "/dev/null" ? null : name.replace(/^b\//, "");
      if (current) files.set(current, new Map());
    } else if (text.startsWith("@@")) {
      inHeader = false;
      const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
      line = match ? Number(match[1]) : 0;
    } else if (!inHeader && current && text.startsWith("+")) {
      files.get(current).set(line, text.slice(1));
      line += 1;
    }
  }
  return files;
}

/** Lines added in the working tree and index since `ref` (e.g. "origin/main" or "HEAD"). */
export function addedLines(cwd, ref) {
  const output = git(cwd, [
    "-c", "core.quotepath=false", "diff", "--unified=0", "--no-color", "--no-ext-diff",
    "--relative", "--diff-filter=ACMR", ref, "--",
  ], "diff");
  return parseDiff(output.toString("utf8"));
}

/** Files added, copied, modified or renamed in the index, relative to `cwd`. */
export function listStagedFiles(cwd) {
  return splitNul(git(cwd, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "--relative", "-z"]));
}

/** The content of a file as staged, which may differ from the working tree. */
export function readStagedFile(cwd, relative) {
  return git(cwd, ["show", `:./${relative}`]);
}

/** Paths (relative to `cwd`, with "/" separators) of the files git tracks below `cwd`. */
export function listTrackedFiles(cwd) {
  return splitNul(git(cwd, ["ls-files", "-z"]));
}
