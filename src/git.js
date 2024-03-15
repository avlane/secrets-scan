import { execFileSync } from "node:child_process";

export class GitError extends Error {}

function git(cwd, args) {
  try {
    return execFileSync("git", args, {
      cwd,
      maxBuffer: 512 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    if (error.code === "ENOENT") throw new GitError("git is not installed or not on the PATH");
    const detail = error.stderr?.toString().trim().split("\n")[0];
    throw new GitError(`git ${args[0]} failed${detail ? `: ${detail}` : ""}`);
  }
}

function splitNul(buffer) {
  return buffer.toString("utf8").split("\0").filter((name) => name !== "");
}

/** Paths (relative to `cwd`, with "/" separators) of the files git tracks below `cwd`. */
export function listTrackedFiles(cwd) {
  return splitNul(git(cwd, ["ls-files", "-z"]));
}
