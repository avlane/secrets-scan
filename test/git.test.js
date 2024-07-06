import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

import { main } from "../src/cli.js";
import { GitError, listStagedFiles, listTrackedFiles, readStagedFile } from "../src/git.js";
import { AWS_KEY } from "./fakes.js";
import { capture, makeTree } from "./helpers.js";

let haveGit = true;
try {
  execFileSync("git", ["--version"], { stdio: "ignore" });
} catch {
  haveGit = false;
}

const cleanups = [];
afterEach(() => cleanups.splice(0).forEach((fn) => fn()));

function repo(files, tracked) {
  const { dir, cleanup } = makeTree(files);
  cleanups.push(cleanup);
  execFileSync("git", ["init", "-q"], { cwd: dir });
  if (tracked.length > 0) execFileSync("git", ["add", "--", ...tracked], { cwd: dir });
  return dir;
}

describe("git mode", { skip: !haveGit && "git is not installed" }, () => {
  it("lists tracked files only, relative to the directory", () => {
    const dir = repo({ "a.txt": "1", "sub/b.txt": "2", "untracked.txt": "3", ".gitignore": "ignored.txt\n", "ignored.txt": "4" },
      ["a.txt", "sub/b.txt", ".gitignore"]);
    assert.deepEqual(listTrackedFiles(dir).sort(), [".gitignore", "a.txt", "sub/b.txt"]);
    assert.deepEqual(listTrackedFiles(path.join(dir, "sub")), ["b.txt"]);
  });

  it("handles file names with spaces and non-ASCII characters", () => {
    const dir = repo({ "my file.txt": "1", "café/ü.txt": "2" }, ["my file.txt", "café/ü.txt"]);
    assert.deepEqual(listTrackedFiles(dir).sort(), ["café/ü.txt", "my file.txt"]);
  });

  it("lists staged files and reads their staged content", () => {
    const dir = repo({ "a.txt": "staged version\n", "b.txt": "unstaged\n" }, ["a.txt"]);
    fs.writeFileSync(path.join(dir, "a.txt"), "edited later\n");
    assert.deepEqual(listStagedFiles(dir), ["a.txt"]);
    assert.equal(readStagedFile(dir, "a.txt").toString(), "staged version\n");
  });

  it("throws a GitError outside a repository", () => {
    const { dir, cleanup } = makeTree({});
    cleanups.push(cleanup);
    assert.throws(() => listTrackedFiles(dir), GitError);
  });

  it("--git scans tracked files and leaves untracked or ignored ones alone", async () => {
    const dir = repo({
      "tracked.env": `K=${AWS_KEY}\n`,
      "untracked.env": `K=${AWS_KEY}\n`,
      ".gitignore": "ignored.env\n",
      "ignored.env": `K=${AWS_KEY}\n`,
    }, ["tracked.env", ".gitignore"]);
    const everything = capture();
    await main([], { ...everything.io, cwd: dir });
    assert.equal(everything.out.stdout.trim().split("\n").length, 3);

    const tracked = capture();
    const code = await main(["--git"], { ...tracked.io, cwd: dir });
    assert.equal(code, 1);
    assert.match(tracked.out.stdout, /^tracked\.env:1:3 /);
    assert.equal(tracked.out.stdout.trim().split("\n").length, 1);
    assert.match(tracked.out.stderr, /scanned 2 files/);
  });

  it("--git still applies --exclude and --include", async () => {
    const dir = repo({ "a.env": `K=${AWS_KEY}\n`, "vendor/b.env": `K=${AWS_KEY}\n`, "c.txt": `K=${AWS_KEY}\n` },
      ["a.env", "vendor/b.env", "c.txt"]);
    const { io, out } = capture();
    await main(["--git", "--exclude", "vendor", "--include", "*.env"], { ...io, cwd: dir });
    assert.deepEqual(out.stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["a.env:1:3"]);
  });

  it("--git skips tracked files that were deleted from the working tree", async () => {
    const dir = repo({ "gone.env": `K=${AWS_KEY}\n`, "here.txt": "fine\n" }, ["gone.env", "here.txt"]);
    fs.rmSync(path.join(dir, "gone.env"));
    const { io, out } = capture();
    assert.equal(await main(["--git"], { ...io, cwd: dir }), 0);
    assert.match(out.stderr, /scanned 1 file\)\n/);
  });

  it("--staged scans what is in the index, not the working tree", async () => {
    const dir = repo({ "new.env": `K=${AWS_KEY}\n`, "clean.txt": "fine\n", "other.env": "FINE=1\n" }, ["new.env", "clean.txt"]);
    // After staging: the secret is removed from the working copy, and a secret is added to an unstaged file.
    fs.writeFileSync(path.join(dir, "new.env"), "K=removed-after-staging\n");
    fs.writeFileSync(path.join(dir, "other.env"), `K=${AWS_KEY}\n`);
    const { io, out } = capture();
    const code = await main(["--staged"], { ...io, cwd: dir });
    assert.equal(code, 1);
    assert.deepEqual(out.stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["new.env:1:3"]);
    assert.match(out.stderr, /scanned 2 files/);
  });

  it("--staged with nothing staged scans nothing", async () => {
    const dir = repo({ "a.env": `K=${AWS_KEY}\n` }, []);
    const { io, out } = capture();
    assert.equal(await main(["--staged"], { ...io, cwd: dir }), 0);
    assert.match(out.stderr, /scanned 0 files/);
  });

  it("--staged works from a subdirectory", async () => {
    const dir = repo({ "pkg/a.env": `K=${AWS_KEY}\n`, "top.env": `K=${AWS_KEY}\n` }, ["pkg/a.env", "top.env"]);
    const { io, out } = capture();
    await main(["--staged"], { ...io, cwd: path.join(dir, "pkg") });
    assert.deepEqual(out.stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["a.env:1:3"]);
  });

  it("--git and --staged cannot be combined", async () => {
    const { io, out } = capture();
    assert.equal(await main(["--git", "--staged"], { ...io, cwd: process.cwd() }), 2);
    assert.match(out.stderr, /cannot be combined/);
  });

  it("--git outside a repository is an error", async () => {
    const { dir, cleanup } = makeTree({ "a.txt": "x" });
    cleanups.push(cleanup);
    const { io, out } = capture();
    assert.equal(await main(["--git"], { ...io, cwd: dir }), 2);
    assert.match(out.stderr, /git ls-files failed/);
  });
});
