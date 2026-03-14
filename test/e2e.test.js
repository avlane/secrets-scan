import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";

import { AWS_KEY } from "./fakes.js";
import { makeTree } from "./helpers.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bin = path.join(root, "bin", "secrets-scan.js");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

const cleanups = [];
afterEach(() => cleanups.splice(0).forEach((fn) => fn()));

function cli(files, args = [], options = {}) {
  const { dir, cleanup } = makeTree(files);
  cleanups.push(cleanup);
  const result = spawnSync(process.execPath, [bin, ...args], { cwd: dir, encoding: "utf8", ...options });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr, dir };
}

describe("the secrets-scan executable", () => {
  it("is executable and has a node shebang", { skip: process.platform === "win32" }, () => {
    assert.ok(fs.statSync(bin).mode & 0o111, "bin/secrets-scan.js should be executable");
    assert.match(fs.readFileSync(bin, "utf8"), /^#!\/usr\/bin\/env node\n/);
  });

  it("exits 0 for a clean tree, 1 with findings, 2 on usage errors", () => {
    assert.equal(cli({ "a.txt": "hello\n" }).code, 0);
    assert.equal(cli({ "a.env": `K=${AWS_KEY}\n` }).code, 1);
    for (const args of [["--bogus"], ["--format", "xml"], ["missing-dir"], ["--only", "nope"]]) {
      const result = cli({}, args);
      assert.equal(result.code, 2, args.join(" "));
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /^secrets-scan: /);
    }
  });

  it("prints findings on stdout and the summary on stderr", () => {
    const { stdout, stderr } = cli({ "src/a.env": `K=${AWS_KEY}\n` });
    assert.match(stdout, /^src\/a\.env:1:3 {2}aws-access-key-id {2}\[high\]/);
    assert.ok(!stdout.includes(AWS_KEY));
    assert.match(stderr, /^secrets-scan: 1 potential secret in 1 file/);
  });

  it("reads standard input from a pipe", () => {
    const { code, stdout } = cli({}, ["--stdin", "--stdin-filename", "piped.env", "--format", "json"], { input: `K=${AWS_KEY}\n` });
    assert.equal(code, 1);
    assert.equal(JSON.parse(stdout).findings[0].path, "piped.env");
  });

  it("reports its version and a help text with the exit statuses", () => {
    assert.equal(cli({}, ["--version"]).stdout, `secrets-scan ${pkg.version}\n`);
    const help = cli({}, ["--help"]).stdout;
    assert.match(help, /^Usage: secrets-scan/);
    assert.match(help, /Exit status: 0 nothing found, 1 secrets found, 2 error\./);
  });

  it("scans its own repository without findings", () => {
    const result = spawnSync(process.execPath, [bin, ".", "--git", "--quiet"], { cwd: root, encoding: "utf8" });
    assert.equal(result.stdout, "", result.stdout);
    assert.equal(result.status, 0);
  });
});
