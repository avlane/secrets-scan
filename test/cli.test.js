import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { main } from "../src/cli.js";
import { AWS_KEY, GITHUB_TOKEN } from "./fakes.js";
import { capture, makeTree } from "./helpers.js";

const cleanups = [];
afterEach(() => cleanups.splice(0).forEach((fn) => fn()));

async function run(files, args = []) {
  const { dir, cleanup } = makeTree(files);
  cleanups.push(cleanup);
  const { io, out } = capture();
  const code = await main(args, { ...io, cwd: dir });
  return { code, ...out, dir };
}

describe("cli", () => {
  it("exits 0 and prints nothing for a clean tree", async () => {
    const { code, stdout, stderr } = await run({ "a.js": "export const a = 1;\n" });
    assert.deepEqual([code, stdout, stderr], [0, "", ""]);
  });

  it("exits 1 and reports file, line, rule and a redacted secret", async () => {
    const { code, stdout } = await run({ "src/config.js": `// config\nconst key = "${AWS_KEY}";\n` });
    assert.equal(code, 1);
    assert.match(stdout, /^src\/config\.js:2:14 {2}aws-access-key-id {2}\[high\] {2}AWS access key ID: AKIA\*+\n$/);
    assert.ok(!stdout.includes(AWS_KEY));
  });

  it("reports files in walk order, one line per finding", async () => {
    const { stdout } = await run({
      "b.env": `TOKEN=${GITHUB_TOKEN}\n`,
      "a/key.txt": `${AWS_KEY}\n`,
    });
    assert.deepEqual(stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["b.env:1:7", "a/key.txt:1:1"]);
  });

  it("skips binary files", async () => {
    const { code } = await run({ "data.bin": `\0${AWS_KEY}`, "image.png": AWS_KEY });
    assert.equal(code, 0);
  });

  it("scans a single file given as the path", async () => {
    const { code, stdout } = await run({ "one.txt": AWS_KEY, "two.txt": AWS_KEY }, ["one.txt"]);
    assert.equal(code, 1);
    assert.equal(stdout.trim().split("\n").length, 1);
    assert.match(stdout, /^one\.txt:1:1/);
  });

  it("exits 2 for a path that does not exist", async () => {
    const { code, stdout, stderr } = await run({}, ["nope"]);
    assert.equal(code, 2);
    assert.equal(stdout, "");
    assert.match(stderr, /no such file or directory: nope/);
  });

  it("exits 2 for unknown options", async () => {
    const { code, stderr } = await run({}, ["--frobnicate"]);
    assert.equal(code, 2);
    assert.match(stderr, /Unknown option '--frobnicate'/);
  });

  it("prints help and version", async () => {
    const help = await run({}, ["--help"]);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /^Usage: secrets-scan/);
    const version = await run({}, ["-v"]);
    assert.match(version.stdout, /^secrets-scan \d+\.\d+\.\d+\n$/);
  });
});
