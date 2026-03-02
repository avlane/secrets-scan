import assert from "node:assert/strict";
import { Readable } from "node:stream";
import fs from "node:fs";
import path from "node:path";
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
  it("exits 0 and prints nothing but a summary for a clean tree", async () => {
    const { code, stdout, stderr } = await run({ "a.js": "export const a = 1;\n" });
    assert.deepEqual([code, stdout], [0, ""]);
    assert.equal(stderr, "secrets-scan: no secrets found (scanned 1 file)\n");
  });

  it("--quiet drops the summary", async () => {
    const { stderr } = await run({ "k.env": `${AWS_KEY}\n` }, ["--quiet"]);
    assert.equal(stderr, "");
  });

  it("the summary counts findings and files", async () => {
    const { stderr } = await run({ "a.env": `${AWS_KEY}\n`, "b.txt": "nothing\n" });
    assert.equal(stderr, "secrets-scan: 1 potential secret in 1 file (1 high); scanned 2 files\n");
  });

  it("--color always colors the report; the default for a pipe does not", async () => {
    const files = { "k.env": `${AWS_KEY}\n` };
    assert.match((await run(files, ["--color", "always"])).stdout, /\x1b\[31m\[high\]/);
    assert.ok(!(await run(files)).stdout.includes("\x1b["));
    assert.equal((await run(files, ["--color", "sometimes"])).code, 2);
  });

  it("exits 1 and reports file, line, rule and a redacted secret", async () => {
    const { code, stdout } = await run({ "src/config.js": `// config\nconst key = "${AWS_KEY}";\n` });
    assert.equal(code, 1);
    assert.match(stdout, /^src\/config\.js:2:14 {2}aws-access-key-id {2}\[high\] {2}AWS access key ID: AKIA\*+\n$/);
    assert.ok(!stdout.includes(AWS_KEY));
  });

  it("shows the matched text only with --show-secrets", async () => {
    const files = { "a.env": `KEY=${AWS_KEY}\n` };
    assert.ok(!(await run(files)).stdout.includes(AWS_KEY));
    assert.ok((await run(files, ["--show-secrets"])).stdout.includes(AWS_KEY));
  });

  it("reports files in walk order, one line per finding", async () => {
    const { stdout } = await run({
      "b.env": `TOKEN=${GITHUB_TOKEN}\n`,
      "a/key.txt": `${AWS_KEY}\n`,
    });
    assert.deepEqual(stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["b.env:1:7", "a/key.txt:1:1"]);
  });

  it("finds high-entropy strings unless told not to", async () => {
    const files = { "app.conf": "blob = wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYq3Zd8TSKuvB\n" };
    const found = await run(files);
    assert.equal(found.code, 1);
    assert.match(found.stdout, /high-entropy-string/);
    const without = await run(files, ["--no-entropy"]);
    assert.equal(without.code, 0);
  });

  it("prints JSON with --format json", async () => {
    const { code, stdout } = await run({ "k.env": `KEY=${AWS_KEY}\n` }, ["--format", "json"]);
    assert.equal(code, 1);
    const doc = JSON.parse(stdout);
    assert.equal(doc.summary.total, 1);
    assert.equal(doc.findings[0].rule, "aws-access-key-id");
    assert.match(doc.findings[0].fingerprint, /^[0-9a-f]{32}$/);
    assert.ok(!stdout.includes(AWS_KEY));
  });

  it("prints valid JSON when nothing is found", async () => {
    const { code, stdout } = await run({ "a.txt": "hello\n" }, ["-f", "json"]);
    assert.equal(code, 0);
    assert.equal(JSON.parse(stdout).summary.total, 0);
  });

  it("prints SARIF with --format sarif", async () => {
    const { code, stdout } = await run({ "src/k.env": `KEY=${AWS_KEY}\n` }, ["--format", "sarif"]);
    assert.equal(code, 1);
    const doc = JSON.parse(stdout);
    const [result] = doc.runs[0].results;
    assert.equal(result.ruleId, "aws-access-key-id");
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/k.env");
    assert.ok(doc.runs[0].tool.driver.rules.some((rule) => rule.id === "high-entropy-string"));
    assert.ok(!stdout.includes(AWS_KEY));
  });

  it("prints GitHub annotations with --format github", async () => {
    const { code, stdout } = await run({ "src/k.env": `KEY=${AWS_KEY}\n` }, ["--format", "github"]);
    assert.equal(code, 1);
    assert.equal(stdout, "::error file=src/k.env,line=1,col=5,endColumn=25,title=aws-access-key-id::AWS access key ID\n");
  });

  it("writes the report to a file with --output", async () => {
    const { dir, cleanup } = makeTree({ "k.env": `KEY=${AWS_KEY}\n` });
    cleanups.push(cleanup);
    const { io, out } = capture();
    const code = await main(["--format", "sarif", "--output", "results.sarif"], { ...io, cwd: dir });
    assert.equal(code, 1);
    assert.equal(out.stdout, "");
    assert.match(out.stderr, /1 potential secret/);
    const written = JSON.parse(fs.readFileSync(path.join(dir, "results.sarif"), "utf8"));
    assert.equal(written.runs[0].results.length, 1);
    assert.deepEqual(fs.readdirSync(dir).sort(), ["k.env", "results.sarif"]);
    // Running again finds nothing new in the report file itself.
    const again = capture();
    assert.equal(await main(["--format", "sarif", "--output", "results.sarif"], { ...again.io, cwd: dir }), 1);
    assert.match(again.out.stderr, /scanned 1 file\n/);
  });

  it("--output never writes escape codes unless --color always", async () => {
    const { dir, cleanup } = makeTree({ "k.env": `KEY=${AWS_KEY}\n` });
    cleanups.push(cleanup);
    const io = capture().io;
    await main(["--output", "plain.txt", "--color", "auto"], { ...io, cwd: dir, env: {} });
    assert.ok(!fs.readFileSync(path.join(dir, "plain.txt"), "utf8").includes("\x1b["));
    await main(["--output", "colored.txt", "--color", "always"], { ...io, cwd: dir });
    assert.ok(fs.readFileSync(path.join(dir, "colored.txt"), "utf8").includes("\x1b["));
  });

  it("--output into a missing directory is an error and leaves nothing behind", async () => {
    const { code, stderr } = await run({ "k.env": `KEY=${AWS_KEY}\n` }, ["--output", "missing/dir/report.txt"]);
    assert.equal(code, 2);
    assert.match(stderr, /cannot write missing\/dir\/report\.txt: ENOENT/);
  });

  it("rejects unknown formats", async () => {
    const { code, stderr } = await run({}, ["--format", "xml"]);
    assert.equal(code, 2);
    assert.match(stderr, /unknown format 'xml'/);
  });

  it("honours --include and --exclude", async () => {
    const files = { "src/a.env": `K=${AWS_KEY}\n`, "docs/b.md": `K=${AWS_KEY}\n`, "vendor/c.env": `K=${AWS_KEY}\n` };
    const all = await run(files);
    assert.equal(all.stdout.trim().split("\n").length, 3);
    const onlyEnv = await run(files, ["--include", "*.env"]);
    assert.equal(onlyEnv.stdout.trim().split("\n").length, 2);
    const noVendor = await run(files, ["--exclude", "vendor", "--exclude", "docs/"]);
    assert.match(noVendor.stdout, /^src\/a\.env/);
    assert.equal(noVendor.stdout.trim().split("\n").length, 1);
  });

  it("applies the default .secrets-allowlist", async () => {
    const files = {
      ".secrets-allowlist": "path: docs/**\nregex: ^AKIAQYL\\w+$\n",
      "docs/a.md": `${GITHUB_TOKEN}\n`,
      "src/b.env": `${AWS_KEY}\n`,
      "src/c.env": `T=${GITHUB_TOKEN}\n`,
    };
    const { code, stdout } = await run(files);
    assert.equal(code, 1);
    assert.deepEqual(stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["src/c.env:1:3"]);
  });

  it("allowlist entries can name a rule or a fingerprint, and can expire", async () => {
    const files = { "a.env": `K=${AWS_KEY}\nT=${GITHUB_TOKEN}\n` };
    const json = JSON.parse((await run(files, ["-f", "json"])).stdout);
    const awsFingerprint = json.findings.find((f) => f.rule === "aws-access-key-id").fingerprint;
    const byRule = await run({ ...files, "allow.txt": "rule: github-token @ *.env\n" }, ["--allowlist", "allow.txt"]);
    assert.deepEqual(byRule.stdout.trim().split("\n").map((l) => l.split("  ")[1]), ["aws-access-key-id"]);
    const byFingerprint = await run({ ...files, "allow.txt": `fingerprint: ${awsFingerprint}\nrule: github-token\n` }, ["--allowlist", "allow.txt"]);
    assert.equal(byFingerprint.code, 0);
    const expired = await run({ ...files, "allow.txt": "rule: github-token  expires=2020-01-01\n" }, ["--allowlist", "allow.txt"]);
    assert.equal(expired.code, 1);
    assert.equal(expired.stdout.trim().split("\n").length, 2);
    assert.match(expired.stderr, /warning: allowlist entry expired on 2020-01-01 and is ignored: allow\.txt:1: rule: github-token/);
  });

  it("an allowlist entry for an unknown rule is an error", async () => {
    const { code, stderr } = await run({ "allow.txt": "rule: github-tokens\n" }, ["--allowlist", "allow.txt"]);
    assert.equal(code, 2);
    assert.match(stderr, /allow\.txt:1: unknown rule 'github-tokens'/);
  });

  it("takes an explicit allowlist and fails if it is missing or invalid", async () => {
    const files = { "k.env": `${AWS_KEY}\n`, "mine.txt": "path: k.env\n", "bad.txt": "nonsense\n" };
    assert.equal((await run(files, ["--allowlist", "mine.txt"])).code, 0);
    const missing = await run(files, ["--allowlist", "nope.txt"]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /cannot read allowlist/);
    const bad = await run(files, ["--allowlist", "bad.txt"]);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /bad\.txt:1: expected/);
  });

  it("does not scan lock files and minified bundles unless asked to", async () => {
    const files = {
      "package-lock.json": `{"token": "${GITHUB_TOKEN}"}\n`,
      "dist/app.min.js": `var k="${AWS_KEY}";\n`,
      "app.js.map": `${AWS_KEY}\n`,
    };
    assert.equal((await run(files)).code, 0);
    const forced = await run(files, ["--no-default-skips"]);
    assert.equal(forced.code, 1);
    assert.equal(forced.stdout.trim().split("\n").length, 3);
  });

  it("--min-severity hides lower severities", async () => {
    const files = { "a.env": `K=${AWS_KEY}\n`, "b.yml": 'password: "aB3dE6gH9jK"\n' };
    const all = await run(files);
    assert.equal(all.stdout.trim().split("\n").length, 2);
    const high = await run(files, ["--min-severity", "high"]);
    assert.deepEqual(high.stdout.trim().split("\n").map((l) => l.split("  ")[1]), ["aws-access-key-id"]);
    const onlyMedium = await run({ "b.yml": 'password: "aB3dE6gH9jK"\n' }, ["--min-severity", "high"]);
    assert.equal(onlyMedium.code, 0);
    assert.equal((await run(files, ["--min-severity", "critical"])).code, 2);
  });

  it("skips files over --max-size and says so", async () => {
    const files = { "big.env": `K=${AWS_KEY}\n` + "#".repeat(5000), "small.env": `K=${AWS_KEY}\n` };
    const limited = await run(files, ["--max-size", "1k"]);
    assert.deepEqual(limited.stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["small.env:1:3"]);
    assert.match(limited.stderr, /1 larger than --max-size skipped/);
    assert.equal((await run(files)).stdout.trim().split("\n").length, 2);
    assert.equal((await run(files, ["--max-size", "lots"])).code, 2);
  });

  it("--list-rules lists every rule with its severity", async () => {
    const { code, stdout } = await run({}, ["--list-rules"]);
    assert.equal(code, 0);
    assert.match(stdout, /^aws-access-key-id +high +AWS access key ID$/m);
    assert.match(stdout, /^high-entropy-string +medium +High-entropy string$/m);
  });

  it("--explain describes a rule", async () => {
    const { code, stdout } = await run({}, ["--explain", "aws-access-key-id"]);
    assert.equal(code, 0);
    assert.match(stdout, /^aws-access-key-id \(high\)\n {2}AWS access key ID\n/);
    const unknown = await run({}, ["--explain", "aws"]);
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /unknown rule 'aws'/);
  });

  it("--only and --disable choose the rules", async () => {
    const files = { "a.env": `K=${AWS_KEY}\nT=${GITHUB_TOKEN}\n` };
    const only = await run(files, ["--only", "github-token"]);
    assert.deepEqual(only.stdout.trim().split("\n").map((l) => l.split("  ")[1]), ["github-token"]);
    const disabled = await run(files, ["--disable", "github-token", "--disable", "high-entropy-string"]);
    assert.deepEqual(disabled.stdout.trim().split("\n").map((l) => l.split("  ")[1]), ["aws-access-key-id"]);
    const bad = await run(files, ["--only", "nonsense"]);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /unknown rule 'nonsense'/);
  });

  it("scans standard input with --stdin or the path -", async () => {
    const scanStdin = async (args, text) => {
      const { io, out } = capture();
      const code = await main(args, { ...io, stdin: Readable.from([Buffer.from(text)]), cwd: process.cwd() });
      return { code, ...out };
    };
    const staged = await scanStdin(["--stdin"], `line one\nK=${AWS_KEY}\n`);
    assert.equal(staged.code, 1);
    assert.match(staged.stdout, /^<stdin>:2:3 {2}aws-access-key-id/);
    const named = await scanStdin(["-", "--stdin-filename", "config/prod.env"], `K=${AWS_KEY}\n`);
    assert.match(named.stdout, /^config\/prod\.env:1:3 /);
    assert.equal((await scanStdin(["--stdin"], "nothing here\n")).code, 0);
    const mixed = await scanStdin(["--stdin", "somewhere"], "x");
    assert.equal(mixed.code, 2);
    assert.match(mixed.stderr, /cannot be combined with PATH/);
  });

  it("accepts ./ in front of exclude patterns", async () => {
    const files = { "vendor/a.env": `K=${AWS_KEY}\n`, "src/b.env": `K=${AWS_KEY}\n` };
    const { stdout } = await run(files, ["--exclude", "./vendor"]);
    assert.deepEqual(stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["src/b.env:1:3"]);
  });

  const canTestPermissions = process.platform !== "win32" && process.getuid?.() !== 0;

  it("warns about files and directories it cannot read and carries on", { skip: !canTestPermissions && "needs permission checks" }, async () => {
    const { dir, cleanup } = makeTree({ "locked.env": `K=${AWS_KEY}\n`, "sealed/inner.env": `K=${AWS_KEY}\n`, "ok.env": `K=${AWS_KEY}\n` });
    cleanups.push(() => {
      fs.chmodSync(path.join(dir, "sealed"), 0o700);
      cleanup();
    });
    fs.chmodSync(path.join(dir, "locked.env"), 0o000);
    fs.chmodSync(path.join(dir, "sealed"), 0o000);
    const { io, out } = capture();
    const code = await main([], { ...io, cwd: dir });
    assert.equal(code, 1); // the readable file still has its finding
    assert.match(out.stdout, /^ok\.env:1:3 /);
    assert.match(out.stderr, /warning: cannot read locked\.env: EACCES/);
    assert.match(out.stderr, /warning: cannot read directory sealed: EACCES/);
    assert.match(out.stderr, /1 could not be read/);
  });

  it("--verbose says what was skipped", async () => {
    const files = { "big.env": "#".repeat(3000), "image.bin": "a\0b", "ok.txt": "fine\n" };
    const quiet = await run(files, ["--max-size", "1k"]);
    assert.ok(!quiet.stderr.includes("skipped (larger"));
    const verbose = await run(files, ["--max-size", "1k", "--verbose"]);
    assert.match(verbose.stderr, /skipped \(larger than --max-size\): big\.env/);
    assert.match(verbose.stderr, /skipped binary file: image\.bin/);
  });

  it("--verbose mentions symbolic links, which are never followed", { skip: process.platform === "win32" }, async () => {
    const { dir, cleanup } = makeTree({ "real.env": `K=${AWS_KEY}\n` });
    cleanups.push(cleanup);
    fs.symlinkSync(path.join(dir, "real.env"), path.join(dir, "link.env"));
    const { io, out } = capture();
    await main(["--verbose"], { ...io, cwd: dir });
    assert.equal(out.stdout.trim().split("\n").length, 1);
    assert.match(out.stderr, /skipped symbolic link: link\.env/);
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
