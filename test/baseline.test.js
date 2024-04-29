import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

import { applyBaseline, createBaseline, readBaseline, writeBaseline } from "../src/baseline.js";
import { main } from "../src/cli.js";
import { AWS_KEY, GITHUB_TOKEN } from "./fakes.js";
import { capture, makeTree } from "./helpers.js";

const finding = (fingerprint, path = "a.env", line = 1) => ({ fingerprint, ruleId: "r", path, line, secret: "SECRET" });

describe("baseline file", () => {
  it("lists fingerprints sorted by path and line, without secrets", () => {
    const baseline = createBaseline([finding("f2", "b.env", 3), finding("f1", "a.env", 9), finding("f3", "a.env", 2)]);
    assert.equal(baseline.version, 1);
    assert.deepEqual(baseline.findings.map((e) => [e.path, e.line]), [["a.env", 2], ["a.env", 9], ["b.env", 3]]);
    assert.ok(!JSON.stringify(baseline).includes("SECRET"));
  });

  it("round-trips through a file and rejects other files", () => {
    const { dir, cleanup } = makeTree({ "junk.json": "{}", "bad.json": "not json" });
    try {
      const file = path.join(dir, "baseline.json");
      writeBaseline(file, [finding("f1")]);
      assert.deepEqual(readBaseline(file), createBaseline([finding("f1")]));
      assert.throws(() => readBaseline(path.join(dir, "junk.json")), /not a secrets-scan baseline/);
      assert.throws(() => readBaseline(path.join(dir, "bad.json")), /not valid JSON/);
      assert.throws(() => readBaseline(path.join(dir, "missing.json")), /cannot read baseline/);
    } finally {
      cleanup();
    }
  });
});

describe("applyBaseline", () => {
  it("splits known from new findings", () => {
    const baseline = createBaseline([finding("f1"), finding("f2")]);
    const { fresh, known } = applyBaseline([finding("f1", "a.env", 7), finding("f3")], baseline);
    assert.deepEqual(known.map((f) => f.fingerprint), ["f1"]);
    assert.deepEqual(fresh.map((f) => f.fingerprint), ["f3"]);
  });

  it("is not fooled by a line number change", () => {
    const { fresh } = applyBaseline([finding("f1", "a.env", 400)], createBaseline([finding("f1", "a.env", 2)]));
    assert.deepEqual(fresh, []);
  });

  it("covers one occurrence per entry: a second copy is new", () => {
    const baseline = createBaseline([finding("f1")]);
    const { fresh, known } = applyBaseline([finding("f1", "a.env", 1), finding("f1", "a.env", 2)], baseline);
    assert.equal(known.length, 1);
    assert.equal(fresh.length, 1);
  });
});

describe("baseline in the cli", () => {
  const cleanups = [];
  afterEach(() => cleanups.splice(0).forEach((fn) => fn()));

  async function run(files, args) {
    const { dir, cleanup } = makeTree(files);
    cleanups.push(cleanup);
    const { io, out } = capture();
    const code = await main(args, { ...io, cwd: dir });
    return { code, dir, ...out };
  }

  it("adopts the scanner on a project that already has findings", async () => {
    const files = { "old.env": `K=${AWS_KEY}\n` };
    const first = await run(files, ["--write-baseline", "baseline.json"]);
    assert.equal(first.code, 0);
    assert.match(first.stderr, /wrote 1 finding to baseline\.json/);
    const written = fs.readFileSync(path.join(first.dir, "baseline.json"), "utf8");
    assert.ok(!written.includes(AWS_KEY));

    fs.writeFileSync(path.join(first.dir, "new.env"), `T=${GITHUB_TOKEN}\n`);
    const { io, out } = capture();
    const code = await main(["--baseline", "baseline.json"], { ...io, cwd: first.dir });
    assert.equal(code, 1);
    assert.deepEqual(out.stdout.trim().split("\n").map((l) => l.split("  ")[0]), ["new.env:1:3"]);
    assert.match(out.stderr, /1 known in the baseline ignored/);
  });

  it("exits 0 when only baselined findings remain", async () => {
    const files = { "old.env": `K=${AWS_KEY}\n` };
    const { dir } = await run(files, ["--write-baseline", "b.json"]);
    const { io, out } = capture();
    assert.equal(await main(["--baseline", "b.json"], { ...io, cwd: dir }), 0);
    assert.equal(out.stdout, "");
    assert.match(out.stderr, /no new secrets found .*1 known in the baseline ignored/);
  });

  it("a missing or invalid baseline is an error", async () => {
    const missing = await run({ "a.txt": "x" }, ["--baseline", "nope.json"]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /cannot read baseline/);
  });
});
