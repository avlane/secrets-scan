import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { scanSources } from "../src/pipeline.js";
import { RULES } from "../src/rules.js";
import { AWS_KEY } from "./fakes.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const source = (relative, contents, delay = 0) => ({
  relative,
  read: async () => {
    await sleep(delay);
    if (contents instanceof Error) throw contents;
    return Buffer.from(contents);
  },
});
const options = { rules: RULES, scanOptions: { entropy: false }, maxSize: 1024 };

describe("scanSources", () => {
  it("returns findings in source order even when reads finish out of order", async () => {
    const sources = [
      source("slow.env", `K=${AWS_KEY}\n`, 25),
      source("fast.env", `K=${AWS_KEY}\n`, 0),
      source("clean.txt", "nothing\n", 5),
      source("medium.env", `K=${AWS_KEY}\n`, 10),
    ];
    const { findings, filesScanned } = await scanSources(sources, options);
    assert.deepEqual(findings.map((f) => f.path), ["slow.env", "fast.env", "medium.env"]);
    assert.equal(filesScanned, 4);
  });

  it("counts and reports unreadable, large and binary sources", async () => {
    const warnings = [];
    const notes = [];
    const denied = Object.assign(new Error("denied"), { code: "EACCES" });
    const gone = Object.assign(new Error("gone"), { code: "ENOENT" });
    const { findings, filesScanned, skippedLarge, unreadable } = await scanSources([
      source("denied.env", denied),
      source("gone.env", gone),
      source("big.env", "x".repeat(2000)),
      source("blob.bin", "a\0b"),
      source("ok.env", `K=${AWS_KEY}\n`),
    ], { ...options, warn: (m) => warnings.push(m), note: (m) => notes.push(m) });
    assert.equal(findings.length, 1);
    assert.deepEqual([filesScanned, skippedLarge, unreadable], [1, 1, 1]);
    assert.deepEqual(warnings, ["cannot read denied.env: EACCES"]);
    assert.deepEqual(notes, ["skipped (larger than --max-size): big.env", "skipped binary file: blob.bin"]);
  });

  it("accepts sources that read synchronously", async () => {
    const { findings } = await scanSources([{ relative: "a.env", read: () => Buffer.from(`K=${AWS_KEY}`) }], options);
    assert.equal(findings.length, 1);
  });
});
