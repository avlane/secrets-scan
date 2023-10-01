import assert from "node:assert/strict";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

import { hasBinaryExtension, looksBinary, walk } from "../src/walk.js";
import { makeTree } from "./helpers.js";

const cleanups = [];
afterEach(() => cleanups.splice(0).forEach((fn) => fn()));

function tree(files) {
  const made = makeTree(files);
  cleanups.push(made.cleanup);
  return made.dir;
}

describe("walk", () => {
  it("yields files in a stable, depth-first order", () => {
    const dir = tree({ "b.txt": "", "a/z.txt": "", "a/y.txt": "", "c/d/e.txt": "" });
    const found = [...walk(dir)].map((f) => path.relative(dir, f).split(path.sep).join("/"));
    assert.deepEqual(found, ["b.txt", "a/y.txt", "a/z.txt", "c/d/e.txt"]);
  });

  it("skips version control and dependency folders", () => {
    const dir = tree({ ".git/config": "", "node_modules/x/index.js": "", "src/a.js": "" });
    assert.deepEqual([...walk(dir)].map((f) => path.basename(f)), ["a.js"]);
  });

  it("accepts a custom list of ignored directories", () => {
    const dir = tree({ "build/a.js": "", "src/b.js": "" });
    const found = [...walk(dir, { ignoredDirs: ["build"] })].map((f) => path.basename(f));
    assert.deepEqual(found, ["b.js"]);
  });

  it("returns nothing for an empty or missing directory", () => {
    const dir = tree({});
    assert.deepEqual([...walk(dir)], []);
    assert.deepEqual([...walk(path.join(dir, "missing"))], []);
  });
});

describe("binary detection", () => {
  it("knows binary extensions", () => {
    assert.ok(hasBinaryExtension("logo.PNG"));
    assert.ok(hasBinaryExtension("a/b/archive.tar.gz"));
    assert.ok(!hasBinaryExtension("script.js"));
    assert.ok(!hasBinaryExtension("Makefile"));
  });

  it("recognises NUL bytes", () => {
    assert.ok(looksBinary(Buffer.from([0x50, 0x4b, 0x00, 0x04])));
    assert.ok(!looksBinary(Buffer.from("plain text\n")));
  });
});
