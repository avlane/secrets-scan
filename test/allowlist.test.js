import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isAllowed, parseAllowlist } from "../src/allowlist.js";

const finding = (path, secret = "s3cr3t-value") => ({ path, secret, ruleId: "x" });

describe("parseAllowlist", () => {
  it("parses paths and regexes, skipping comments and blank lines", () => {
    const list = parseAllowlist("# header\n\npath: docs/**   # examples\nregex: ^EXAMPLE_\n  path:  *.md  \n");
    assert.equal(list.paths.length, 2);
    assert.equal(list.regexes.length, 1);
  });

  it("allows findings in matching paths", () => {
    const list = parseAllowlist("path: docs/examples/**\npath: *.snap\n");
    assert.ok(isAllowed(finding("docs/examples/a/b.md"), list));
    assert.ok(isAllowed(finding("src/__snapshots__/x.snap"), list));
    assert.ok(!isAllowed(finding("src/app.js"), list));
  });

  it("allows findings whose secret matches a regex", () => {
    const list = parseAllowlist("regex: ^EXAMPLE_[A-Z]+$\n");
    assert.ok(isAllowed(finding("a", "EXAMPLE_TOKEN"), list));
    assert.ok(!isAllowed(finding("a", "REAL_EXAMPLE_TOKEN"), list));
  });

  it("a '#' inside a value is kept unless it starts a comment", () => {
    const list = parseAllowlist("regex: ^a#b$\n");
    assert.ok(isAllowed(finding("x", "a#b"), list));
  });

  it("reports the line of a bad entry", () => {
    assert.throws(() => parseAllowlist("path: ok\nbogus: x\n", "allow.txt"), /allow\.txt:2: unknown entry "bogus"/);
    assert.throws(() => parseAllowlist("path:\n", "allow.txt"), /allow\.txt:1: expected "kind: value"/);
    assert.throws(() => parseAllowlist("just text\n", "allow.txt"), /allow\.txt:1: expected/);
    assert.throws(() => parseAllowlist("regex: (\n", "allow.txt"), /allow\.txt:1: invalid regular expression/);
  });

  it("an empty list allows nothing", () => {
    assert.ok(!isAllowed(finding("a"), parseAllowlist("")));
  });
});
