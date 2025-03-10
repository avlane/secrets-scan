import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isAllowed, parseAllowlist } from "../src/allowlist.js";

const finding = (path, secret = "s3cr3t-value", extra = {}) => ({ path, secret, ruleId: "x", fingerprint: "0".repeat(32), ...extra });

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
    assert.throws(() => parseAllowlist("path: ok\nbogus: x\n", "allow.txt"), /allow\.txt:2: unknown entry "bogus" \(use path, regex, rule or fingerprint\)/);
    assert.throws(() => parseAllowlist("path:\n", "allow.txt"), /allow\.txt:1: expected "kind: value"/);
    assert.throws(() => parseAllowlist("just text\n", "allow.txt"), /allow\.txt:1: expected/);
    assert.throws(() => parseAllowlist("regex: (\n", "allow.txt"), /allow\.txt:1: invalid regular expression/);
  });

  it("allows one rule everywhere or only in some files", () => {
    const list = parseAllowlist("rule: generic-secret-assignment\nrule: jwt @ docs/**\n");
    assert.ok(isAllowed(finding("a/b.js", "x", { ruleId: "generic-secret-assignment" }), list));
    assert.ok(isAllowed(finding("docs/a.md", "x", { ruleId: "jwt" }), list));
    assert.ok(!isAllowed(finding("src/a.js", "x", { ruleId: "jwt" }), list));
    assert.ok(!isAllowed(finding("docs/a.md", "x", { ruleId: "github-token" }), list));
  });

  it("allows one specific finding by fingerprint", () => {
    const fp = "ab12".repeat(8);
    const list = parseAllowlist(`fingerprint: ${fp}   # the sandbox key\n`);
    assert.ok(isAllowed(finding("any/path", "x", { fingerprint: fp }), list));
    assert.ok(!isAllowed(finding("any/path", "x", { fingerprint: "cd34".repeat(8) }), list));
    assert.throws(() => parseAllowlist("fingerprint: abc\n", "f"), /f:1: a fingerprint is 32 hex digits/);
  });

  it("entries stop applying after their expiry date and are reported", () => {
    const text = "path: legacy/**  expires=2025-03-31\nregex: ^tmp-  expires=2099-12-31\n";
    const before = parseAllowlist(text, "a.txt", new Date("2025-03-31T12:00:00Z"));
    assert.ok(isAllowed(finding("legacy/x.js"), before));
    assert.deepEqual(before.expired, []);
    const after = parseAllowlist(text, "a.txt", new Date("2025-04-01T00:00:01Z"));
    assert.ok(!isAllowed(finding("legacy/x.js"), after));
    assert.ok(isAllowed(finding("x", "tmp-1"), after));
    assert.deepEqual(after.expired, [{ where: "a.txt:1", entry: "path: legacy/**", date: "2025-03-31" }]);
  });

  it("rejects malformed expiry dates", () => {
    for (const bad of ["soon", "2025-13-45", "2025-3-1"]) {
      assert.throws(() => parseAllowlist(`path: x  expires=${bad}\n`, "f"), /f:1: expires= needs a date/, bad);
    }
  });

  it("an empty list allows nothing", () => {
    assert.ok(!isAllowed(finding("a"), parseAllowlist("")));
  });
});
