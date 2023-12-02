import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { fingerprint } from "../src/fingerprint.js";

describe("fingerprint", () => {
  it("is a 32 character hex string", () => {
    assert.match(fingerprint("rule", "a.txt", "secret"), /^[0-9a-f]{32}$/);
  });

  it("is stable and depends on rule, path and secret", () => {
    const base = fingerprint("rule", "a.txt", "secret");
    assert.equal(fingerprint("rule", "a.txt", "secret"), base);
    assert.notEqual(fingerprint("other", "a.txt", "secret"), base);
    assert.notEqual(fingerprint("rule", "b.txt", "secret"), base);
    assert.notEqual(fingerprint("rule", "a.txt", "secret2"), base);
  });

  it("does not run the fields together", () => {
    assert.notEqual(fingerprint("ab", "c", "d"), fingerprint("a", "bc", "d"));
  });

  it("does not contain the secret", () => {
    assert.ok(!fingerprint("rule", "a.txt", "hunter2hunter2").includes("hunter2"));
  });
});
