import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseSize } from "../src/size.js";

describe("parseSize", () => {
  it("understands plain numbers and units", () => {
    assert.equal(parseSize("0"), 0);
    assert.equal(parseSize("4096"), 4096);
    assert.equal(parseSize("500k"), 500 * 1024);
    assert.equal(parseSize("2M"), 2 * 1024 * 1024);
    assert.equal(parseSize("1.5MiB"), 1.5 * 1024 * 1024);
    assert.equal(parseSize(" 10 kb "), 10 * 1024);
    assert.equal(parseSize("1g"), 1024 ** 3);
  });

  it("rejects nonsense", () => {
    for (const bad of ["", "abc", "-1", "10x", "1..5k", "k10"]) {
      assert.throws(() => parseSize(bad), /invalid size/, bad);
    }
  });
});
