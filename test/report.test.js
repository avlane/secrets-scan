import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { display, formatText, redact } from "../src/report.js";

describe("redact", () => {
  it("masks short secrets completely", () => {
    assert.equal(redact("abc"), "***");
    assert.equal(redact("12345678"), "********");
  });

  it("keeps only the first four characters of longer ones", () => {
    assert.equal(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA************");
    assert.equal(redact("abcde12345"), "abcd******");
  });

  it("never reveals more than a prefix, whatever the length", () => {
    const secret = "q".repeat(500) + "TAIL";
    assert.ok(!redact(secret).includes("TAIL"));
    assert.ok(redact(secret).length <= 16);
  });
});

describe("formatText", () => {
  const finding = {
    path: "a/b.js", line: 3, column: 9, ruleId: "github-token", severity: "high",
    message: "GitHub token", secret: "ghp_secretsecretsecretsecretsecret123456",
  };

  it("is empty without findings", () => {
    assert.equal(formatText([]), "");
  });

  it("masks by default and shows the secret on request", () => {
    assert.equal(formatText([finding]), "a/b.js:3:9  github-token  [high]  GitHub token: ghp_************\n");
    assert.match(formatText([finding], { showSecrets: true }), /GitHub token: ghp_secretsecret/);
    assert.equal(display("abcdefghij", false), "abcd******");
    assert.equal(display("abcdefghij", true), "abcdefghij");
  });
});
