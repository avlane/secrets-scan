import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { RULES } from "../src/rules.js";
import { scanText } from "../src/scanner.js";
import { AWS_KEY, GITHUB_TOKEN, PRIVATE_KEY_HEADER } from "./fakes.js";

const scan = (text) => scanText(text, "file.txt", RULES);

describe("scanText", () => {
  it("finds nothing in ordinary text", () => {
    assert.deepEqual(scan("const answer = 42;\nconsole.log('hello');\n"), []);
  });

  it("reports rule, 1-based position and the secret", () => {
    const [finding] = scan(`first line\naws_key = "${AWS_KEY}"\n`);
    assert.equal(finding.ruleId, "aws-access-key-id");
    assert.equal(finding.severity, "high");
    assert.equal(finding.path, "file.txt");
    assert.equal(finding.line, 2);
    assert.equal(finding.column, 12);
    assert.equal(finding.endColumn, 12 + AWS_KEY.length);
    assert.equal(finding.secret, AWS_KEY);
  });

  it("understands all line endings", () => {
    const text = `a\r\nb\rKEY=${AWS_KEY}\nc`;
    assert.deepEqual(scan(text).map((f) => f.line), [3]);
  });

  it("finds GitHub tokens of every kind", () => {
    for (const prefix of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) {
      const token = prefix + GITHUB_TOKEN.slice(4);
      assert.equal(scan(`token: ${token}`)[0]?.ruleId, "github-token", prefix);
    }
    const fineGrained = "github_pat_" + "11ABCDEFG0abcdefghijkl_" + "mnopqrstuvwxyz0123456789ABCDEFGHIJ";
    assert.equal(scan(`export GH=${fineGrained}`)[0]?.ruleId, "github-token");
  });

  it("finds private key blocks", () => {
    for (const kind of ["RSA ", "EC ", "DSA ", "OPENSSH ", "", "ENCRYPTED "]) {
      const header = `-----BEGIN ${kind}PRIVATE KEY-----`;
      assert.equal(scan(header)[0]?.ruleId, "private-key", header);
    }
    assert.equal(scan("-----BEGIN PGP PRIVATE KEY BLOCK-----")[0]?.ruleId, "private-key");
    assert.equal(scan(PRIVATE_KEY_HEADER)[0]?.ruleId, "private-key");
    assert.deepEqual(scan("-----BEGIN PUBLIC KEY-----"), []);
    assert.deepEqual(scan("-----BEGIN CERTIFICATE-----"), []);
  });

  it("does not match keys that are part of a longer word", () => {
    assert.deepEqual(scan(`x${AWS_KEY}`), []);
    assert.deepEqual(scan(`${AWS_KEY}X`), []);
  });
});
