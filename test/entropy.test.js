import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { charsetOf, findHighEntropyStrings, isHighEntropy, shannonEntropy } from "../src/entropy.js";
import { RULES } from "../src/rules.js";
import { scanText } from "../src/scanner.js";
import { AWS_KEY } from "./fakes.js";

// 40 characters, the shape of an AWS secret access key; made up.
const RANDOM_BASE64 = "wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYzEXAMPLEKEY";
const RANDOM_HEX = "9f86d081884c7d659a2feaa0c55ad015";

describe("shannonEntropy", () => {
  it("is 0 for empty and uniform text", () => {
    assert.equal(shannonEntropy(""), 0);
    assert.equal(shannonEntropy("aaaaaaaa"), 0);
  });

  it("is log2 of the alphabet size when characters are evenly used", () => {
    assert.equal(shannonEntropy("abcd"), 2);
    assert.equal(shannonEntropy("abcdefgh"), 3);
    assert.ok(Math.abs(shannonEntropy("aabb") - 1) < 1e-12);
  });
});

describe("isHighEntropy", () => {
  it("accepts random-looking base64 and hex", () => {
    assert.ok(isHighEntropy(RANDOM_BASE64));
    assert.ok(isHighEntropy(RANDOM_HEX));
  });

  it("rejects short, repetitive and natural-language strings", () => {
    assert.ok(!isHighEntropy("Zx9Qp2"));
    assert.ok(!isHighEntropy("a".repeat(40)));
    assert.ok(!isHighEntropy("abababababababababababababab"));
    assert.ok(!isHighEntropy("this-is-a-fairly-long-kebab-case-name"));
    assert.ok(!isHighEntropy("getUserAccountByEmailAddress"));
  });

  it("only considers base64 and hex alphabets", () => {
    assert.equal(charsetOf("deadBEEF01"), "hex");
    assert.equal(charsetOf("abc+/=_-XYZ"), "base64");
    assert.equal(charsetOf("has space inside"), null);
    assert.ok(!isHighEntropy("p@ssw0rd!#%^&*()_+{}|:<>?~`"));
  });
});

describe("findHighEntropyStrings", () => {
  it("finds quoted and assigned tokens with their position", () => {
    const line = `key = "${RANDOM_BASE64}" # and ${RANDOM_HEX}`;
    const found = [...findHighEntropyStrings(line)];
    assert.deepEqual(found.map((f) => f.token), [RANDOM_BASE64, RANDOM_HEX]);
    assert.equal(found[0].index, 7);
  });

  it("does not cut tokens out of longer words", () => {
    assert.deepEqual([...findHighEntropyStrings(`x${RANDOM_BASE64}!y`)], []);
  });
});

describe("known non-secrets", () => {
  const hash = "sha512-" + "Zk3Hq9sV1pXw0aT8eLmNc2YdRu7BgFjIo5KtQ4vWzA6Ex/yD+Mh1nCbPl0Su3Xr9OaVqTgJwZe8iLk==";
  const uuid = "123e4567-e89b-12d3-a456-426614174000";

  it("are not reported", () => {
    assert.deepEqual(scanText(`"integrity": "${hash}"`, "package-lock.json", RULES), []);
    assert.deepEqual(scanText(`id = "${uuid}"`, "a.js", RULES), []);
    const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg";
    assert.deepEqual(scanText(`url(data:image/png;base64,${png})`, "a.css", RULES), []);
  });

  it("do not hide real secrets next to them", () => {
    const found = scanText(`id=${uuid} blob=${RANDOM_BASE64}`, "a", RULES);
    assert.deepEqual(found.map((f) => f.secret), [RANDOM_BASE64]);
  });
});

describe("entropy findings in scanText", () => {
  it("reports a high-entropy string that no rule knows", () => {
    const [finding] = scanText(`SECRET_BLOB: ${RANDOM_BASE64}\n`, "a.yml", RULES);
    assert.equal(finding.ruleId, "high-entropy-string");
    assert.equal(finding.severity, "medium");
    assert.equal(finding.column, 14);
  });

  it("does not report the same text twice when a rule already matched", () => {
    const findings = scanText(`key=${AWS_KEY}\n`, "a.env", RULES);
    assert.deepEqual(findings.map((f) => f.ruleId), ["aws-access-key-id"]);
  });

  it("can be switched off", () => {
    assert.deepEqual(scanText(`blob=${RANDOM_BASE64}`, "a", RULES, { entropy: false }), []);
  });
});
