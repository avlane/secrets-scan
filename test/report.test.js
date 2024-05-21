import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { display, formatJson, formatSarif, formatSummary, formatText, redact, summarize, useColor } from "../src/report.js";

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

describe("formatJson", () => {
  const finding = {
    path: "a.env", line: 2, column: 5, endColumn: 25, ruleId: "aws-access-key-id", severity: "high",
    message: "AWS access key ID", secret: "AKIAIOSFODNN7EXAMPLE", fingerprint: "f".repeat(32),
  };

  it("has a stable document shape and masks secrets", () => {
    const doc = JSON.parse(formatJson([finding], { version: "9.9.9" }));
    assert.deepEqual(doc, {
      version: 1,
      tool: { name: "secrets-scan", version: "9.9.9" },
      summary: { total: 1, bySeverity: { high: 1, medium: 0, low: 0 } },
      findings: [{
        rule: "aws-access-key-id", severity: "high", message: "AWS access key ID", path: "a.env",
        line: 2, column: 5, endColumn: 25, match: "AKIA************", fingerprint: "f".repeat(32),
      }],
    });
  });

  it("can include the secret", () => {
    assert.equal(JSON.parse(formatJson([finding], { showSecrets: true })).findings[0].match, "AKIAIOSFODNN7EXAMPLE");
  });

  it("is valid for no findings", () => {
    assert.deepEqual(JSON.parse(formatJson([])).findings, []);
    assert.equal(summarize([]).total, 0);
  });
});

describe("formatSarif", () => {
  const catalog = [
    { id: "aws-access-key-id", description: "AWS access key ID", severity: "high" },
    { id: "high-entropy-string", description: "High-entropy string", severity: "medium" },
  ];
  const finding = {
    path: "config/a.env", line: 4, column: 7, endColumn: 27, ruleId: "high-entropy-string",
    severity: "medium", message: "High-entropy string", secret: "THE-SECRET-VALUE", fingerprint: "ab".repeat(16),
  };

  it("produces a SARIF 2.1.0 run with rules and results", () => {
    const doc = JSON.parse(formatSarif([finding], { version: "1.2.3", catalog }));
    assert.equal(doc.version, "2.1.0");
    assert.match(doc.$schema, /sarif-2\.1\.0/);
    const [run] = doc.runs;
    assert.equal(run.tool.driver.name, "secrets-scan");
    assert.equal(run.tool.driver.version, "1.2.3");
    assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ["aws-access-key-id", "high-entropy-string"]);
    assert.equal(run.tool.driver.rules[0].defaultConfiguration.level, "error");
    assert.equal(run.tool.driver.rules[1].defaultConfiguration.level, "warning");
    const [result] = run.results;
    assert.equal(result.ruleId, "high-entropy-string");
    assert.equal(result.ruleIndex, 1);
    assert.equal(result.level, "warning");
    assert.deepEqual(result.locations[0].physicalLocation, {
      artifactLocation: { uri: "config/a.env", uriBaseId: "%SRCROOT%" },
      region: { startLine: 4, startColumn: 7, endColumn: 27 },
    });
    assert.deepEqual(result.partialFingerprints, { "secretsScan/v1": "ab".repeat(16) });
  });

  it("never contains the secret", () => {
    assert.ok(!formatSarif([finding], { catalog }).includes("THE-SECRET-VALUE"));
  });

  it("is a valid document without results", () => {
    const doc = JSON.parse(formatSarif([], { catalog }));
    assert.deepEqual(doc.runs[0].results, []);
  });
});

describe("formatSummary", () => {
  const f = (path, severity) => ({ path, severity });

  it("says when nothing was found", () => {
    assert.equal(formatSummary([], 1), "secrets-scan: no secrets found (scanned 1 file)\n");
    assert.equal(formatSummary([], 12), "secrets-scan: no secrets found (scanned 12 files)\n");
  });

  it("counts findings, files and severities", () => {
    assert.equal(formatSummary([f("a", "high")], 4),
      "secrets-scan: 1 potential secret in 1 file (1 high); scanned 4 files\n");
    assert.equal(formatSummary([f("a", "high"), f("a", "medium"), f("b", "medium")], 9),
      "secrets-scan: 3 potential secrets in 2 files (1 high, 2 medium); scanned 9 files\n");
  });
});

describe("colors", () => {
  const finding = { path: "a", line: 1, column: 1, ruleId: "r", severity: "high", message: "m", secret: "abcdefghij" };

  it("are off by default and wrap parts of the line when on", () => {
    assert.ok(!formatText([finding]).includes("\x1b["));
    const colored = formatText([finding], { color: true });
    assert.match(colored, /\x1b\[31m\[high\]\x1b\[0m/);
    assert.equal(colored.replace(/\x1b\[\d+m/g, ""), formatText([finding]));
  });

  it("follow --color, NO_COLOR and the terminal", () => {
    const tty = { isTTY: true };
    const pipe = {};
    assert.equal(useColor("always", pipe, { NO_COLOR: "1" }), true);
    assert.equal(useColor("never", tty, {}), false);
    assert.equal(useColor("auto", tty, {}), true);
    assert.equal(useColor("auto", pipe, {}), false);
    assert.equal(useColor("auto", tty, { NO_COLOR: "1" }), false);
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
