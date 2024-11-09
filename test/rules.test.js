import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { RULES, looksLikePlaceholder } from "../src/rules.js";
import { scanText } from "../src/scanner.js";
import {
  AWS_KEY, GITHUB_TOKEN, GOOGLE_API_KEY, MAILGUN_KEY, NPM_TOKEN, PRIVATE_KEY_HEADER, SENDGRID_KEY,
  SLACK_TOKEN, SLACK_WEBHOOK, STRIPE_KEY, STRIPE_WEBHOOK, TWILIO_KEY,
} from "./fakes.js";

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

  it("finds Slack tokens and webhooks", () => {
    assert.equal(scan(`SLACK_BOT=${SLACK_TOKEN}`)[0]?.ruleId, "slack-token");
    assert.equal(scan(`hook: "${SLACK_WEBHOOK}"`)[0]?.ruleId, "slack-webhook");
  });

  it("finds the keys of common providers", () => {
    const cases = {
      "stripe-key": STRIPE_KEY,
      "stripe-webhook-secret": STRIPE_WEBHOOK,
      "google-api-key": GOOGLE_API_KEY,
      "npm-token": NPM_TOKEN,
      "sendgrid-key": SENDGRID_KEY,
      "twilio-api-key": TWILIO_KEY,
      "mailgun-key": MAILGUN_KEY,
    };
    for (const [ruleId, secret] of Object.entries(cases)) {
      for (const line of [`x = "${secret}"`, `X=${secret}`, secret]) {
        const found = scan(line);
        assert.equal(found.length, 1, `${ruleId}: ${line}`);
        assert.equal(found[0].ruleId, ruleId);
        assert.equal(found[0].secret, secret);
      }
    }
  });

  it("does not take test keys or near misses for live keys", () => {
    const rulesOnly = (text) => scanText(text, "file.txt", RULES, { entropy: false });
    assert.deepEqual(rulesOnly("sk_test_" + "0123456789abcdefghijklmn"), []);
    assert.deepEqual(rulesOnly(STRIPE_KEY.slice(0, -8)), []);
    assert.deepEqual(rulesOnly(NPM_TOKEN.slice(0, -1)), []);
    assert.deepEqual(rulesOnly(TWILIO_KEY.toUpperCase()), []);
    assert.deepEqual(rulesOnly("task-key-" + "0123456789abcdef"), []);
  });

  it("finds Google Cloud service account key files", () => {
    assert.equal(scan('  "type": "service_account",')[0]?.ruleId, "gcp-service-account");
    assert.deepEqual(scan('  "type": "authorized_user",'), []);
  });

  it("finds hard-coded credentials in assignments", () => {
    const cases = [
      'password = "s3cr3tValue99"',
      "DB_PASSWORD: 'Tr0ub4dor&3xyz'",
      'const apiKey = "k8d92jfh38dh2"',
      '{"client_secret": "a8f5f167f44f4964e6c998dee827110c"}',
      "auth_token='b7e2c9d1f0a34'",
    ];
    for (const line of cases) {
      const found = scan(line);
      assert.equal(found.length, 1, line);
      assert.equal(found[0].ruleId, "generic-secret-assignment", line);
    }
    const [finding] = scan('password = "s3cr3tValue99"');
    assert.equal(finding.secret, "s3cr3tValue99");
    assert.equal(finding.column, 13);
  });

  it("ignores short values and values that are not quoted literals", () => {
    assert.deepEqual(scan('password = "short"'), []);
    assert.deepEqual(scan("password = getPassword()"), []);
    assert.deepEqual(scan("const token = process.argv[2];"), []);
    assert.deepEqual(scan('password = ""'), []);
  });

  it("ignores placeholders", () => {
    for (const value of ["changeme123", "your_password_here", "xxxxxxxxxxxx", "************",
      "aaaaaaaaaaaa", "EXAMPLE_TOKEN_VALUE", "placeholder-value", "dummyvalue123"]) {
      assert.deepEqual(scan(`secret = "${value}"`), [], value);
      assert.ok(looksLikePlaceholder(value), value);
    }
    assert.ok(!looksLikePlaceholder("k8d92jfh38dh2"));
  });

  it("ignores identifiers and translation keys used as values", () => {
    for (const value of ["validation_failed_message", "user.password.reset", "forgot-password-link"]) {
      assert.deepEqual(scan(`password: "${value}"`), [], value);
    }
    assert.equal(scan('password: "Valid_Looking-Pass9"').length, 1);
  });

  it("reports every secret on a line, not just the first", () => {
    const line = `{"a": "${AWS_KEY}", "b": "${GITHUB_TOKEN}", "c": "${AWS_KEY}"}`;
    const found = scan(line);
    assert.deepEqual(found.map((f) => f.ruleId), ["aws-access-key-id", "aws-access-key-id", "github-token"].sort((a, b) => 0));
    assert.deepEqual(found.map((f) => f.column).sort((a, b) => a - b), [
      line.indexOf(AWS_KEY) + 1, line.indexOf(GITHUB_TOKEN) + 1, line.lastIndexOf(AWS_KEY) + 1,
    ]);
    assert.equal(new Set(found.map((f) => f.column)).size, 3);
  });

  it("finds several generic assignments on one line", () => {
    const found = scan('{"password": "aB3dE6gH9jK", "api_key": "zY8wV5tS2qP"}');
    assert.deepEqual(found.map((f) => f.secret), ["aB3dE6gH9jK", "zY8wV5tS2qP"]);
  });

  it("runs only the specific rules on very long lines", () => {
    const filler = "x ".repeat(6000);
    const line = `${filler} password = "aB3dE6gH9jK" ${AWS_KEY}`;
    assert.deepEqual(scanText(line, "bundle.js", RULES, { maxLineLength: 100 }).map((f) => f.ruleId), ["aws-access-key-id"]);
    assert.deepEqual(scanText(line, "bundle.js", RULES, { maxLineLength: 100000 }).map((f) => f.ruleId).sort(),
      ["aws-access-key-id", "generic-secret-assignment"]);
  });

  it("reports text once even when several rules match it", () => {
    const found = scan(`"token": "${GITHUB_TOKEN}"`);
    assert.deepEqual(found.map((f) => f.ruleId), ["github-token"]);
  });

  it("honours inline ignore comments", () => {
    assert.deepEqual(scan(`key = "${AWS_KEY}"  // secrets-scan:ignore`), []);
    assert.deepEqual(scan(`# secrets-scan:ignore-next-line\nkey = "${AWS_KEY}"\n`), []);
    assert.equal(scan(`# secrets-scan:ignore-next-line\nok\nkey = "${AWS_KEY}"\n`).length, 1);
    assert.deepEqual(scan(`/* secrets-scan:ignore-file */\na = "${AWS_KEY}"\nb = "${GITHUB_TOKEN}"\n`), []);
  });

  it("an ignore comment only affects its own line", () => {
    const text = `a = "${AWS_KEY}" # secrets-scan:ignore\nb = "${GITHUB_TOKEN}"\n`;
    assert.deepEqual(scan(text).map((f) => f.line), [2]);
  });

  it("does not match keys that are part of a longer word", () => {
    assert.deepEqual(scan(`x${AWS_KEY}`), []);
    assert.deepEqual(scan(`${AWS_KEY}X`), []);
  });
});
