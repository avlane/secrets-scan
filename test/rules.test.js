import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { RULES, explainRule, ruleCatalog, looksLikePlaceholder, selectRules } from "../src/rules.js";
import { scanText } from "../src/scanner.js";
import {
  AWS_KEY, AZURE_STORAGE_KEY, DATABRICKS_TOKEN, DIGITALOCEAN_TOKEN, DISCORD_WEBHOOK, GITHUB_TOKEN,
  GOOGLE_API_KEY, MAILGUN_KEY, NPM_TOKEN, PRIVATE_KEY_HEADER, PYPI_TOKEN, SENDGRID_KEY, SENTRY_TOKEN,
  SHOPIFY_TOKEN, SLACK_TOKEN, SLACK_WEBHOOK, SQUARE_TOKEN, STRIPE_KEY, STRIPE_WEBHOOK, TWILIO_KEY,
} from "./fakes.js";

const scan = (text) => scanText(text, "file.txt", RULES);

describe("rule catalog and selection", () => {
  it("has unique ids, a severity and a description for every rule", () => {
    const catalog = ruleCatalog();
    assert.equal(new Set(catalog.map((r) => r.id)).size, catalog.length);
    for (const rule of catalog) {
      assert.match(rule.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
      assert.ok(["low", "medium", "high"].includes(rule.severity), rule.id);
      assert.ok(rule.description.length > 3, rule.id);
    }
  });

  it("runs everything by default", () => {
    const { rules, entropy } = selectRules();
    assert.equal(rules.length, RULES.length);
    assert.equal(entropy, true);
  });

  it("--only keeps just the named rules, and entropy only when named", () => {
    const wanted = ["github-token", "jwt"];
    assert.deepEqual(selectRules({ only: wanted }).rules.map((r) => r.id), RULES.map((r) => r.id).filter((id) => wanted.includes(id)));
    assert.equal(selectRules({ only: ["github-token"] }).entropy, false);
    const entropyOnly = selectRules({ only: ["high-entropy-string"] });
    assert.deepEqual([entropyOnly.rules.length, entropyOnly.entropy], [0, true]);
  });

  it("--disable removes rules", () => {
    const { rules, entropy } = selectRules({ disable: ["generic-secret-assignment", "high-entropy-string"] });
    assert.ok(!rules.some((r) => r.id === "generic-secret-assignment"));
    assert.equal(rules.length, RULES.length - 1);
    assert.equal(entropy, false);
  });

  it("rejects unknown ids", () => {
    assert.throws(() => selectRules({ only: ["github-tokens"] }), /unknown rule 'github-tokens'/);
    assert.throws(() => selectRules({ disable: ["nope"] }), /unknown rule 'nope'/);
  });
});

describe("explainRule", () => {
  it("explains every rule in the catalog", () => {
    for (const { id } of ruleCatalog()) {
      const text = explainRule(id);
      assert.ok(text.startsWith(`${id} (`), id);
      assert.match(text, /What to do:/, id);
      assert.match(text, new RegExp(`--disable ${id}`), id);
    }
  });

  it("shows the pattern of a pattern rule and the idea of the entropy rule", () => {
    assert.match(explainRule("github-token"), /gh\[pousr\]_/);
    assert.match(explainRule("github-token"), /Revoke the credential/);
    assert.match(explainRule("generic-secret-assignment"), /Check whether the value is a real credential/);
    assert.match(explainRule("high-entropy-string"), /Shannon entropy/);
  });

  it("returns null for unknown rules", () => {
    assert.equal(explainRule("nope"), null);
  });
});

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

  it("finds more provider credentials", () => {
    const cases = {
      "pypi-token": PYPI_TOKEN,
      "shopify-token": SHOPIFY_TOKEN,
      "digitalocean-token": DIGITALOCEAN_TOKEN,
      "databricks-token": DATABRICKS_TOKEN,
      "sentry-auth-token": SENTRY_TOKEN,
      "square-token": SQUARE_TOKEN,
      "discord-webhook": DISCORD_WEBHOOK,
    };
    for (const [ruleId, secret] of Object.entries(cases)) {
      for (const line of [`x = "${secret}"`, `X=${secret}`, `curl ${secret} --fail`]) {
        const found = scan(line);
        assert.equal(found.length, 1, `${ruleId}: ${line}`);
        assert.equal(found[0].ruleId, ruleId, line);
        assert.equal(found[0].secret, secret);
      }
    }
    const [azure] = scan(`DefaultEndpointsProtocol=https;AccountName=demo;${AZURE_STORAGE_KEY};EndpointSuffix=core.windows.net`);
    assert.equal(azure.ruleId, "azure-storage-key");
    assert.equal(azure.secret, AZURE_STORAGE_KEY.slice("AccountKey=".length));
  });

  it("does not take look-alikes for those credentials", () => {
    const rulesOnly = (text) => scanText(text, "file.txt", RULES, { entropy: false });
    assert.deepEqual(rulesOnly("shpat_" + "0123456789abcdef0123456789abcde"), []);
    assert.deepEqual(rulesOnly("dop_v1_" + "xyz"), []);
    assert.deepEqual(rulesOnly("dapi" + "0123456789abcdef0123456789abcdez"), []);
    assert.deepEqual(rulesOnly("pypi-" + "short"), []);
    assert.deepEqual(rulesOnly("https://discord.com/channels/123/456"), []);
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

  it("finds JSON web tokens whose header decodes", () => {
    const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const jwt = `${part({ alg: "HS256", typ: "JWT" })}.${part({ sub: "1234567890", name: "Test User" })}.dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ`;
    const found = scan(`Authorization: Bearer ${jwt}`);
    assert.deepEqual(found.map((f) => [f.ruleId, f.secret]), [["jwt", jwt]]);
    const notAJwt = `${part({ foo: "bar" })}.${part({ sub: "x" })}.dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ`;
    assert.deepEqual(scan(`x = ${notAJwt}`, "file.txt").filter((f) => f.ruleId === "jwt"), []);
  });

  it("finds passwords inside URLs", () => {
    const cases = {
      "postgres://app:hunter22secret@db.internal:5432/app": "hunter22secret",
      "amqps://guest-user:Zx81!kqpL@mq.example.org/vhost": "Zx81!kqpL",
      '"https://deploy:ghx_9fK2m1Q8@git.example.com/repo.git"': "ghx_9fK2m1Q8",
    };
    for (const [line, password] of Object.entries(cases)) {
      const found = scan(`url = ${line}`);
      assert.deepEqual(found.map((f) => [f.ruleId, f.secret]), [["url-credentials", password]], line);
    }
  });

  it("ignores URLs without credentials or with placeholder passwords", () => {
    for (const line of [
      "https://example.com:8443/path", "ssh://git@github.com/org/repo.git",
      "postgres://user:password@localhost/db", "mysql://root:root@127.0.0.1/db",
      "redis://:${REDIS_PASSWORD}@cache:6379", "https://user:<password>@host/", "http://user:%s@host/",
      "postgres://app:changeme123@db/app", "https://user:{{ token }}@host/",
    ]) {
      assert.deepEqual(scanText(line, "f", RULES, { entropy: false }), [], line);
    }
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
      "aaaaaaaaaaaa", "EXAMPLE_TOKEN_VALUE", "placeholder-value", "dummyvalue123",
      "${DB_PASSWORD}", "$DB_PASSWORD", "$(cat /run/secrets/db)", "{{ vault_password }}", "<your-password>",
      "%(password)s", "process.env.DB_PASSWORD", "os.environ['DB_PASSWORD']", "DB_PASSWORD_FROM_ENV",
      "abcxxxxdef123", "ab***cdefgh"]) {
      assert.deepEqual(scan(`secret = "${value}"`), [], value);
      assert.ok(looksLikePlaceholder(value), value);
    }
    assert.ok(!looksLikePlaceholder("k8d92jfh38dh2"));
  });

  it("does not report the example keys from AWS documentation", () => {
    assert.deepEqual(scan("aws_access_key_id = " + "AKIA" + "IOSFODNN7EXAMPLE"), []);
    assert.deepEqual(scan("key: " + "ASIA" + "IOSFODNN7EXAMPLE"), []);
    assert.equal(scan("aws_access_key_id = " + AWS_KEY).length, 1);
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
    assert.deepEqual(found.map((f) => f.ruleId), ["aws-access-key-id", "aws-access-key-id", "github-token"]);
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
