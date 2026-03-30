import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { RULES } from "../src/rules.js";
import { decodeText, scanBuffer } from "../src/scanner.js";
import { AWS_KEY } from "./fakes.js";

const utf16le = (text, bom = true) => Buffer.concat([bom ? Buffer.from([0xff, 0xfe]) : Buffer.alloc(0), Buffer.from(text, "utf16le")]);
const utf16be = (text) => Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(text, "utf16le").swap16()]);

describe("decodeText", () => {
  it("decodes plain UTF-8 and strips a UTF-8 byte order mark", () => {
    assert.equal(decodeText(Buffer.from("café ✓")), "café ✓");
    assert.equal(decodeText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("KEY=1")])), "KEY=1");
  });

  it("decodes UTF-16 in both byte orders when there is a byte order mark", () => {
    assert.equal(decodeText(utf16le("KEY=é中\n")), "KEY=é中\n");
    assert.equal(decodeText(utf16be("KEY=é中\n")), "KEY=é中\n");
  });

  it("tolerates a truncated UTF-16 file", () => {
    assert.equal(decodeText(Buffer.concat([utf16be("abc"), Buffer.from([0x00])])), "abc");
  });

  it("calls anything else with NUL bytes binary", () => {
    assert.equal(decodeText(Buffer.from([0x50, 0x4b, 0x03, 0x00, 0x04])), null);
    assert.equal(decodeText(utf16le("KEY=1", false)), null); // no BOM: indistinguishable from binary
    assert.equal(decodeText(Buffer.alloc(0)), "");
  });
});

describe("scanBuffer", () => {
  it("finds secrets in UTF-16 files", () => {
    for (const buffer of [utf16le(`# settings\r\nKEY=${AWS_KEY}\r\n`), utf16be(`# settings\r\nKEY=${AWS_KEY}\r\n`)]) {
      const [finding] = scanBuffer(buffer, "settings.ini", RULES, { entropy: false });
      assert.equal(finding.ruleId, "aws-access-key-id");
      assert.deepEqual([finding.line, finding.column], [2, 5]);
    }
  });

  it("columns on the first line are not shifted by a byte order mark", () => {
    const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${AWS_KEY}\n`)]);
    assert.equal(scanBuffer(withBom, "a.txt", RULES, { entropy: false })[0].column, 1);
  });

  it("still skips binary content", () => {
    assert.deepEqual(scanBuffer(Buffer.from(`\0${AWS_KEY}`), "a.bin", RULES), []);
  });
});
