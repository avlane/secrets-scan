import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { compileGlob, createMatcher } from "../src/glob.js";

const matches = (pattern, file, isDirectory = false) => compileGlob(pattern).test(file, isDirectory);

describe("globs without a slash match names anywhere", () => {
  it("matches files and directories by name", () => {
    assert.ok(matches("*.min.js", "a/b/app.min.js"));
    assert.ok(matches("*.min.js", "app.min.js"));
    assert.ok(!matches("*.min.js", "app.js"));
    assert.ok(matches("node_modules", "x/node_modules/y/z.js"));
    assert.ok(!matches("node_modules", "x/my_node_modules/z.js"));
  });

  it("supports ? and character classes", () => {
    assert.ok(matches("file?.txt", "d/file1.txt"));
    assert.ok(!matches("file?.txt", "d/file10.txt"));
    assert.ok(matches("log[0-9].txt", "log7.txt"));
    assert.ok(!matches("log[!0-9].txt", "log7.txt"));
    assert.ok(matches("a[b", "a[b"));
  });

  it("treats regex metacharacters literally", () => {
    assert.ok(matches("a+b(1).txt", "a+b(1).txt"));
    assert.ok(!matches("a.txt", "abtxt"));
  });

  it("directory-only patterns do not match plain files", () => {
    assert.ok(matches("build/", "build/out.js"));
    assert.ok(matches("build/", "x/build", true));
    assert.ok(!matches("build/", "x/build"));
  });
});

describe("globs with a slash are anchored", () => {
  it("match from the scan root, and below matching directories", () => {
    assert.ok(matches("docs/generated", "docs/generated"));
    assert.ok(matches("docs/generated", "docs/generated/api/index.html"));
    assert.ok(!matches("docs/generated", "x/docs/generated"));
    assert.ok(matches("/docs", "docs/a.md"));
  });

  it("star stays inside one directory, double star does not", () => {
    assert.ok(matches("src/*.js", "src/a.js"));
    assert.ok(!matches("src/*.js", "src/deep/a.js"));
    assert.ok(matches("src/**/*.js", "src/a.js"));
    assert.ok(matches("src/**/*.js", "src/deep/er/a.js"));
    assert.ok(matches("**/fixtures/*.json", "test/fixtures/a.json"));
    assert.ok(matches("**/fixtures/*.json", "fixtures/a.json"));
    assert.ok(matches("logs/**", "logs/a/b"));
  });
});

describe("leading ./", () => {
  it("is ignored, so ./docs/gen and docs/gen are the same pattern", () => {
    assert.ok(matches("./docs/generated", "docs/generated/api.html"));
    assert.ok(matches("./docs/generated/", "docs/generated/api.html"));
    assert.ok(!matches("./docs/generated", "x/docs/generated"));
    assert.ok(matches("././src/**/*.js", "src/a/b.js"));
    assert.ok(matches("./*.md", "README.md") && matches("./*.md", "docs/README.md"));
  });

  it("a lone ./ is not a pattern", () => {
    assert.equal(compileGlob("./"), null);
    assert.ok(!createMatcher(["./"]).matches("anything"));
  });
});

describe("createMatcher", () => {
  it("matches if any pattern does, ignores blanks", () => {
    const matcher = createMatcher(["*.md", "  ", "vendor/"]);
    assert.equal(matcher.size, 2);
    assert.ok(matcher.matches("README.md"));
    assert.ok(matcher.matches("vendor/x.js"));
    assert.ok(!matcher.matches("src/x.js"));
  });

  it("an empty matcher matches nothing", () => {
    assert.ok(!createMatcher([]).matches("anything"));
  });
});
