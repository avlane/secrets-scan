import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { formatJson, formatText } from "./report.js";
import { RULES } from "./rules.js";
import { scanFile } from "./scanner.js";
import { createMatcher } from "./glob.js";
import { hasBinaryExtension, walk } from "./walk.js";

const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const EXIT_CLEAN = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

const HELP = `Usage: secrets-scan [options] [PATH...]

Scan files below each PATH (default: the current directory) for likely secrets.

Options:
  -h, --help       show this help
  -v, --version    show the version
      --no-entropy do not look for high-entropy strings, only for known patterns
      --show-secrets  print the matched text instead of masking it
  -f, --format FMT  output format: text (default) or json
      --include GLOB  only scan files matching GLOB (repeatable)
      --exclude GLOB  skip files and directories matching GLOB (repeatable)

Exit status: 0 nothing found, 1 secrets found, 2 error.
`;

const OPTIONS = {
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  "no-entropy": { type: "boolean" },
  "show-secrets": { type: "boolean" },
  format: { type: "string", short: "f", default: "text" },
  include: { type: "string", multiple: true },
  exclude: { type: "string", multiple: true },
};
const FORMATS = ["text", "json"];

export async function main(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();

  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (error) {
    stderr.write(`secrets-scan: ${error.message}\nTry 'secrets-scan --help'.\n`);
    return EXIT_ERROR;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    stdout.write(HELP);
    return EXIT_CLEAN;
  }
  if (values.version) {
    stdout.write(`secrets-scan ${pkg.version}\n`);
    return EXIT_CLEAN;
  }

  if (!FORMATS.includes(values.format)) {
    stderr.write(`secrets-scan: unknown format '${values.format}' (use ${FORMATS.join(" or ")})\n`);
    return EXIT_ERROR;
  }
  const include = createMatcher(values.include ?? []);
  const exclude = createMatcher(values.exclude ?? []);
  const roots = positionals.length > 0 ? positionals : ["."];
  const findings = [];
  for (const root of roots) {
    const absoluteRoot = path.resolve(cwd, root);
    if (!fs.existsSync(absoluteRoot)) {
      stderr.write(`secrets-scan: no such file or directory: ${root}\n`);
      return EXIT_ERROR;
    }
    const files = fs.statSync(absoluteRoot).isDirectory() ? walk(absoluteRoot, { include, exclude }) : [absoluteRoot];
    const base = fs.statSync(absoluteRoot).isDirectory() ? absoluteRoot : path.dirname(absoluteRoot);
    for (const file of files) {
      if (hasBinaryExtension(file)) continue;
      const relative = path.relative(base, file).split(path.sep).join("/");
      findings.push(...scanFile(file, relative, RULES, { entropy: !values["no-entropy"] }));
    }
  }

  const options = { showSecrets: values["show-secrets"], version: pkg.version };
  stdout.write(values.format === "json" ? formatJson(findings, options) : formatText(findings, options));
  return findings.length > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}
