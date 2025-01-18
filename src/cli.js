import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { DEFAULT_ALLOWLIST_NAME, EMPTY_ALLOWLIST, isAllowed, loadAllowlist } from "./allowlist.js";
import { applyBaseline, readBaseline, writeBaseline } from "./baseline.js";
import { GitError, listStagedFiles, listTrackedFiles, readStagedFile } from "./git.js";
import { createMatcher } from "./glob.js";
import { formatJson, formatSarif, formatSummary, formatText, useColor } from "./report.js";
import { SEVERITIES, ruleCatalog, selectRules } from "./rules.js";
import { scanBuffer } from "./scanner.js";
import { parseSize } from "./size.js";
import { DEFAULT_SKIPPED_FILES, hasBinaryExtension, walk } from "./walk.js";

const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const EXIT_CLEAN = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

const HELP = `Usage: secrets-scan [options] [PATH...]

Scan files below each PATH (default: the current directory) for likely secrets.

Options:
  -h, --help       show this help
  -v, --version    show the version
      --git        scan only the files git tracks (instead of walking the directory)
      --staged     scan the content staged in git's index (for a pre-commit hook)
      --no-default-skips  also scan lock files, *.min.js and source maps
      --no-entropy do not look for high-entropy strings, only for known patterns
      --list-rules  list the detection rules and exit
      --only ID    run only this rule (repeatable); --disable ID turns a rule off
      --show-secrets  print the matched text instead of masking it
  -f, --format FMT  output format: text (default), json or sarif
      --include GLOB  only scan files matching GLOB (repeatable)
      --exclude GLOB  skip files and directories matching GLOB (repeatable)
      --allowlist FILE  entries to ignore (default: .secrets-allowlist if it exists)
      --max-size SIZE  skip files larger than SIZE, e.g. 500k or 2M (default: 1M)
      --max-line-length N  on lines longer than N characters only run the specific rules (default: 10000)
      --min-severity LEVEL  report only findings of this severity or higher: low (default), medium, high
      --baseline FILE  ignore the findings recorded in FILE; only new ones are reported
      --write-baseline FILE  record the current findings in FILE and exit 0
      --color MODE  color the text report: auto (default), always or never
  -q, --quiet       do not print the summary line on stderr

Exit status: 0 nothing found, 1 secrets found, 2 error.
`;

const OPTIONS = {
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  git: { type: "boolean" },
  staged: { type: "boolean" },
  "no-default-skips": { type: "boolean" },
  "no-entropy": { type: "boolean" },
  "list-rules": { type: "boolean" },
  only: { type: "string", multiple: true },
  disable: { type: "string", multiple: true },
  "show-secrets": { type: "boolean" },
  format: { type: "string", short: "f", default: "text" },
  include: { type: "string", multiple: true },
  exclude: { type: "string", multiple: true },
  allowlist: { type: "string" },
  "min-severity": { type: "string", default: "low" },
  "max-size": { type: "string", default: "1M" },
  "max-line-length": { type: "string", default: "10000" },
  baseline: { type: "string" },
  "write-baseline": { type: "string" },
  color: { type: "string", default: "auto" },
  quiet: { type: "boolean", short: "q" },
};
const FORMATS = ["text", "json", "sarif"];

class UsageError extends Error {}

/**
 * The files to scan for one PATH argument, as [{relative, read()}].
 * `relative` is relative to the scanned directory and uses "/" separators.
 */
function sourcesFor(absoluteRoot, { git, staged, include, exclude, skip }) {
  const stat = fs.statSync(absoluteRoot);
  if (!stat.isDirectory()) {
    return [{ relative: path.basename(absoluteRoot), read: () => fs.readFileSync(absoluteRoot) }];
  }
  let relatives;
  if (staged) {
    relatives = listStagedFiles(absoluteRoot).filter((relative) => {
      if (exclude.matches(relative)) return false;
      return include.size === 0 || include.matches(relative);
    });
  } else if (git) {
    relatives = listTrackedFiles(absoluteRoot).filter((relative) => {
      if (exclude.matches(relative)) return false;
      return include.size === 0 || include.matches(relative);
    });
  } else {
    relatives = [...walk(absoluteRoot, { include, exclude })]
      .map((file) => path.relative(absoluteRoot, file).split(path.sep).join("/"));
  }
  return relatives
    .filter((relative) => !hasBinaryExtension(relative))
    .filter((relative) => !skip.has(path.join(absoluteRoot, ...relative.split("/"))))
    .map((relative) => ({
      relative,
      read: staged
        ? () => readStagedFile(absoluteRoot, relative)
        : () => fs.readFileSync(path.join(absoluteRoot, ...relative.split("/"))),
    }));
}

export async function main(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();

  try {
    return await run(argv, { stdout, stderr, cwd, env: io.env ?? process.env });
  } catch (error) {
    if (error instanceof UsageError || error instanceof GitError) {
      stderr.write(`secrets-scan: ${error.message}\n`);
      return EXIT_ERROR;
    }
    throw error;
  }
}

async function run(argv, { stdout, stderr, cwd, env }) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (error) {
    throw new UsageError(`${error.message}\nTry 'secrets-scan --help'.`);
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
  if (values["list-rules"]) {
    const catalog = ruleCatalog();
    const width = Math.max(...catalog.map((rule) => rule.id.length));
    for (const rule of catalog) stdout.write(`${rule.id.padEnd(width)}  ${rule.severity.padEnd(6)}  ${rule.description}\n`);
    return EXIT_CLEAN;
  }
  let selection;
  try {
    selection = selectRules({ only: values.only, disable: values.disable });
  } catch (error) {
    throw new UsageError(error.message);
  }

  if (!FORMATS.includes(values.format)) {
    throw new UsageError(`unknown format '${values.format}' (use ${FORMATS.join(" or ")})`);
  }
  if (!["auto", "always", "never"].includes(values.color)) {
    throw new UsageError(`unknown color mode '${values.color}' (use auto, always or never)`);
  }
  if (!SEVERITIES.includes(values["min-severity"])) {
    throw new UsageError(`unknown severity '${values["min-severity"]}' (use ${SEVERITIES.join(", ")})`);
  }
  let maxSize;
  let maxLineLength;
  try {
    maxSize = parseSize(values["max-size"]);
    maxLineLength = parseSize(values["max-line-length"]);
  } catch (error) {
    throw new UsageError(error.message);
  }
  let allowlist = EMPTY_ALLOWLIST;
  const allowlistFile = path.resolve(cwd, values.allowlist ?? DEFAULT_ALLOWLIST_NAME);
  if (values.allowlist || fs.existsSync(allowlistFile)) {
    try {
      allowlist = loadAllowlist(allowlistFile);
    } catch (error) {
      throw new UsageError(error.code === "ENOENT" ? `cannot read allowlist: ${error.message}` : error.message);
    }
  }

  if (values.git && values.staged) throw new UsageError("--git and --staged cannot be combined");
  const context = {
    git: values.git,
    staged: values.staged,
    include: createMatcher(values.include ?? []),
    // A baseline file is full of hashes: never scan the one we are reading or writing.
    skip: new Set([values.baseline, values["write-baseline"]].filter(Boolean).map((file) => path.resolve(cwd, file))),
    exclude: createMatcher([...(values["no-default-skips"] ? [] : DEFAULT_SKIPPED_FILES), ...(values.exclude ?? [])]),
  };
  const scanOptions = { entropy: selection.entropy && !values["no-entropy"], maxLineLength };
  const roots = positionals.length > 0 ? positionals : ["."];
  let findings = [];
  let filesScanned = 0;
  let skippedLarge = 0;
  for (const root of roots) {
    const absoluteRoot = path.resolve(cwd, root);
    if (!fs.existsSync(absoluteRoot)) throw new UsageError(`no such file or directory: ${root}`);
    for (const source of sourcesFor(absoluteRoot, context)) {
      let buffer;
      try {
        buffer = source.read();
      } catch {
        continue; // vanished since it was listed, e.g. tracked but deleted
      }
      if (buffer.length > maxSize) {
        skippedLarge += 1;
        continue;
      }
      filesScanned += 1;
      findings.push(...scanBuffer(buffer, source.relative, selection.rules, scanOptions));
    }
  }
  const minimum = SEVERITIES.indexOf(values["min-severity"]);
  findings = findings.filter((f) => !isAllowed(f, allowlist) && SEVERITIES.indexOf(f.severity) >= minimum);

  if (values["write-baseline"]) {
    writeBaseline(path.resolve(cwd, values["write-baseline"]), findings);
    stderr.write(`secrets-scan: wrote ${findings.length} finding${findings.length === 1 ? "" : "s"} to ${values["write-baseline"]}\n`);
    return EXIT_CLEAN;
  }
  let baselined = 0;
  if (values.baseline) {
    let baseline;
    try {
      baseline = readBaseline(path.resolve(cwd, values.baseline));
    } catch (error) {
      throw new UsageError(error.message);
    }
    const split = applyBaseline(findings, baseline);
    findings = split.fresh;
    baselined = split.known.length;
  }

  const options = {
    showSecrets: values["show-secrets"],
    version: pkg.version,
    color: useColor(values.color, stdout, env),
  };
  if (values.format === "json") stdout.write(formatJson(findings, options));
  else if (values.format === "sarif") stdout.write(formatSarif(findings, { ...options, catalog: ruleCatalog() }));
  else stdout.write(formatText(findings, options));
  if (!values.quiet) stderr.write(formatSummary(findings, filesScanned, { baselined, skippedLarge }));
  return findings.length > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}
