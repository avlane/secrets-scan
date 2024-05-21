import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { DEFAULT_ALLOWLIST_NAME, EMPTY_ALLOWLIST, isAllowed, loadAllowlist } from "./allowlist.js";
import { applyBaseline, readBaseline, writeBaseline } from "./baseline.js";
import { GitError, listTrackedFiles } from "./git.js";
import { createMatcher } from "./glob.js";
import { formatJson, formatSarif, formatSummary, formatText, useColor } from "./report.js";
import { RULES, ruleCatalog } from "./rules.js";
import { scanBuffer } from "./scanner.js";
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
      --no-default-skips  also scan lock files, *.min.js and source maps
      --no-entropy do not look for high-entropy strings, only for known patterns
      --show-secrets  print the matched text instead of masking it
  -f, --format FMT  output format: text (default), json or sarif
      --include GLOB  only scan files matching GLOB (repeatable)
      --exclude GLOB  skip files and directories matching GLOB (repeatable)
      --allowlist FILE  entries to ignore (default: .secrets-allowlist if it exists)
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
  "no-default-skips": { type: "boolean" },
  "no-entropy": { type: "boolean" },
  "show-secrets": { type: "boolean" },
  format: { type: "string", short: "f", default: "text" },
  include: { type: "string", multiple: true },
  exclude: { type: "string", multiple: true },
  allowlist: { type: "string" },
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
function sourcesFor(absoluteRoot, { git, include, exclude, skip }) {
  const stat = fs.statSync(absoluteRoot);
  if (!stat.isDirectory()) {
    return [{ relative: path.basename(absoluteRoot), read: () => fs.readFileSync(absoluteRoot) }];
  }
  let relatives;
  if (git) {
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
    .map((relative) => ({ relative, read: () => fs.readFileSync(path.join(absoluteRoot, ...relative.split("/"))) }));
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

  if (!FORMATS.includes(values.format)) {
    throw new UsageError(`unknown format '${values.format}' (use ${FORMATS.join(" or ")})`);
  }
  if (!["auto", "always", "never"].includes(values.color)) {
    throw new UsageError(`unknown color mode '${values.color}' (use auto, always or never)`);
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

  const context = {
    git: values.git,
    include: createMatcher(values.include ?? []),
    // A baseline file is full of hashes: never scan the one we are reading or writing.
    skip: new Set([values.baseline, values["write-baseline"]].filter(Boolean).map((file) => path.resolve(cwd, file))),
    exclude: createMatcher([...(values["no-default-skips"] ? [] : DEFAULT_SKIPPED_FILES), ...(values.exclude ?? [])]),
  };
  const scanOptions = { entropy: !values["no-entropy"] };
  const roots = positionals.length > 0 ? positionals : ["."];
  let findings = [];
  let filesScanned = 0;
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
      filesScanned += 1;
      findings.push(...scanBuffer(buffer, source.relative, RULES, scanOptions));
    }
  }
  findings = findings.filter((f) => !isAllowed(f, allowlist));

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
  if (!values.quiet) stderr.write(formatSummary(findings, filesScanned, { baselined }));
  return findings.length > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}
