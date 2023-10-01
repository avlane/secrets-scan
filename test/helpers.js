import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Create a temporary directory tree from {relativePath: contents}. */
export function makeTree(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-scan-"));
  for (const [name, contents] of Object.entries(files)) {
    const full = path.join(dir, ...name.split("/"));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, contents);
  }
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Collect what a command writes instead of printing it. */
export function capture() {
  const out = { stdout: "", stderr: "" };
  return {
    out,
    io: {
      stdout: { write: (text) => { out.stdout += text; } },
      stderr: { write: (text) => { out.stderr += text; } },
    },
  };
}
