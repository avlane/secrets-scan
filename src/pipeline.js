import { mapConcurrent } from "./pool.js";
import { scanBuffer } from "./scanner.js";
import { looksBinary } from "./walk.js";

export const DEFAULT_CONCURRENCY = 16;

/**
 * Read and scan sources ({relative, read()}) with several reads in flight.
 * Findings come back in the order of the sources, so reports are deterministic.
 */
export async function scanSources(sources, { rules, scanOptions, maxSize, warn = () => {}, note = () => {}, concurrency = DEFAULT_CONCURRENCY }) {
  const stats = { filesScanned: 0, skippedLarge: 0, unreadable: 0 };
  const perSource = await mapConcurrent(sources, concurrency, async (source) => {
    let buffer;
    try {
      buffer = await source.read();
    } catch (error) {
      if (error.code === "ENOENT") return []; // vanished since it was listed, e.g. tracked but deleted
      stats.unreadable += 1;
      warn(`cannot read ${source.relative}: ${error.code ?? error.message}`);
      return [];
    }
    if (buffer.length > maxSize) {
      stats.skippedLarge += 1;
      note(`skipped (larger than --max-size): ${source.relative}`);
      return [];
    }
    if (looksBinary(buffer)) {
      note(`skipped binary file: ${source.relative}`);
      return [];
    }
    stats.filesScanned += 1;
    return scanBuffer(buffer, source.relative, rules, scanOptions);
  });
  return { findings: perSource.flat(), ...stats };
}
