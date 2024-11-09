const UNITS = { "": 1, b: 1, k: 1024, kb: 1024, kib: 1024, m: 1024 ** 2, mb: 1024 ** 2, mib: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3, gib: 1024 ** 3 };

/** "1048576", "500k", "2M" or "1.5MiB" as a number of bytes. Units are powers of 1024. */
export function parseSize(text) {
  const match = /^\s*(\d+(?:\.\d+)?)\s*([a-z]*)\s*$/i.exec(text);
  const unit = match ? UNITS[match[2].toLowerCase()] : undefined;
  if (unit === undefined) throw new Error(`invalid size '${text}' (examples: 500k, 2M, 1048576)`);
  return Math.floor(Number(match[1]) * unit);
}
