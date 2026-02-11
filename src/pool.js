/**
 * Map `items` through the async function `fn` with at most `limit` calls in flight.
 * Results are in the order of `items`, whatever order the calls finish in.
 */
export async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
