import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { mapConcurrent } from "../src/pool.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe("mapConcurrent", () => {
  it("keeps the order of the items whatever order the calls finish in", async () => {
    const delays = [30, 1, 15, 1, 5];
    const result = await mapConcurrent(delays, 3, async (delay, index) => {
      await sleep(delay);
      return `${index}:${delay}`;
    });
    assert.deepEqual(result, ["0:30", "1:1", "2:15", "3:1", "4:5"]);
  });

  it("never has more than `limit` calls in flight, and uses all of them", async () => {
    let active = 0;
    let peak = 0;
    await mapConcurrent(Array.from({ length: 20 }, (_, i) => i), 4, async () => {
      active += 1;
      peak = Math.max(peak, active);
      await sleep(2);
      active -= 1;
    });
    assert.equal(peak, 4);
  });

  it("handles no items, fewer items than the limit, and a limit of one", async () => {
    assert.deepEqual(await mapConcurrent([], 8, async (x) => x), []);
    assert.deepEqual(await mapConcurrent([1, 2], 8, async (x) => x * 2), [2, 4]);
    const order = [];
    await mapConcurrent([1, 2, 3], 1, async (x) => {
      order.push(`start${x}`);
      await sleep(1);
      order.push(`end${x}`);
    });
    assert.deepEqual(order, ["start1", "end1", "start2", "end2", "start3", "end3"]);
  });

  it("rejects when a call throws", async () => {
    await assert.rejects(mapConcurrent([1, 2, 3], 2, async (x) => {
      if (x === 2) throw new Error("boom");
      return x;
    }), /boom/);
  });
});
