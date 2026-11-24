import { describe, expect, it, vi } from "vitest";
import {
  averageLuma,
  PosterJobQueue,
  POSTER_BLACK_LUMA,
  POSTER_VERIFIED_PREFIX,
} from "./attachmentMedia";

function rgbaFrame(r: number, g: number, b: number, pixels: number): Uint8ClampedArray {
  const data = new Uint8ClampedArray(pixels * 4);
  for (let i = 0; i < data.length; i += 4) {
    data[i] = r;
    data[i + 1] = g;
    data[i + 2] = b;
    data[i + 3] = 255;
  }
  return data;
}

describe("averageLuma", () => {
  it("reports a black frame below the poster threshold", () => {
    expect(averageLuma(rgbaFrame(0, 0, 0, 1024))).toBe(0);
    expect(averageLuma(rgbaFrame(5, 5, 5, 1024))).toBeLessThan(POSTER_BLACK_LUMA);
  });

  it("reports a lit frame above the poster threshold", () => {
    expect(averageLuma(rgbaFrame(255, 255, 255, 1024))).toBeCloseTo(255, 0);
    expect(averageLuma(rgbaFrame(64, 64, 64, 1024))).toBeGreaterThan(POSTER_BLACK_LUMA);
  });

  it("weights channels by Rec.709 (green dominates)", () => {
    const green = averageLuma(rgbaFrame(0, 128, 0, 256));
    const blue = averageLuma(rgbaFrame(0, 0, 128, 256));
    expect(green).toBeGreaterThan(blue);
    expect(green).toBeCloseTo(0.7152 * 128, 1);
  });

  it("samples sparse buffers and survives empty input", () => {
    expect(averageLuma(new Uint8ClampedArray(0))).toBe(0);
    // 3 pixels with stride 16 still samples the first pixel only.
    expect(averageLuma(rgbaFrame(200, 200, 200, 3), 16)).toBeCloseTo(200, 0);
  });
});

describe("POSTER_VERIFIED_PREFIX", () => {
  it("is the base64 of exactly three marker bytes", () => {
    expect(POSTER_VERIFIED_PREFIX).toHaveLength(4);
    expect(atob(POSTER_VERIFIED_PREFIX)).toBe("v2\0");
  });

  it("concatenates with any base64 payload without corrupting it", () => {
    // 3 marker bytes = one full base64 quantum, so prefix + base64(jpeg)
    // must decode to markerBytes + jpegBytes and slice(4) must round-trip.
    const jpeg = "\xff\xd8\xff\xe0veyra-test-bytes";
    const stored = POSTER_VERIFIED_PREFIX + btoa(jpeg);
    expect(atob(stored)).toBe("v2\0" + jpeg);
    expect(stored.slice(POSTER_VERIFIED_PREFIX.length)).toBe(btoa(jpeg));
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

describe("PosterJobQueue", () => {
  it("caps active poster decoders", async () => {
    const queue = new PosterJobQueue<number>(2);
    const first = deferred<number>();
    const second = deferred<number>();
    const third = deferred<number>();
    const controllers = [new AbortController(), new AbortController(), new AbortController()];
    const tasks = [first, second, third].map((item) => vi.fn(() => item.promise));

    const results = tasks.map((task, index) => queue.enqueue(String(index), task, controllers[index].signal));
    await Promise.resolve();
    expect(queue.stats()).toEqual({ active: 2, queued: 1, jobs: 3 });
    expect(tasks[2]).not.toHaveBeenCalled();

    first.resolve(1);
    await results[0];
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(tasks[2]).toHaveBeenCalledOnce();
    second.resolve(2);
    third.resolve(3);
    await expect(Promise.all(results)).resolves.toEqual([1, 2, 3]);
  });

  it("deduplicates jobs for the same attachment", async () => {
    const queue = new PosterJobQueue<string>(2);
    const work = deferred<string>();
    const task = vi.fn(() => work.promise);
    const first = queue.enqueue("same", task, new AbortController().signal);
    const second = queue.enqueue("same", task, new AbortController().signal);

    await Promise.resolve();
    expect(task).toHaveBeenCalledOnce();
    expect(queue.stats().jobs).toBe(1);
    work.resolve("poster");
    await expect(Promise.all([first, second])).resolves.toEqual(["poster", "poster"]);
  });

  it("removes cancelled queued work before it starts", async () => {
    const queue = new PosterJobQueue<number>(1);
    const active = deferred<number>();
    const activeTask = vi.fn(() => active.promise);
    const queuedTask = vi.fn(async () => 2);
    const activePromise = queue.enqueue("active", activeTask, new AbortController().signal);
    const queuedController = new AbortController();
    const queuedPromise = queue.enqueue("queued", queuedTask, queuedController.signal);

    await Promise.resolve();
    queuedController.abort();
    await expect(queuedPromise).rejects.toMatchObject({ name: "AbortError" });
    expect(queuedTask).not.toHaveBeenCalled();
    expect(queue.stats()).toEqual({ active: 1, queued: 0, jobs: 1 });
    active.resolve(1);
    await expect(activePromise).resolves.toBe(1);
  });

  it("restarts a cancelled-but-still-running job for a fresh subscriber", async () => {
    const queue = new PosterJobQueue<number>(1);
    // First task hangs until its signal aborts (a decoder mid-flight).
    let firstSignal: AbortSignal | undefined;
    const task = vi.fn((signal: AbortSignal) => {
      if (task.mock.calls.length === 1) {
        firstSignal = signal;
        return new Promise<number>((_, reject) => {
          signal.addEventListener("abort", () => reject(posterAbortErrorLike()), { once: true });
        });
      }
      return Promise.resolve(42);
    });

    const firstController = new AbortController();
    const firstPromise = queue.enqueue("same", task, firstController.signal);
    await Promise.resolve();
    expect(task).toHaveBeenCalledOnce();

    // Last consumer leaves while the task is still running…
    firstController.abort();
    await expect(firstPromise).rejects.toMatchObject({ name: "AbortError" });
    expect(firstSignal?.aborted).toBe(true);

    // …and a new consumer for the same attachment must get a fresh job,
    // not the dying one.
    const secondPromise = queue.enqueue("same", task, new AbortController().signal);
    await expect(secondPromise).resolves.toBe(42);
    expect(task).toHaveBeenCalledTimes(2);
    expect(queue.stats()).toEqual({ active: 0, queued: 0, jobs: 0 });
  });

  it("starts a fresh job when the same key is enqueued right after settlement", async () => {
    const queue = new PosterJobQueue<number>(1);
    const first = deferred<number>();
    let calls = 0;
    const task = vi.fn(() => {
      calls += 1;
      return calls === 1 ? first.promise : Promise.resolve(2);
    });

    const firstPromise = queue.enqueue("same", task, new AbortController().signal);
    // Re-enqueue in the continuation of the first result: this lands in the
    // microtask gap between subscriber settlement and the scheduler's
    // `finally` cleanup. The settled job must already be gone from the key
    // map, otherwise this enqueue joins it and its promise hangs forever.
    const secondPromise = firstPromise.then(() =>
      queue.enqueue("same", task, new AbortController().signal),
    );
    await Promise.resolve();
    first.resolve(1);
    await expect(firstPromise).resolves.toBe(1);
    await expect(secondPromise).resolves.toBe(2);
    expect(task).toHaveBeenCalledTimes(2);
    expect(queue.stats()).toEqual({ active: 0, queued: 0, jobs: 0 });
  });
});

function posterAbortErrorLike(): Error {
  const error = new Error("aborted");
  error.name = "AbortError";
  return error;
}
