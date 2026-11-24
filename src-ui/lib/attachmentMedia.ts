import { convertFileSrc } from "@tauri-apps/api/core";

/// Streaming URL for an attachment served by the backend `veyra-media`
/// protocol (chunked encrypted store, HTTP Range). `<img>`/`<video>` point
/// `src` straight at it, so no attachment bytes cross the IPC bridge as
/// base64 and video seeking works. `convertFileSrc` yields the correct
/// per-platform shape (`http(s)://veyra-media.localhost/...` on Android/
/// Windows, `veyra-media://localhost/...` on macOS/Linux) but runs its path
/// argument through encodeURIComponent — a `/` inside it becomes `%2F` and
/// Android's WebView 404s the request — so only the fixed root goes through
/// it and the id is appended as a real path segment.
export function veyraMediaUrl(attachmentId: string): string {
  return `${convertFileSrc("attachment", "veyra-media")}/${encodeURIComponent(attachmentId)}`;
}

/// Android WebView cannot play large videos over the intercepted
/// veyra-media scheme — its media pipeline never advances past the first
/// capped 206 window (next-steps/android-video-streaming.md). Video
/// elements there stream from a token-guarded loopback HTTP server with
/// honest range semantics instead. `null` until App.tsx loads the
/// port+token (and always null on desktop/iOS) — callers fall back to the
/// custom protocol, which is correct on those platforms.
let mediaServer: { port: number; token: string } | null = null;

export function setMediaServerInfo(info: { port: number; token: string } | null): void {
  mediaServer = info;
}

export function veyraVideoUrl(attachmentId: string): string {
  if (!mediaServer) return veyraMediaUrl(attachmentId);
  return `http://127.0.0.1:${mediaServer.port}/attachment/${encodeURIComponent(attachmentId)}?t=${mediaServer.token}`;
}

export function veyraVideoPosterUrl(attachmentId: string): string {
  const url = veyraVideoUrl(attachmentId);
  return url.includes("?") ? `${url}&purpose=poster` : `${url}?purpose=poster`;
}

/// Privacy-safe diagnostic label: stable within the frontend session without
/// exposing the attachment UUID in console/device logs.
export function attachmentMediaTag(attachmentId: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < attachmentId.length; index += 1) {
    hash ^= attachmentId.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function mediaUrlShape(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host || "<native>"}/attachment/<id>`;
  } catch {
    return "veyra-media:<unparsed>";
  }
}

/// Average Rec.709 luma (0–255) over an RGBA pixel buffer, sampling every
/// `sampleStride`-th pixel. Below `POSTER_BLACK_LUMA` a frame is treated as
/// effectively black — screen recordings and fade-ins start on black frames,
/// and a poster captured there reads as "no preview".
export const POSTER_BLACK_LUMA = 12;

export function averageLuma(data: ArrayLike<number>, sampleStride = 16): number {
  const step = 4 * Math.max(1, Math.floor(sampleStride));
  let total = 0;
  let count = 0;
  for (let i = 0; i + 2 < data.length; i += step) {
    total += 0.2126 * data[i] + 0.7152 * data[i + 1] + 0.0722 * data[i + 2];
    count += 1;
  }
  return count ? total / count : 0;
}

/// Marker prepended to the persisted poster payload once the multi-frame
/// luma probe has run, so the black-poster self-heal executes at most once
/// per attachment: a marked poster is trusted as-is even when black (the
/// video really is dark at every probed timestamp). The backend stores the
/// decoded bytes opaquely, and 3 marker bytes (`v2\0`) encode to exactly one
/// base64 quantum — so the marker is a fixed 4-char prefix on the base64
/// string and `slice(4)` of a marked payload is valid base64 of the JPEG.
export const POSTER_VERIFIED_PREFIX = "djIA"; // btoa("v2\0")

/// Bounded LRU of generated video-poster object URLs / data URIs, keyed by
/// attachment id, so scrolling back or reopening a chat does not redo poster
/// decoding. Evicted entries that are object URLs are revoked.
const POSTER_CACHE_LIMIT = 60;
const posterCache = new Map<string, string>();

export function getCachedPoster(attachmentId: string): string | undefined {
  const value = posterCache.get(attachmentId);
  if (value !== undefined) {
    // refresh recency
    posterCache.delete(attachmentId);
    posterCache.set(attachmentId, value);
  }
  return value;
}

export function setCachedPoster(attachmentId: string, url: string): void {
  if (posterCache.has(attachmentId)) posterCache.delete(attachmentId);
  posterCache.set(attachmentId, url);
  while (posterCache.size > POSTER_CACHE_LIMIT) {
    const oldest = posterCache.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    const evicted = posterCache.get(oldest);
    posterCache.delete(oldest);
    if (evicted && evicted.startsWith("blob:")) URL.revokeObjectURL(evicted);
  }
}

export type PosterQueueStats = {
  active: number;
  queued: number;
  jobs: number;
};

type PosterTask<T> = (signal: AbortSignal) => Promise<T>;
type PosterSubscriber<T> = {
  signal: AbortSignal;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
  onAbort: () => void;
};
type PosterJob<T> = {
  key: string;
  task: PosterTask<T>;
  controller: AbortController;
  subscribers: Map<symbol, PosterSubscriber<T>>;
  started: boolean;
};

function posterAbortError(): Error {
  const error = new Error("poster job cancelled");
  error.name = "AbortError";
  return error;
}

/// Global bounded decoder scheduler. Duplicate attachment ids share one task;
/// queued work disappears when its last mounted consumer aborts, and an active
/// task receives AbortSignal so it can release the media element immediately.
export class PosterJobQueue<T> {
  private readonly pending: PosterJob<T>[] = [];
  private readonly jobs = new Map<string, PosterJob<T>>();
  private active = 0;

  constructor(
    private readonly limit: number,
    private readonly onStats?: (stats: PosterQueueStats) => void,
  ) {
    if (!Number.isInteger(limit) || limit < 1) {
      throw new Error("poster queue limit must be at least one");
    }
  }

  stats(): PosterQueueStats {
    return { active: this.active, queued: this.pending.length, jobs: this.jobs.size };
  }

  enqueue(key: string, task: PosterTask<T>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) return Promise.reject(posterAbortError());

    let job = this.jobs.get(key);
    if (!job) {
      job = {
        key,
        task,
        controller: new AbortController(),
        subscribers: new Map(),
        started: false,
      };
      this.jobs.set(key, job);
      this.pending.push(job);
    }

    const selectedJob = job;
    const token = Symbol(key);
    const result = new Promise<T>((resolve, reject) => {
      const onAbort = () => {
        const subscriber = selectedJob.subscribers.get(token);
        if (!subscriber) return;
        selectedJob.subscribers.delete(token);
        subscriber.reject(posterAbortError());
        if (selectedJob.subscribers.size === 0) this.cancelJob(selectedJob);
      };
      selectedJob.subscribers.set(token, { signal, resolve, reject, onAbort });
      signal.addEventListener("abort", onAbort, { once: true });
    });

    this.emitStats();
    this.pump();
    return result;
  }

  private cancelJob(job: PosterJob<T>): void {
    job.controller.abort();
    // Drop the key immediately: a started task may keep running until it
    // honours the abort, and a same-key enqueue arriving meanwhile must get
    // a fresh job instead of joining this dying one.
    this.removeJob(job);
    if (!job.started) {
      const index = this.pending.indexOf(job);
      if (index >= 0) this.pending.splice(index, 1);
      this.emitStats();
      this.pump();
    }
  }

  // A newer job may already own this key (same-key enqueue after cancel or
  // settle), so only delete the map entry while it is still ours.
  private removeJob(job: PosterJob<T>): void {
    if (this.jobs.get(job.key) === job) this.jobs.delete(job.key);
  }

  private pump(): void {
    while (this.active < this.limit && this.pending.length > 0) {
      const job = this.pending.shift();
      if (!job) continue;
      if (job.subscribers.size === 0) {
        this.removeJob(job);
        continue;
      }
      job.started = true;
      this.active += 1;
      this.emitStats();
      void Promise.resolve()
        .then(() => job.task(job.controller.signal))
        .then(
          (value) => this.settle(job, (subscriber) => subscriber.resolve(value)),
          (error) => this.settle(job, (subscriber) => subscriber.reject(error)),
        )
        .finally(() => {
          this.removeJob(job);
          this.active -= 1;
          this.emitStats();
          this.pump();
        });
    }
  }

  private settle(
    job: PosterJob<T>,
    settleSubscriber: (subscriber: PosterSubscriber<T>) => void,
  ): void {
    // Synchronous with settlement — a same-key enqueue in the microtask gap
    // before `finally` runs must start a fresh job, not join a settled one.
    this.removeJob(job);
    for (const subscriber of job.subscribers.values()) {
      subscriber.signal.removeEventListener("abort", subscriber.onAbort);
      settleSubscriber(subscriber);
    }
    job.subscribers.clear();
  }

  private emitStats(): void {
    this.onStats?.(this.stats());
  }
}
