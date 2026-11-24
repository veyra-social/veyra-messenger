import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __activeCallToneForTests,
  __resetCallProgressSoundsForTests,
  installCallProgressAudioUnlock,
  playCallEndCue,
  playCallProgressTone,
  stopCallProgressTone,
} from "./callProgressSounds";

class FakeOscillator {
  static started = 0;
  static stopped = 0;

  type = "";
  frequency = { value: 0 };
  onended: (() => void) | null = null;
  connect = vi.fn();
  disconnect = vi.fn();
  start = vi.fn(() => {
    FakeOscillator.started += 1;
  });
  stop = vi.fn(() => {
    FakeOscillator.stopped += 1;
  });
}

class FakeGain {
  gain = {
    setValueAtTime: vi.fn(),
    linearRampToValueAtTime: vi.fn(),
  };
  connect = vi.fn();
  disconnect = vi.fn();
}

class FakeAudioContext {
  static instances: FakeAudioContext[] = [];

  currentTime = 0;
  state = "running";
  destination = {};
  resume = vi.fn(() => Promise.resolve());
  createOscillator = vi.fn(() => new FakeOscillator());
  createGain = vi.fn(() => new FakeGain());

  constructor() {
    FakeAudioContext.instances.push(this);
  }
}

describe("outgoing call tones", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeOscillator.started = 0;
    FakeOscillator.stopped = 0;
    FakeAudioContext.instances = [];
    vi.stubGlobal("AudioContext", FakeAudioContext);
    __resetCallProgressSoundsForTests();
  });

  afterEach(() => {
    __resetCallProgressSoundsForTests();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("repeats the ringback on its cadence and stops on demand", () => {
    playCallProgressTone("call-1", "ringback");
    expect(FakeOscillator.started).toBe(1);

    // 1 s on / 4 s off: one more beep per five seconds, not per render.
    vi.advanceTimersByTime(5_000);
    expect(FakeOscillator.started).toBe(2);
    vi.advanceTimersByTime(10_000);
    expect(FakeOscillator.started).toBe(4);

    stopCallProgressTone("call-1");
    expect(__activeCallToneForTests()).toBeNull();
    vi.advanceTimersByTime(15_000);
    expect(FakeOscillator.started).toBe(4);
  });

  it("does not restart the cadence when the same tone is re-applied", () => {
    playCallProgressTone("call-1", "connecting");
    vi.advanceTimersByTime(600);
    expect(FakeOscillator.started).toBe(2);

    // A re-render asking for exactly what is already playing changes nothing.
    playCallProgressTone("call-1", "connecting");
    expect(FakeOscillator.started).toBe(2);
    vi.advanceTimersByTime(600);
    expect(FakeOscillator.started).toBe(3);
  });

  it("pulses densely enough that a fast route hunt is still heard as a pattern", () => {
    // Route hunting is often over in under a second; at a sparse period that
    // left exactly one beep, which reads as a glitch rather than a signal.
    playCallProgressTone("call-1", "connecting");
    vi.advanceTimersByTime(1_000);
    expect(FakeOscillator.started).toBeGreaterThanOrEqual(2);
  });

  it("switches from the connecting blip to the ringback without overlap", () => {
    playCallProgressTone("call-1", "connecting");
    playCallProgressTone("call-1", "ringback");
    expect(__activeCallToneForTests()).toEqual({ callId: "call-1", tone: "ringback" });

    // Two beeps so far: the connecting blip, then the first ringback. The
    // connecting cadence is dead, so its 1.6 s tick adds nothing…
    vi.advanceTimersByTime(1_600);
    expect(FakeOscillator.started).toBe(2);
    // …and the next beep is the ringback's own, at five seconds.
    vi.advanceTimersByTime(3_400);
    expect(FakeOscillator.started).toBe(3);
  });

  it("ignores a stop from a call that is no longer the active one", () => {
    playCallProgressTone("call-1", "ringback");
    stopCallProgressTone("call-1");
    playCallProgressTone("call-2", "ringback");

    // The old call's teardown arriving late must not silence the new call.
    stopCallProgressTone("call-1");
    expect(__activeCallToneForTests()).toEqual({ callId: "call-2", tone: "ringback" });
    vi.advanceTimersByTime(5_000);
    expect(__activeCallToneForTests()).not.toBeNull();
  });

  it("plays a bounded busy cadence and a two-beep ending, and kills the ringback first", () => {
    playCallProgressTone("call-1", "ringback");
    FakeOscillator.started = 0;

    // Busy: three cycles, scheduled up front — no timer keeps it alive.
    playCallEndCue("busy");
    expect(__activeCallToneForTests()).toBeNull();
    expect(FakeOscillator.started).toBe(3);
    vi.advanceTimersByTime(30_000);
    expect(FakeOscillator.started).toBe(3);

    FakeOscillator.started = 0;
    playCallEndCue("ended");
    expect(FakeOscillator.started).toBe(2);
  });

  it("keeps the end cue playing when the call screen tears down after it", () => {
    playCallEndCue("ended");
    FakeOscillator.stopped = 0;

    // The overlay unmounts right behind an ended call; its teardown must not
    // cut the cue that announces it.
    stopCallProgressTone();
    expect(FakeOscillator.stopped).toBe(0);
  });

  it("stays silent when the platform has no audio output", () => {
    __resetCallProgressSoundsForTests();
    vi.stubGlobal("AudioContext", undefined);
    expect(() => playCallProgressTone("call-1", "ringback")).not.toThrow();
    expect(FakeOscillator.started).toBe(0);
  });

  it("keeps nudging a context whose clock is not running (iOS suspension)", () => {
    // iOS: the context starts suspended and the call audio session can
    // re-interrupt it mid-call. A single resume at tone start would be lost;
    // every beep must retry so the pulse recovers on its next tick.
    playCallProgressTone("call-1", "ringback");
    const ctx = FakeAudioContext.instances[0];
    expect(ctx.resume).not.toHaveBeenCalled();

    ctx.state = "interrupted";
    vi.advanceTimersByTime(10_000);
    expect(ctx.resume).toHaveBeenCalledTimes(2);
  });

  it("unlocks the audio context on the first user gesture and then stands down", () => {
    // The tones start from call-phase events, never from the tap itself, so
    // the shared context must be activated by some earlier gesture.
    const listeners = new Map<string, EventListener>();
    vi.stubGlobal("window", {
      addEventListener: vi.fn((event: string, handler: EventListener) => {
        listeners.set(event, handler);
      }),
      removeEventListener: vi.fn((event: string) => {
        listeners.delete(event);
      }),
    });
    __resetCallProgressSoundsForTests();

    // Materialize the shared context first and freeze it the way iOS does.
    playCallProgressTone("call-1", "connecting");
    stopCallProgressTone();
    const ctx = FakeAudioContext.instances[0];
    ctx.state = "suspended";

    installCallProgressAudioUnlock();
    expect(listeners.size).toBe(3);

    // A gesture on a frozen context attempts a resume and keeps listening:
    // a refused resume mid-interruption must not burn the only try.
    const fire = () => listeners.get("pointerdown")?.(new Event("pointerdown"));
    fire();
    expect(ctx.resume).toHaveBeenCalled();
    expect(listeners.size).toBe(3);

    ctx.state = "running";
    fire();
    expect(listeners.size).toBe(0);
  });
});
