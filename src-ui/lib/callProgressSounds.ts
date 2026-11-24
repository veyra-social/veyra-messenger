// Local audio feedback while a call is being set up — outgoing and
// incoming alike. The pulse covers every stretch where the app is working
// and the user is holding a silent phone: route hunting before the invite,
// and media negotiation right after someone taps "Ответить".
//
// The tones are synthesized, not shipped as assets: a ringback IS a plain
// 425 Hz tone on a 1 s / 4 s cadence (the European pattern every phone user
// has heard for decades), and generating it gives exact timing, no decode
// latency and no half-second of stale buffer left ringing after the peer
// picks up.
//
// Ratified 2026-07-29: these tones obey NO setting. A ringback is not a
// notification — the user pressed "call" and is looking at the screen — and
// silence during dialing is a missing basic, not a feature to opt into.
// Nothing here touches the WebRTC track: it is playback on this device only.

export type CallProgressTone = "connecting" | "ringback";

/**
 * How a finished call sounds.
 *
 * `busy` is the classic "занято" cadence (425 Hz, 0.35 s on / 0.35 s off) —
 * but bounded to three cycles. On a landline that pattern repeats until you
 * put the handset down; here there is no handset, the screen closes itself,
 * and a loop would just nag.
 *
 * `ended` is a single descending pair: the call is over, nothing went wrong.
 */
export type CallEndCue = "busy" | "ended";

type ToneShape = {
  /** Hz of the beep. */
  frequency: number;
  /** How long one beep lasts, ms. */
  beepMs: number;
  /** Beep-to-beep period, ms (beep + the silence after it). */
  periodMs: number;
  /** Peak gain, 0..1. */
  peak: number;
  /** Fade-in, seconds. Longer than default = softer onset, no click. */
  attackS?: number;
};

const SHAPES: Record<CallProgressTone, ToneShape> = {
  // Route hunting is usually over in well under a second, so this has to be
  // a dense pulse, not a sparse blip: at the old 1.6 s period the phase
  // ended after a single beep, which landed as an odd little clunk followed
  // by dead air (field report 2026-07-29). A 0.6 s pulse reads as "working"
  // even when it only gets to play twice, and its slow fade-in keeps the
  // first pulse from sounding like a click.
  connecting: { frequency: 400, beepMs: 120, periodMs: 600, peak: 0.045, attackS: 0.04 },
  // The familiar ringback: 425 Hz, one second on, four seconds off.
  ringback: { frequency: 425, beepMs: 1000, periodMs: 5000, peak: 0.12 },
};

/** Click-free envelope edges. */
const ATTACK_S = 0.015;
const RELEASE_S = 0.04;

/** Busy cadence repeats, then stops itself — there is no handset to hang up. */
const BUSY_CYCLES = 3;

type AudioContextCtor = new () => AudioContext;

let context: AudioContext | null = null;
let timer: ReturnType<typeof setInterval> | undefined;
let activeCallId: string | null = null;
let activeTone: CallProgressTone | null = null;
let liveOscillators: OscillatorNode[] = [];

function audioContext(): AudioContext | null {
  if (context) return context;
  const scope = globalThis as unknown as {
    AudioContext?: AudioContextCtor;
    webkitAudioContext?: AudioContextCtor;
  };
  const ctor = scope.AudioContext ?? scope.webkitAudioContext;
  if (!ctor) return null;
  try {
    context = new ctor();
  } catch {
    // No audio output available: dialing stays silent, the call still works.
    return null;
  }
  return context;
}

// iOS WKWebView is the reason this exists twice (here and at tone start).
// The tones begin from a React effect on a call-phase event — outside any
// user-gesture call stack — and WebKit keeps a context that was not activated
// by a gesture in "suspended"; switching the device into the call audio
// session can additionally push it into WebKit's non-standard "interrupted".
// A beep scheduled on a stopped clock is pure silence with no error, so every
// beep re-checks and nudges the clock; the pulse recovers on its next tick.
function ensureRunning(ctx: AudioContext) {
  if (ctx.state !== "running") {
    void ctx.resume().catch(() => undefined);
  }
}

function beep(shape: ToneShape, delayMs = 0, track = true) {
  const ctx = audioContext();
  if (!ctx) return;
  ensureRunning(ctx);
  const startedAt = ctx.currentTime + delayMs / 1000;
  const endsAt = startedAt + shape.beepMs / 1000;
  const oscillator = ctx.createOscillator();
  const gain = ctx.createGain();
  oscillator.type = "sine";
  oscillator.frequency.value = shape.frequency;
  // Ramped edges: a square-edged beep clicks on every repetition.
  const attackS = shape.attackS ?? ATTACK_S;
  gain.gain.setValueAtTime(0, startedAt);
  gain.gain.linearRampToValueAtTime(shape.peak, startedAt + attackS);
  gain.gain.setValueAtTime(shape.peak, endsAt - RELEASE_S);
  gain.gain.linearRampToValueAtTime(0, endsAt);
  oscillator.connect(gain);
  gain.connect(ctx.destination);
  oscillator.onended = () => {
    liveOscillators = liveOscillators.filter((live) => live !== oscillator);
    try {
      oscillator.disconnect();
      gain.disconnect();
    } catch {
      // Already torn down.
    }
  };
  // End cues are deliberately untracked: they are short, finite and already
  // scheduled to stop themselves, and the teardown that follows a finished
  // call must not cut the very sound that announces it.
  if (track) liveOscillators.push(oscillator);
  oscillator.start(startedAt);
  oscillator.stop(endsAt);
}

function silence() {
  if (timer !== undefined) {
    clearInterval(timer);
    timer = undefined;
  }
  for (const oscillator of liveOscillators.splice(0)) {
    try {
      oscillator.stop();
      oscillator.disconnect();
    } catch {
      // Already stopped by its own schedule.
    }
  }
}

let unlockInstalled = false;

/**
 * Companion of `installNotificationSoundUnlock`, for the WebAudio side. On
 * iOS WKWebView an AudioContext only starts its clock when it was created or
 * resumed inside a user gesture; the call tones start from a call-phase event,
 * which never is one. So the shared context is created and resumed on the
 * first gesture anywhere in the app — by the time anyone dials, the clock is
 * already running. Field case 2026-07-30: iPhone, "вызов отправлен", phases
 * moving, total silence. No-ops outside a browser and on repeated installs.
 *
 * Unlike the notification prime this does not give up after the first
 * attempt: the listeners stay until the context actually reports "running",
 * because a resume refused mid-interruption would otherwise burn the only try.
 */
export function installCallProgressAudioUnlock() {
  if (unlockInstalled || typeof window === "undefined") return;
  unlockInstalled = true;

  const events = ["pointerdown", "keydown", "touchstart"] as const;
  const removeListeners = () => {
    for (const event of events) {
      window.removeEventListener(event, unlock, true);
    }
  };
  function unlock() {
    const ctx = audioContext();
    if (!ctx) {
      removeListeners();
      return;
    }
    if (ctx.state === "running") {
      removeListeners();
      return;
    }
    void ctx
      .resume()
      .then(() => {
        if (ctx.state === "running") removeListeners();
      })
      .catch(() => undefined);
  }
  for (const event of events) {
    window.addEventListener(event, unlock, { capture: true, passive: true });
  }
}

/**
 * Starts (or keeps) the tone of one outgoing call. Calling it again with the
 * same call and tone is a no-op, so a re-render cannot restart a cadence
 * mid-beep; a different tone for the same call switches atomically.
 */
export function playCallProgressTone(callId: string, tone: CallProgressTone) {
  if (activeCallId === callId && activeTone === tone) return;
  silence();
  activeCallId = callId;
  activeTone = tone;
  const ctx = audioContext();
  if (!ctx) return;
  ensureRunning(ctx);
  const shape = SHAPES[tone];
  beep(shape);
  timer = setInterval(() => beep(shape), shape.periodMs);
}

/**
 * Plays the short cue of a finished call, once. The whole pattern is
 * scheduled on the audio clock up front, so it survives the teardown of the
 * call screen that triggered it and cannot leave a tone hanging.
 *
 * Deliberately silent for calls YOU ended: on a real phone, putting the
 * handset down makes no sound, and the app already says what happened.
 */
export function playCallEndCue(cue: CallEndCue) {
  // Whatever was dialing is over the moment the call is.
  stopCallProgressTone();
  if (cue === "busy") {
    const shape: ToneShape = { frequency: 425, beepMs: 350, periodMs: 700, peak: 0.1 };
    for (let index = 0; index < BUSY_CYCLES; index += 1) {
      beep(shape, index * shape.periodMs, false);
    }
    return;
  }
  // Ended: a descending pair, short enough to land inside the closing screen.
  beep({ frequency: 425, beepMs: 120, periodMs: 0, peak: 0.09 }, 0, false);
  beep({ frequency: 350, beepMs: 120, periodMs: 0, peak: 0.09 }, 210, false);
}

/**
 * Stops the tone. A `callId` from a call that is no longer the active one is
 * ignored: an ended call must never silence the call that replaced it.
 */
export function stopCallProgressTone(callId?: string) {
  if (callId && activeCallId && callId !== activeCallId) return;
  silence();
  activeCallId = null;
  activeTone = null;
}

/** Test seam: drops all state, including the shared AudioContext. */
export function __resetCallProgressSoundsForTests() {
  silence();
  activeCallId = null;
  activeTone = null;
  context = null;
  unlockInstalled = false;
}

/** Test seam: what is playing right now, if anything. */
export function __activeCallToneForTests(): { callId: string; tone: CallProgressTone } | null {
  return activeCallId && activeTone ? { callId: activeCallId, tone: activeTone } : null;
}
