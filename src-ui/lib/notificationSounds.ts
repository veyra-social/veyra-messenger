import callSoundUrl from "../assets/sounds/Call1.mp3";
import inviteSoundUrl from "../assets/sounds/NewInvite.mp3";
import messageSoundUrl from "../assets/sounds/NewMessage.mp3";

type SoundKey = "message" | "invite" | "call";

type NotificationSoundPrefs = {
  notificationsEnabled: boolean;
  notificationSoundsEnabled: boolean;
  messageSoundEnabled: boolean;
  inviteSoundEnabled: boolean;
  callRingtoneEnabled: boolean;
};

const sources: Record<SoundKey, string> = {
  message: messageSoundUrl,
  invite: inviteSoundUrl,
  call: callSoundUrl,
};

// A tiny (≈0.03s, 8 kHz/8-bit/mono) WAV of pure silence. Used to "unlock" a cue
// <audio> element for later programmatic playback under WebView autoplay policy:
// we play THIS through the real element during a user gesture, so the element
// becomes user-activated, but no actual sound is emitted. This replaced the old
// "muted real cue" prime, which leaked an audible blip on macOS WKWebView
// because WKWebView does not reliably honor `muted`/`volume` on the prime.
const SILENT_WAV_DATA_URI =
  "data:audio/wav;base64,UklGRiQBAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQABAACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA";

const players = new Map<SoundKey, HTMLAudioElement>();
let unlockInstalled = false;
let unlocked = false;
let activeRingtoneCallId: string | null = null;
const silencedRingtoneCallIds = new Set<string>();
const SILENCED_RINGTONE_CALL_LIMIT = 64;
let soundPrefs: NotificationSoundPrefs = {
  notificationsEnabled: true,
  notificationSoundsEnabled: true,
  messageSoundEnabled: true,
  inviteSoundEnabled: true,
  callRingtoneEnabled: true,
};

// --- Cue burst coalescing ----------------------------------------------------
// Every incoming message/invite plays a cue, EXCEPT a rapid burst (e.g. a
// backlog of unread arriving together when the app reopens after being offline)
// which collapses to a single cue. This replaced the old startup/resume silence
// windows: those existed to mute the "startup ding", which turned out to be the
// audio-unlock prime (now silent) — and they were muting genuinely-new live
// messages for ~30s after every unlock/resume. Coalescing keeps live messages
// reliably audible while still capping a backlog burst to one sound.
const CUE_COALESCE_MS = 2_000;
let lastCueAt = 0;

// Retained as no-ops: the old silence windows no longer gate playback, but
// `notificationStartupSilence` still calls these. Cue suppression is now purely
// the burst coalescer in `playOnce`; the call ringtone is no longer gated.
export function armStartupCueSilence(_durationMs?: number) {}

export function armStartupRingtoneSilence(_durationMs?: number) {}

function canPlay(key: SoundKey): boolean {
  if (!soundPrefs.notificationsEnabled) return false;
  if (!soundPrefs.notificationSoundsEnabled) return false;
  if (key === "message") return soundPrefs.messageSoundEnabled;
  if (key === "invite") return soundPrefs.inviteSoundEnabled;
  return soundPrefs.callRingtoneEnabled;
}

export function setNotificationSoundPrefs(prefs: NotificationSoundPrefs) {
  soundPrefs = {
    notificationsEnabled: prefs.notificationsEnabled,
    notificationSoundsEnabled: prefs.notificationSoundsEnabled,
    messageSoundEnabled: prefs.messageSoundEnabled,
    inviteSoundEnabled: prefs.inviteSoundEnabled,
    callRingtoneEnabled: prefs.callRingtoneEnabled,
  };
  if (!canPlay("call")) stopCallRingtone();
}

function player(key: SoundKey): HTMLAudioElement | null {
  if (typeof Audio === "undefined") return null;
  const existing = players.get(key);
  if (existing) return existing;
  const audio = new Audio(sources[key]);
  audio.preload = "auto";
  audio.loop = key === "call";
  players.set(key, audio);
  return audio;
}

function playOnce(key: Exclude<SoundKey, "call">) {
  if (!canPlay(key)) return;
  // Coalesce a rapid burst (backlog redelivery) into a single cue; live
  // messages/invites spaced further apart than CUE_COALESCE_MS each play.
  const now = Date.now();
  if (now - lastCueAt < CUE_COALESCE_MS) return;
  lastCueAt = now;
  const audio = player(key);
  if (!audio) return;
  audio.pause();
  audio.currentTime = 0;
  void audio.play().catch(() => undefined);
}

export function installNotificationSoundUnlock() {
  if (unlockInstalled || typeof window === "undefined") return;
  unlockInstalled = true;

  const events = ["pointerdown", "keydown", "touchstart"] as const;
  const removeListeners = () => {
    for (const event of events) {
      window.removeEventListener(event, unlockAudio, true);
    }
  };
  const prime = async (key: Exclude<SoundKey, "call">) => {
    const audio = player(key);
    if (!audio) return;
    // Play SILENT content (not the real cue) through the element so it becomes
    // user-activated for later programmatic playback, with zero risk of an
    // audible blip — then restore the real cue source.
    const realSrc = audio.src || sources[key];
    try {
      audio.src = SILENT_WAV_DATA_URI;
      await audio.play();
      audio.pause();
    } catch {
      /* autoplay can reject before any gesture; nothing to clean up */
    } finally {
      audio.currentTime = 0;
      audio.src = realSrc;
      audio.load();
    }
  };
  function unlockAudio() {
    if (unlocked) return;
    void Promise.allSettled([prime("message"), prime("invite")]).finally(() => {
      unlocked = true;
      removeListeners();
    });
  }
  for (const event of events) {
    window.addEventListener(event, unlockAudio, { capture: true, passive: true });
  }
}

export function playMessageSound() {
  playOnce("message");
}

export function playInviteSound() {
  playOnce("invite");
}

export function startCallRingtone(callId: string) {
  if (!canPlay("call")) return;
  if (silencedRingtoneCallIds.has(callId)) return;
  if (activeRingtoneCallId === callId) return;
  stopCallRingtone();
  const audio = player("call");
  if (!audio) return;
  activeRingtoneCallId = callId;
  audio.loop = true;
  audio.currentTime = 0;
  void audio.play().catch(() => undefined);
}

export function silenceCallRingtone(callId: string) {
  if (!silencedRingtoneCallIds.has(callId)) {
    silencedRingtoneCallIds.add(callId);
    if (silencedRingtoneCallIds.size > SILENCED_RINGTONE_CALL_LIMIT) {
      const oldest = silencedRingtoneCallIds.values().next().value;
      if (oldest) silencedRingtoneCallIds.delete(oldest);
    }
  }
  stopCallRingtone(callId);
}

export function stopCallRingtone(callId?: string) {
  if (callId && activeRingtoneCallId && activeRingtoneCallId !== callId) return;
  const audio = players.get("call");
  if (audio) {
    audio.pause();
    audio.currentTime = 0;
  }
  activeRingtoneCallId = null;
}

const PREVIEW_RINGTONE_MS = 3000;
let previewRingtoneTimer: number | null = null;

// --- Settings preview state --------------------------------------------------
// The notifications page shows a play/stop button per cue. It subscribes here
// so the button flips back to "play" when the sound ends on its own (short
// cues end via `ended`, the ringtone preview via its 3 s timer).
export type SoundPreviewKey = SoundKey;
let activePreviewKey: SoundPreviewKey | null = null;
let previewListener: ((playing: SoundPreviewKey | null) => void) | null = null;

function setActivePreview(key: SoundPreviewKey | null) {
  activePreviewKey = key;
  previewListener?.(key);
}

/** Single-subscriber preview state feed for the notifications page. */
export function subscribeSoundPreview(
  listener: (playing: SoundPreviewKey | null) => void,
): () => void {
  previewListener = listener;
  listener(activePreviewKey);
  return () => {
    if (previewListener === listener) previewListener = null;
  };
}

/** Stops whichever settings preview is playing. Never touches a real call. */
export function stopSoundPreview() {
  const key = activePreviewKey;
  if (!key) return;
  if (previewRingtoneTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(previewRingtoneTimer);
    previewRingtoneTimer = null;
  }
  const audio = players.get(key);
  if (audio && !(key === "call" && activeRingtoneCallId)) {
    audio.pause();
    audio.currentTime = 0;
    if (key === "call") audio.loop = true;
  }
  setActivePreview(null);
}

// Explicit Settings preview: play a cue once regardless of the saved toggles so
// the user can hear the sound while configuring it. No network event is sent.
function preview(key: Exclude<SoundKey, "call">) {
  stopSoundPreview();
  const audio = player(key);
  if (!audio) return;
  audio.pause();
  audio.currentTime = 0;
  audio.onended = () => {
    if (activePreviewKey === key) setActivePreview(null);
  };
  void audio.play().catch(() => undefined);
  setActivePreview(key);
}

export function previewMessageSound() {
  preview("message");
}

export function previewInviteSound() {
  preview("invite");
}

export function previewCallRingtone() {
  // Do not collide with a real ringing call.
  if (activeRingtoneCallId) return;
  stopSoundPreview();
  const audio = player("call");
  if (!audio) return;
  if (previewRingtoneTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(previewRingtoneTimer);
    previewRingtoneTimer = null;
  }
  audio.loop = false;
  audio.pause();
  audio.currentTime = 0;
  void audio.play().catch(() => undefined);
  setActivePreview("call");
  if (typeof window !== "undefined") {
    previewRingtoneTimer = window.setTimeout(() => {
      previewRingtoneTimer = null;
      if (activePreviewKey === "call") setActivePreview(null);
      if (activeRingtoneCallId) return;
      audio.pause();
      audio.currentTime = 0;
      audio.loop = true;
    }, PREVIEW_RINGTONE_MS);
  }
}

export function __resetNotificationSoundsForTests(nowMs: number = Date.now()) {
  players.clear();
  unlockInstalled = false;
  unlocked = false;
  activeRingtoneCallId = null;
  lastCueAt = 0;
  silencedRingtoneCallIds.clear();
  soundPrefs = {
    notificationsEnabled: true,
    notificationSoundsEnabled: true,
    messageSoundEnabled: true,
    inviteSoundEnabled: true,
    callRingtoneEnabled: true,
  };
  if (previewRingtoneTimer !== null && typeof window !== "undefined") {
    window.clearTimeout(previewRingtoneTimer);
  }
  previewRingtoneTimer = null;
  activePreviewKey = null;
  previewListener = null;
}
