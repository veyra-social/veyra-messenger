// Local foreground haptics for notification events while the app process is
// alive. Android (Chromium WebView) vibrates through the Web Vibration API,
// which only needs the manifest VIBRATE permission, not OS notification
// permission. iOS WKWebView does not implement `navigator.vibrate`, so the
// native `trigger_haptic` Tauri command provides UIKit feedback there. Both
// paths are mutually exclusive per platform (iOS has no Web Vibration API;
// Android's native command returns "unsupported"), so firing both is safe and
// never double-buzzes real hardware. Desktop has no vibration hardware and
// silently no-ops. Everything here is best-effort and respects the master
// notification switch plus a separate vibration toggle.

import { api } from "./tauriApi";

type HapticKind = "message" | "invite" | "call";

type HapticPrefs = {
  notificationsEnabled: boolean;
  vibrationEnabled: boolean;
};

// Web Vibration API patterns in milliseconds. Call uses a stronger, longer
// pattern so an incoming call is harder to miss than ordinary chat traffic.
const WEB_PATTERNS: Record<HapticKind, number | number[]> = {
  message: 20,
  invite: [0, 30, 60, 30],
  call: [0, 400, 200, 400],
};

const CALL_HAPTIC_INTERVAL_MS = 2200;

let hapticPrefs: HapticPrefs = {
  notificationsEnabled: true,
  vibrationEnabled: true,
};
let callHapticTimer: number | null = null;
let activeCallHapticId: string | null = null;

function canVibrate(): boolean {
  return hapticPrefs.notificationsEnabled && hapticPrefs.vibrationEnabled;
}

function fire(kind: HapticKind) {
  if (!canVibrate()) return;
  // Native iOS path (no-op / "unsupported" elsewhere).
  void api.triggerHaptic(kind).catch(() => undefined);
  // Web Vibration API path (Android WebView; no-op on iOS/desktop).
  if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
    try {
      navigator.vibrate(WEB_PATTERNS[kind]);
    } catch {
      /* best effort only */
    }
  }
}

export function setHapticPrefs(prefs: HapticPrefs) {
  hapticPrefs = {
    notificationsEnabled: prefs.notificationsEnabled,
    vibrationEnabled: prefs.vibrationEnabled,
  };
  if (!canVibrate()) stopCallHaptic();
}

export function triggerMessageHaptic() {
  fire("message");
}

export function triggerInviteHaptic() {
  fire("invite");
}

export function startCallHaptic(callId: string) {
  if (!canVibrate()) return;
  if (activeCallHapticId === callId) return;
  stopCallHaptic();
  activeCallHapticId = callId;
  fire("call");
  if (typeof window !== "undefined") {
    callHapticTimer = window.setInterval(() => fire("call"), CALL_HAPTIC_INTERVAL_MS);
  }
}

export function stopCallHaptic(callId?: string) {
  if (callId && activeCallHapticId && activeCallHapticId !== callId) return;
  if (callHapticTimer !== null && typeof window !== "undefined") {
    window.clearInterval(callHapticTimer);
  }
  callHapticTimer = null;
  activeCallHapticId = null;
  if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
    try {
      navigator.vibrate(0);
    } catch {
      /* best effort only */
    }
  }
}
