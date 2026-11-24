// Thin wrapper around the JavaScriptInterface exposed by MainActivity's
// VeyraNativeBridge on Android. Each call resolves synchronously through
// the WebView bridge and returns a JSON envelope `{ ok: boolean, ... }`.
// Returns `false` on non-Android platforms or when the bridge is missing.
//
// Call-audio routing has an iOS twin: WKWebView exposes no JS bridge object,
// so those three calls fall back to Tauri commands (`call_audio_session_*`,
// AVAudioSession under the hood) fired asynchronously — the sync `boolean`
// contract of this module is preserved by reporting availability, not the
// (unknowable) immediate result. 2026-07-16 field report: without this an
// iPhone call is stuck on the loud speaker with no route toggle.

import { invoke } from "@tauri-apps/api/core";
import { isIosUserAgent } from "./usePlatform";

const iosCallAudio =
  typeof navigator !== "undefined" && isIosUserAgent(navigator.userAgent);

type Envelope = { ok: boolean; error?: string };

type NativeBridge = {
  openAppSettings?: () => string;
  startCallAudio?: (speaker: boolean) => string;
  setSpeakerphone?: (on: boolean) => string;
  setKeepScreenOn?: (enabled: boolean) => string;
  setChatKeepScreenOn?: (enabled: boolean) => string;
  setBackupKeepScreenOn?: (enabled: boolean) => string;
  stopCallAudio?: () => string;
  isIgnoringBatteryOptimizations?: () => string;
  requestBatteryExemption?: () => string;
  openBatteryOptimizationSettings?: () => string;
  shareBase64File?: (fileName: string, mimeType: string, b64: string) => string;
};

function getBridge(): NativeBridge | null {
  if (typeof window === "undefined") return null;
  const candidate = (window as Window & { VeyraNative?: unknown }).VeyraNative;
  return (candidate as NativeBridge) ?? null;
}

function safeParse(raw: string): Envelope {
  try {
    const parsed = JSON.parse(raw) as Envelope;
    if (typeof parsed?.ok !== "boolean") return { ok: false, error: "bad envelope" };
    return parsed;
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Open the system "App info" screen for the current package so the user can
 * grant a runtime permission that Android marked USER_FIXED. Used by Phase A
 * voice calls when `getUserMedia` is denied without showing a permission
 * dialog. Returns `true` only when the native bridge is available and the
 * intent dispatched successfully.
 */
export function openAppSettings(): boolean {
  const bridge = getBridge();
  if (!bridge?.openAppSettings) return false;
  const env = safeParse(bridge.openAppSettings());
  return env.ok;
}

export function isNativeBridgeAvailable(): boolean {
  return !!getBridge();
}

/**
 * Enters the native Android voice-call audio session (communication mode +
 * audio focus, earpiece by default unless `speaker`). WebRTC audio in the
 * WebView otherwise stays on the media path. Returns `true` only when the
 * native bridge applied it; no-op (`false`) on platforms without the bridge.
 */
export function startCallAudio(speaker = false): boolean {
  const bridge = getBridge();
  if (bridge?.startCallAudio) return safeParse(bridge.startCallAudio(speaker)).ok;
  if (iosCallAudio) {
    void invoke("call_audio_session_start", { speaker }).catch(() => undefined);
    return true;
  }
  return false;
}

/** Switches the in-call route between earpiece (`false`) and loudspeaker (`true`). */
export function setSpeakerphone(on: boolean): boolean {
  const bridge = getBridge();
  if (bridge?.setSpeakerphone) return safeParse(bridge.setSpeakerphone(on)).ok;
  if (iosCallAudio) {
    void invoke("call_audio_session_set_speaker", { on }).catch(() => undefined);
    return true;
  }
  return false;
}

/**
 * Requests or releases the user's manual "keep the screen on" preference on
 * Android. Its own native slot, so it neither clobbers nor is clobbered by the
 * call / chat / backup requests; the Activity re-applies the flag on resume, so
 * one call per preference change is enough and backgrounding still lets the
 * display sleep.
 */
export function setKeepScreenOn(enabled: boolean): boolean {
  const bridge = getBridge();
  if (!bridge?.setKeepScreenOn) return false;
  return safeParse(bridge.setKeepScreenOn(enabled)).ok;
}

/**
 * Requests or releases Android keep-screen-on for the currently visible chat.
 * The native side tracks this separately from call audio, so releasing a chat
 * window cannot turn the screen off during an active call.
 */
export function setChatKeepScreenOn(enabled: boolean): boolean {
  const bridge = getBridge();
  if (!bridge?.setChatKeepScreenOn) return false;
  return safeParse(bridge.setChatKeepScreenOn(enabled)).ok;
}

/**
 * Requests or releases Android keep-screen-on for a running backup export or
 * restore, so display auto-lock cannot interrupt a multi-minute operation.
 * Its own native slot: releasing it never clobbers call/chat/manual requests.
 */
export function setBackupKeepScreenOn(enabled: boolean): boolean {
  const bridge = getBridge();
  if (!bridge?.setBackupKeepScreenOn) return false;
  return safeParse(bridge.setBackupKeepScreenOn(enabled)).ok;
}

/** Leaves the native Android voice-call audio session and restores prior routing. */
export function stopCallAudio(): boolean {
  const bridge = getBridge();
  if (bridge?.stopCallAudio) return safeParse(bridge.stopCallAudio()).ok;
  if (iosCallAudio) {
    void invoke("call_audio_session_stop").catch(() => undefined);
    return true;
  }
  return false;
}

/** Whether the native speaker-route control is available (Android bridge or iOS session). */
export function isCallAudioRoutingAvailable(): boolean {
  return !!getBridge()?.setSpeakerphone || iosCallAudio;
}

/** Whether the battery-optimization exemption bridge is available (Android). */
export function isBatteryExemptionSupported(): boolean {
  return !!getBridge()?.requestBatteryExemption;
}

/**
 * Whether Veyra is currently excluded from Android battery optimization.
 * Returns `null` when the bridge is unavailable (non-Android) or the query
 * failed, so callers can distinguish "not exempt" (`false`) from "unknown".
 */
export function isIgnoringBatteryOptimizations(): boolean | null {
  const bridge = getBridge();
  if (!bridge?.isIgnoringBatteryOptimizations) return null;
  const env = safeParse(bridge.isIgnoringBatteryOptimizations()) as Envelope & {
    ignoring?: boolean;
  };
  if (!env.ok) return null;
  return !!env.ignoring;
}

/**
 * Opens the system "ignore battery optimizations?" dialog so aggressive OEM
 * power management does not kill the background connectivity service. The grant
 * result is asynchronous; re-read {@link isIgnoringBatteryOptimizations} after
 * the user returns to the app. Returns `true` only when the dialog was launched.
 */
export function requestBatteryExemption(): boolean {
  const bridge = getBridge();
  if (!bridge?.requestBatteryExemption) return false;
  return safeParse(bridge.requestBatteryExemption()).ok;
}

/**
 * Opens the system battery-optimization list. Android has no API to revoke an
 * exemption, so turning background activity back off routes the user here.
 * Returns `true` only when the settings screen was launched.
 */
export function openBatteryOptimizationSettings(): boolean {
  const bridge = getBridge();
  if (!bridge?.openBatteryOptimizationSettings) return false;
  return safeParse(bridge.openBatteryOptimizationSettings()).ok;
}

export function shareBase64File(fileName: string, mimeType: string, b64: string): boolean {
  const bridge = getBridge();
  if (!bridge?.shareBase64File) return false;
  return safeParse(bridge.shareBase64File(fileName, mimeType, b64)).ok;
}
