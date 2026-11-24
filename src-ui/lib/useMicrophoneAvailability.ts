import { useEffect, useState } from "react";
import { api } from "./tauriApi";

export type MicrophoneAvailability = "checking" | "available" | "unavailable" | "unknown";

const CACHE_TTL_MS = 30_000;

let cachedAvailability: { value: MicrophoneAvailability; checkedAt: number } | null = null;

function canUseMediaDevices(): boolean {
  return typeof navigator !== "undefined" && !!navigator.mediaDevices;
}

// Permission state is the only safe passive reason to reject a call.
// Android WebView may expose stub inputs while permission is denied, while
// macOS WKWebView may expose no input before its first capture permission.
// `Permissions.query({ name: "microphone" })` is silent — it does not show
// any system dialog — and returns `granted` / `denied` / `prompt`. We treat
// `prompt` as "unknown" so the rest of the call flow can still try
// `getUserMedia` interactively (which is what triggers the system dialog).
async function queryMicrophonePermission(): Promise<MicrophoneAvailability | null> {
  if (typeof navigator === "undefined" || !navigator.permissions?.query) return null;
  try {
    const status = await navigator.permissions.query({ name: "microphone" as PermissionName });
    if (status.state === "granted") return "available";
    if (status.state === "denied") return "unavailable";
    return null;
  } catch {
    return null;
  }
}

export async function detectMicrophoneAvailability(force = false): Promise<MicrophoneAvailability> {
  if (!canUseMediaDevices() || !navigator.mediaDevices.enumerateDevices) {
    return "unknown";
  }
  const now = Date.now();
  if (
    !force &&
    cachedAvailability &&
    now - cachedAvailability.checkedAt < CACHE_TTL_MS
  ) {
    return cachedAvailability.value;
  }
  const permissionResult = await queryMicrophonePermission();
  if (permissionResult !== null) {
    cachedAvailability = { value: permissionResult, checkedAt: now };
    return permissionResult;
  }
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    const value = devices.some((device) => device.kind === "audioinput")
      ? "available"
      : "unknown";
    cachedAvailability = { value, checkedAt: now };
    return value;
  } catch {
    return "unknown";
  }
}

/**
 * Result of a microphone-access probe. `denied: true` means the runtime
 * permission is explicitly blocked — on Android this typically means
 * USER_FIXED state, where `onPermissionRequest` cannot show a system
 * dialog and the only recovery path is `openAppSettings()`.
 */
export type MicrophoneAccessResult =
  | { ok: true }
  | { ok: false; denied: boolean };

/**
 * Returns `true` when microphone access is explicitly denied. Tries the
 * silent Web Permissions API first (`navigator.permissions.query`), which
 * is authoritative when supported. Android WebView frequently does NOT
 * expose `name: "microphone"` for `Permissions.query` and may throw or
 * return a non-conformant state, so the fallback path is a `getUserMedia`
 * probe that classifies a `NotAllowedError` as `denied`. The fallback
 * still surfaces the system permission dialog the first time it runs;
 * once Android marks the permission USER_FIXED that dialog is suppressed
 * and the probe rejects immediately with `NotAllowedError`.
 */
export async function isMicrophonePermissionDenied(): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.permissions?.query) {
    try {
      const status = await navigator.permissions.query({ name: "microphone" as PermissionName });
      if (status.state === "denied") return true;
      if (status.state === "granted") return false;
      // "prompt" — Permissions API does not know; fall through to probe
    } catch {
      // Permissions API not supported for `microphone` (common on Android
      // WebView) — fall through to the getUserMedia probe.
    }
  }
  if (!canUseMediaDevices() || !navigator.mediaDevices.getUserMedia) return false;
  let stream: MediaStream | null = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    return false;
  } catch (err) {
    return err instanceof Error && err.name === "NotAllowedError";
  } finally {
    stream?.getTracks().forEach((track) => track.stop());
  }
}

export async function ensureMicrophoneAccess(): Promise<MicrophoneAccessResult> {
  if (!canUseMediaDevices() || !navigator.mediaDevices.getUserMedia) {
    return { ok: false, denied: false };
  }
  try {
    // WKWebView may reject capture without initiating the macOS TCC dialog.
    // The native command is a no-op on other platforms and triggers the
    // macOS TCC prompt when WebKit would otherwise reject silently. WebKit's
    // getUserMedia remains the authoritative capture attempt below.
    await api.requestSystemMicrophoneAccess();
  } catch {
    // Web preview and older native builds have no command; let getUserMedia
    // remain the portable authoritative request in those environments.
  }
  let stream: MediaStream | null = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    cachedAvailability = { value: "available", checkedAt: Date.now() };
    return { ok: true };
  } catch (err) {
    const denied = err instanceof Error && err.name === "NotAllowedError";
    return { ok: false, denied };
  } finally {
    stream?.getTracks().forEach((track) => track.stop());
  }
}

export function useMicrophoneAvailability(): MicrophoneAvailability {
  const [availability, setAvailability] = useState<MicrophoneAvailability>("checking");

  useEffect(() => {
    let cancelled = false;
    const refresh = (force = false) => {
      detectMicrophoneAvailability(force).then((value) => {
        if (!cancelled) setAvailability(value);
      });
    };
    refresh();

    // Listen to `devicechange` (mediaDevices) and to Permissions API state
    // changes so the chat header Phone button updates the moment the user
    // grants or revokes microphone access from Settings or a system dialog.
    const onDeviceChange = () => refresh(true);
    if (canUseMediaDevices() && navigator.mediaDevices.addEventListener) {
      navigator.mediaDevices.addEventListener("devicechange", onDeviceChange);
    }
    let permissionStatus: PermissionStatus | null = null;
    const onPermissionChange = () => refresh(true);
    if (navigator.permissions?.query) {
      navigator.permissions
        .query({ name: "microphone" as PermissionName })
        .then((status) => {
          if (cancelled) return;
          permissionStatus = status;
          status.addEventListener("change", onPermissionChange);
        })
        .catch(() => undefined);
    }
    return () => {
      cancelled = true;
      if (canUseMediaDevices() && navigator.mediaDevices.removeEventListener) {
        navigator.mediaDevices.removeEventListener("devicechange", onDeviceChange);
      }
      permissionStatus?.removeEventListener("change", onPermissionChange);
    };
  }, []);

  return availability;
}
