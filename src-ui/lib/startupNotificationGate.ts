import type { AppNotificationEvent } from "./types";

export const STARTUP_NOTIFICATION_TIMESTAMP_SKEW_MS = 5_000;
export const STARTUP_NOTIFICATION_QUIET_MS = 30_000;

let startupNotificationSilencedUntil = Date.now() + STARTUP_NOTIFICATION_QUIET_MS;

export type StartupNotificationGateInput = {
  kind: AppNotificationEvent["kind"];
  createdAt: string;
  listenerStartedAt: number;
  contactsPrimed: boolean;
  quietUntil: number;
  now: number;
};

export function isPreexistingNotification(
  createdAt: string,
  listenerStartedAt: number,
): boolean {
  const created = Date.parse(createdAt);
  // Fail closed: a notification we cannot timestamp is treated as pre-existing
  // so malformed createdAt can never leak a startup cue.
  if (!Number.isFinite(created)) return true;
  return created <= listenerStartedAt + STARTUP_NOTIFICATION_TIMESTAMP_SKEW_MS;
}

export function armStartupNotificationSilence(
  durationMs: number = STARTUP_NOTIFICATION_QUIET_MS,
) {
  const until = Date.now() + Math.max(0, durationMs);
  if (until > startupNotificationSilencedUntil) {
    startupNotificationSilencedUntil = until;
  }
}

export function isStartupNotificationSilenced(now: number = Date.now()): boolean {
  return now < startupNotificationSilencedUntil;
}

export function __resetStartupNotificationSilenceForTests(nowMs: number = Date.now()) {
  startupNotificationSilencedUntil = nowMs;
}

export function shouldSuppressStartupNotification({
  kind,
  createdAt,
  listenerStartedAt,
  contactsPrimed,
  quietUntil,
  now,
}: StartupNotificationGateInput): boolean {
  if (kind === "call") {
    if (now <= quietUntil) return true;
    return isPreexistingNotification(createdAt, listenerStartedAt);
  }
  if (!contactsPrimed) return true;
  if (now <= quietUntil) return true;
  return isPreexistingNotification(createdAt, listenerStartedAt);
}
