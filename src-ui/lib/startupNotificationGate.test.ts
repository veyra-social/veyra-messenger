import { afterEach, describe, expect, it, vi } from "vitest";
import {
  __resetStartupNotificationSilenceForTests,
  armStartupNotificationSilence,
  isStartupNotificationSilenced,
  STARTUP_NOTIFICATION_QUIET_MS,
  shouldSuppressStartupNotification,
} from "./startupNotificationGate";

const listenerStartedAt = Date.parse("2026-06-07T10:00:00.000Z");
const quietUntil = listenerStartedAt + STARTUP_NOTIFICATION_QUIET_MS;

function input(overrides: Partial<Parameters<typeof shouldSuppressStartupNotification>[0]>) {
  return {
    kind: "message" as const,
    createdAt: "2026-06-07T10:00:45.000Z",
    listenerStartedAt,
    contactsPrimed: true,
    quietUntil,
    now: quietUntil + 1,
    ...overrides,
  };
}

describe("startup notification gate", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("tracks a shared startup notification silence window", () => {
    const now = Date.parse("2026-06-07T10:00:00.000Z");
    vi.useFakeTimers();
    vi.setSystemTime(now);
    __resetStartupNotificationSilenceForTests(now);
    expect(isStartupNotificationSilenced(now)).toBe(false);

    armStartupNotificationSilence(STARTUP_NOTIFICATION_QUIET_MS);

    expect(isStartupNotificationSilenced(now + STARTUP_NOTIFICATION_QUIET_MS - 1)).toBe(true);
    expect(isStartupNotificationSilenced(now + STARTUP_NOTIFICATION_QUIET_MS + 1)).toBe(false);
  });

  it("suppresses message and invite events before contacts are primed", () => {
    expect(
      shouldSuppressStartupNotification(input({ kind: "message", contactsPrimed: false })),
    ).toBe(true);
    expect(
      shouldSuppressStartupNotification(input({ kind: "invite", contactsPrimed: false })),
    ).toBe(true);
  });

  it("suppresses message, invite, and call events inside the quiet window", () => {
    const now = quietUntil;

    expect(shouldSuppressStartupNotification(input({ kind: "message", now }))).toBe(true);
    expect(shouldSuppressStartupNotification(input({ kind: "invite", now }))).toBe(true);
    expect(shouldSuppressStartupNotification(input({ kind: "call", now }))).toBe(true);
  });

  it("suppresses malformed or old timestamps after the quiet window", () => {
    expect(shouldSuppressStartupNotification(input({ createdAt: "not-a-date" }))).toBe(true);
    expect(
      shouldSuppressStartupNotification(input({ createdAt: "2026-06-07T10:00:04.000Z" })),
    ).toBe(true);
    expect(
      shouldSuppressStartupNotification(
        input({ kind: "call", createdAt: "2026-06-07T10:00:04.000Z" }),
      ),
    ).toBe(true);
  });

  it("allows fresh post-window message, invite, and call events", () => {
    expect(shouldSuppressStartupNotification(input({ kind: "message" }))).toBe(false);
    expect(shouldSuppressStartupNotification(input({ kind: "invite" }))).toBe(false);
    expect(shouldSuppressStartupNotification(input({ kind: "call" }))).toBe(false);
  });
});
