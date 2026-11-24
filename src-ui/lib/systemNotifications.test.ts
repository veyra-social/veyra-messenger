import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createChannel,
  isPermissionGranted,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import {
  __resetStartupNotificationSilenceForTests,
  armStartupNotificationSilence,
} from "./startupNotificationGate";
import {
  setSystemNotificationPrefs,
  showSystemNotificationForEvent,
} from "./systemNotifications";
import type { AppNotificationEvent, NotificationPrefs } from "./types";

vi.mock("@tauri-apps/plugin-notification", () => ({
  Importance: { Default: "default", High: "high" },
  Visibility: { Private: "private" },
  createChannel: vi.fn(() => Promise.resolve()),
  isPermissionGranted: vi.fn(() => Promise.resolve(true)),
  onAction: vi.fn(),
  requestPermission: vi.fn(() => Promise.resolve("granted")),
  sendNotification: vi.fn(),
}));

const prefs: NotificationPrefs = {
  notificationsEnabled: true,
  notificationSoundsEnabled: true,
  messageSoundEnabled: true,
  inviteSoundEnabled: true,
  callRingtoneEnabled: true,
  vibrationEnabled: true,
  notificationPreviewMode: "private",
};

const labels = {
  appTitle: "Veyra",
  newMessage: "New message",
  newInvite: "New invite",
  incomingCall: "Incoming call",
  testBody: "Test",
  sampleSender: "Alice",
  sampleMessage: "Hello",
};

function event(kind: AppNotificationEvent["kind"]): AppNotificationEvent {
  if (kind === "invite") {
    return {
      kind,
      contactId: "contact-1",
      contactName: "Alice",
      createdAt: "2026-06-07T10:00:45.000Z",
    };
  }
  if (kind === "call") {
    return {
      kind,
      callId: "call-1",
      chatId: "chat-1",
      contactName: "Alice",
      createdAt: "2026-06-07T10:00:45.000Z",
    };
  }
  return {
    kind,
    chatId: "chat-1",
    messageId: "message-1",
    contactName: "Alice",
    preview: "Hello",
    createdAt: "2026-06-07T10:00:45.000Z",
  };
}

describe("system notifications startup silence", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-07T10:00:00.000Z"));
    vi.stubGlobal("navigator", { userAgent: "Macintosh; Intel Mac OS X 14_0" });
    vi.stubGlobal("document", { hidden: true, hasFocus: () => false });
    __resetStartupNotificationSilenceForTests(Date.now());
    setSystemNotificationPrefs(prefs);
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("posts the macOS banner even when the (now vestigial) startup silence is armed", async () => {
    armStartupNotificationSilence(30_000);

    await showSystemNotificationForEvent(event("message"), {
      selectedChatId: null,
      labels,
    });

    expect(isPermissionGranted).toHaveBeenCalled();
    expect(sendNotification).toHaveBeenCalledTimes(1);
    // macOS banner carries no `sound` (an unrecognised value made sendNotification
    // fail); the audible cue is the local web-audio one.
    expect(sendNotification).toHaveBeenLastCalledWith(
      expect.not.objectContaining({ sound: expect.anything() }),
    );
  });

  it("posts fresh macOS message, invite, and call banners (no startup-silence suppression)", async () => {
    armStartupNotificationSilence(30_000);

    await showSystemNotificationForEvent(event("message"), { selectedChatId: null, labels });
    await showSystemNotificationForEvent(event("invite"), { selectedChatId: null, labels });
    await showSystemNotificationForEvent(event("call"), { selectedChatId: null, labels });

    expect(sendNotification).toHaveBeenCalledTimes(3);
  });

  it("allows fresh macOS system notifications after startup silence expires", async () => {
    armStartupNotificationSilence(30_000);
    vi.setSystemTime(new Date("2026-06-07T10:00:31.000Z"));

    await showSystemNotificationForEvent(event("message"), {
      selectedChatId: null,
      labels,
    });

    expect(sendNotification).toHaveBeenCalledTimes(1);
  });
});
