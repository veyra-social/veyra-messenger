import {
  Importance,
  Visibility,
  createChannel,
  isPermissionGranted,
  onAction,
  requestPermission,
  sendNotification,
  type Options,
} from "@tauri-apps/plugin-notification";
import type { PluginListener } from "@tauri-apps/api/core";
import type {
  AppNotificationEvent,
  NotificationPrefs,
  NotificationPreviewMode,
} from "./types";

type SystemNotificationLabels = {
  appTitle: string;
  newMessage: string;
  newInvite: string;
  incomingCall: string;
  testBody: string;
  sampleSender: string;
  sampleMessage: string;
};

type SystemNotificationOptions = {
  selectedChatId?: string | null;
  labels: SystemNotificationLabels;
};

type NotificationRoute = {
  kind?: unknown;
  chatId?: unknown;
  contactId?: unknown;
  callId?: unknown;
};

const MESSAGE_CHANNEL_ID = "veyra-messages-v2";
const INVITE_CHANNEL_ID = "veyra-invites-v2";
const CALL_CHANNEL_ID = "veyra-calls-v2";
const MAX_NOTIFICATION_ID = 2_147_483_647;

let prefs: NotificationPrefs = {
  notificationsEnabled: true,
  notificationSoundsEnabled: true,
  messageSoundEnabled: true,
  inviteSoundEnabled: true,
  callRingtoneEnabled: true,
  vibrationEnabled: true,
  notificationPreviewMode: "private",
};
const channelReady = new Map<string, Promise<boolean>>();

function isMacOSDesktop(): boolean {
  return (
    typeof navigator !== "undefined" &&
    /Macintosh|Mac OS X/i.test(navigator.userAgent) &&
    !/iPad|iPhone|iPod/i.test(navigator.userAgent)
  );
}

export function setSystemNotificationPrefs(next: NotificationPrefs) {
  prefs = {
    notificationsEnabled: next.notificationsEnabled,
    notificationSoundsEnabled: next.notificationSoundsEnabled,
    messageSoundEnabled: next.messageSoundEnabled,
    inviteSoundEnabled: next.inviteSoundEnabled,
    callRingtoneEnabled: next.callRingtoneEnabled,
    vibrationEnabled: next.vibrationEnabled,
    notificationPreviewMode: next.notificationPreviewMode,
  };
}

export async function isSystemNotificationPermissionGranted(): Promise<boolean> {
  try {
    return await isPermissionGranted();
  } catch {
    return false;
  }
}

export async function requestSystemNotificationPermission(): Promise<boolean> {
  try {
    if (await isPermissionGranted()) return true;
    return (await requestPermission()) === "granted";
  } catch {
    return false;
  }
}

async function ensureChannel(id: string): Promise<boolean> {
  if (!channelReady.has(id)) {
    const isCall = id === CALL_CHANNEL_ID;
    const isInvite = id === INVITE_CHANNEL_ID;
    channelReady.set(
      id,
      createChannel({
        id,
        name: isCall ? "Veyra Calls" : isInvite ? "Veyra Invites" : "Veyra Messages",
        sound: isCall ? "call1" : isInvite ? "new_invite" : "new_message",
        importance: isCall ? Importance.High : Importance.Default,
        visibility: Visibility.Private,
        vibration: isCall,
      })
        .then(() => true)
        .catch(() => false),
    );
  }
  return await channelReady.get(id)!;
}

function nextNotificationId(): number {
  return Math.max(1, Date.now() % MAX_NOTIFICATION_ID);
}

function genericBody(event: AppNotificationEvent, labels: SystemNotificationLabels): string {
  if (event.kind === "message") return labels.newMessage;
  if (event.kind === "invite") return labels.newInvite;
  return labels.incomingCall;
}

// Resolves the notification title/body for the active preview mode. `private`
// never reveals who sent what; `sender` reveals the contact/chat name only;
// `message` additionally reveals the message preview (messages only — invites
// and calls keep the generic body since they carry no preview).
function notificationContent(
  event: AppNotificationEvent,
  labels: SystemNotificationLabels,
  mode: NotificationPreviewMode,
): { title: string; body: string } {
  const generic = genericBody(event, labels);
  if (mode === "private") {
    return { title: labels.appTitle, body: generic };
  }
  const name = event.contactName?.trim();
  const title = name && name.length > 0 ? name : labels.appTitle;
  if (mode === "message" && event.kind === "message") {
    const preview = event.preview?.trim();
    return { title, body: preview && preview.length > 0 ? preview : generic };
  }
  return { title, body: generic };
}

function testNotificationContent(
  labels: SystemNotificationLabels,
  mode: NotificationPreviewMode,
): { title: string; body: string } {
  if (mode === "private") {
    return { title: labels.appTitle, body: labels.testBody };
  }
  if (mode === "message") {
    return { title: labels.sampleSender, body: labels.sampleMessage };
  }
  return { title: labels.sampleSender, body: labels.newMessage };
}

function notificationExtra(event: AppNotificationEvent): NotificationRoute {
  if (event.kind === "message") {
    return { kind: event.kind, chatId: event.chatId };
  }
  if (event.kind === "invite") {
    return { kind: event.kind, contactId: event.contactId };
  }
  return { kind: event.kind, chatId: event.chatId, callId: event.callId };
}

export async function showSystemNotificationForEvent(
  event: AppNotificationEvent,
  options: SystemNotificationOptions,
) {
  if (!prefs.notificationsEnabled) return;
  const appIsVisible = !document.hidden && document.hasFocus();
  if (appIsVisible) return;
  if (
    event.kind === "message" &&
    event.chatId === options.selectedChatId &&
    !document.hidden &&
    document.hasFocus()
  ) {
    return;
  }
  if (!(await isSystemNotificationPermissionGranted())) return;
  const channelId =
    event.kind === "call"
      ? CALL_CHANNEL_ID
      : event.kind === "invite"
        ? INVITE_CHANNEL_ID
        : MESSAGE_CHANNEL_ID;
  const channelAvailable = await ensureChannel(channelId);
  const content = notificationContent(event, options.labels, prefs.notificationPreviewMode);
  const notification: Options = {
    id: nextNotificationId(),
    title: content.title,
    body: content.body,
    group: event.kind === "call" ? "veyra-calls" : "veyra",
    autoCancel: true,
    visibility: Visibility.Private,
    extra: notificationExtra(event),
    icon: "ic_stat_veyra",
    iconColor: "#08A95F",
  };
  if (channelAvailable) {
    notification.channelId = channelId;
  }
  // No explicit macOS `sound`: an unrecognised sound name made `sendNotification`
  // fail so the banner never appeared at all. The audible part on macOS now comes
  // from the local web-audio cue, which plays even while the app is minimized
  // (see the App message/invite handlers); this banner stays a silent visual.
  sendNotification(notification);
}

export async function sendTestSystemNotification(labels: SystemNotificationLabels): Promise<boolean> {
  if (!(await requestSystemNotificationPermission())) return false;
  const channelAvailable = await ensureChannel(MESSAGE_CHANNEL_ID);
  const content = testNotificationContent(labels, prefs.notificationPreviewMode);
  const notification: Options = {
    id: nextNotificationId(),
    title: content.title,
    body: content.body,
    group: "veyra",
    autoCancel: true,
    visibility: Visibility.Private,
    extra: { kind: "test" },
    icon: "ic_stat_veyra",
    iconColor: "#08A95F",
  };
  if (channelAvailable) {
    notification.channelId = MESSAGE_CHANNEL_ID;
  }
  sendNotification(notification);
  return true;
}

export async function installSystemNotificationActionHandler(
  onRoute: (route: NotificationRoute) => void,
): Promise<PluginListener | null> {
  try {
    return await onAction((notification: Options) => {
      if (notification.extra) {
        onRoute(notification.extra as NotificationRoute);
      }
    });
  } catch {
    return null;
  }
}

export async function focusMainWindowFromNotification() {
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    const window = getCurrentWindow();
    await window.show();
    await window.unminimize();
    await window.setFocus();
  } catch {
    /* best effort only */
  }
}
