import type { ActiveDeliveryPath, ChannelState } from "./types";
import i18n from "../i18n";
import { isDebugUi } from "../uiMode";

export function shortId(value: string, left = 10, right = 8) {
  if (!value || value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

export function dateTime(value?: string | null) {
  if (!value) return "";
  return new Date(value).toLocaleString(i18n.language);
}

// HH:MM in the active locale (e.g. "12:42" / "12:42 PM"). Used in the chat
// message-row header (`<author> · <time>`) — short and unambiguous within the
// same day's grouping; the day-divider above provides the date context.
export function timeShort(value?: string | null): string {
  if (!value) return "";
  return new Date(value).toLocaleTimeString(i18n.language, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function sameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function dayLabel(d: Date): string {
  const now = new Date();
  if (sameDay(d, now)) return i18n.t("chat.today");
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(d, yesterday)) return i18n.t("chat.yesterday");
  const sameYear = d.getFullYear() === now.getFullYear();
  return d.toLocaleDateString(i18n.language, {
    day: "numeric",
    month: "long",
    year: sameYear ? undefined : "numeric",
  });
}

// Decide what day-divider label to render between two messages (or before the
// very first one). Returns `null` when the two messages fall on the same
// calendar day (no divider needed). When the gap exceeds ~30 days we return
// the full date+time with seconds via `dateTime()` — that signals "a long
// time has passed" more clearly than just a date capsule.
export function formatDayDivider(
  curr: string,
  prev: string | null,
): string | null {
  const c = new Date(curr);
  if (!prev) return dayLabel(c);
  const p = new Date(prev);
  if (sameDay(c, p)) return null;
  const diffMs = c.getTime() - p.getTime();
  if (diffMs >= 30 * 24 * 3600 * 1000) {
    return dateTime(curr);
  }
  return dayLabel(c);
}

export function presenceLabel(status: string, lastSeenAt?: string | null) {
  if (status === "online") return i18n.t("presence.online");
  if (lastSeenAt) return i18n.t("presence.lastSeen", { time: dateTime(lastSeenAt) });
  return i18n.t("presence.offline");
}

type ChannelLoadState = "loading" | "ready" | "error";

export function activeDeliveryPathTag(path: ActiveDeliveryPath): string {
  switch (path) {
    case "lan":
      return "LAN";
    case "tcp":
      return "TCP";
    case "quic":
      return "QUIC";
    case "wss":
      return "WSS";
    case "relay":
      return "Relay";
    case "relay_quic":
      return "R-QUIC";
    case "relay_wss":
      return "R-WSS";
    case "web_rtc":
      return "WebRTC";
    case "https":
      return "HTTPS";
    case "crypto_http":
      return "C-HTTP";
    case "transit":
      return "Transit";
    default:
      // Runtime values come from the backend and may outrun this union
      // (schema drift between versions) — never leak "undefined" into the
      // header, show a neutral globe instead.
      return "🌐";
  }
}

// Builds a single-line subtitle for the chat header.
// Direct chats: the optional tag is a separately confirmed active delivery
// executor. Presence leases, route hints and last-known transports never create it.
export function chatHeaderSubtitle(
  chat: { chat_type: string; is_self_chat?: boolean | null },
  directContact?: { presence_status: string; last_seen_at?: string | null } | null,
  activeDeliveryPath?: ActiveDeliveryPath | null,
): string {
  if (chat.is_self_chat) return "";
  if (chat.chat_type === "direct") {
    if (directContact?.presence_status === "online") {
      // The transport tag (LAN/QUIC/R-WSS/…) is developer vocabulary — only
      // the debug UI shows it; release users just see "online".
      if (!isDebugUi || !activeDeliveryPath) return i18n.t("presence.online");
      return i18n.t("presence.onlineVia", { kind: activeDeliveryPathTag(activeDeliveryPath) });
    }
    if (directContact?.last_seen_at) return dateTime(directContact.last_seen_at);
    return presenceLabel(
      directContact?.presence_status ?? "offline",
      directContact?.last_seen_at ?? null,
    );
  }
  return chat.chat_type;
}

export type OutboundDeliveryStage =
  | "preparing"
  | "queued"
  | "searchingTransport"
  | "sending"
  | "sent"
  | "delivered"
  | "failed"
  | "hidden";

export function outboundDeliveryStage(
  status: string,
  messageId: string,
  transportLoadState: ChannelLoadState,
  channelState?: ChannelState | null,
): OutboundDeliveryStage {
  if (status === "read") return "hidden";
  if (status === "failed") return "failed";
  if (status === "delivered") return "delivered";
  if (status === "sent") return "sent";
  if (messageId.startsWith("optimistic-")) return "preparing";
  if (status === "pending") {
    if (transportLoadState === "loading") return "searchingTransport";
    if (
      channelState === "none" ||
      channelState === "unknown" ||
      channelState === "unavailable"
    ) {
      return "searchingTransport";
    }
    if (channelState === "ready") return "sending";
    return "queued";
  }
  return "hidden";
}
