import type { ChatMessage } from "./types";

type MessageOrderFields = Pick<
  ChatMessage,
  "created_at" | "direction" | "display_at" | "message_id" | "received_at"
>;
type MessageIdentityFields = Pick<ChatMessage, "direction" | "message_id">;

/**
 * Where a message sits in the timeline. The backend decides this once, when
 * the row is written, and stores it: for an inbound message it is the time it
 * was WRITTEN, pulled back no further than the reorder window and never above
 * the user's own previous message. That depends on what the chat looked like
 * at the moment of arrival, so it cannot be recomputed here — always read the
 * stored value.
 */
export function messageDisplayTimestamp(message: MessageOrderFields): string {
  return message.display_at;
}

/**
 * When the row reached THIS device, on this device's clock. Unlike the display
 * position it only ever moves forward, which is what makes it a safe cursor
 * for the incremental poll: a message that arrives late but is displayed
 * further up would be skipped forever by a display-order cursor.
 */
export function messageArrivalTimestamp(message: MessageOrderFields): string {
  if (message.direction === "inbound") {
    return message.received_at ?? message.created_at;
  }
  return message.created_at;
}

/** Newest arrival across the loaded messages — not necessarily the last one. */
export function latestArrivalTimestamp(messages: MessageOrderFields[]): string {
  let latest = "";
  for (const message of messages) {
    const arrival = messageArrivalTimestamp(message);
    if (arrival > latest) latest = arrival;
  }
  return latest;
}

export function compareMessagesByDisplayOrder(
  left: MessageOrderFields,
  right: MessageOrderFields,
): number {
  const byTime = messageDisplayTimestamp(left).localeCompare(messageDisplayTimestamp(right));
  return byTime !== 0 ? byTime : left.message_id.localeCompare(right.message_id);
}

export function hasNewInboundMessage(
  previous: MessageIdentityFields[],
  next: MessageIdentityFields[],
): boolean {
  if (next.length <= previous.length) return false;
  const previousIds = new Set(previous.map((message) => message.message_id));
  return next.some(
    (message) => message.direction === "inbound" && !previousIds.has(message.message_id),
  );
}
