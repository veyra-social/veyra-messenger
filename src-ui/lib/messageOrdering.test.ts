import { describe, expect, it } from "vitest";
import {
  compareMessagesByDisplayOrder,
  hasNewInboundMessage,
  latestArrivalTimestamp,
  messageArrivalTimestamp,
  messageDisplayTimestamp,
} from "./messageOrdering";

const message = (
  message_id: string,
  direction: "inbound" | "outbound",
  created_at: string,
  received_at: string | null = null,
  display_at: string = received_at ?? created_at,
) => ({ message_id, direction, created_at, received_at, display_at });

describe("message display order", () => {
  it("sorts by the stored display position, not by arrival", () => {
    const outbound = message("out", "outbound", "2026-07-03T10:40:30.000Z");
    // Written before the reply, delivered after it, and the backend decided it
    // still belongs below the reply (own-message floor).
    const delayedInbound = message(
      "in",
      "inbound",
      "2026-07-03T10:40:18.000Z",
      "2026-07-03T10:40:55.000Z",
      "2026-07-03T10:40:30.001Z",
    );

    expect(
      [delayedInbound, outbound].sort(compareMessagesByDisplayOrder).map((item) => item.message_id),
    ).toEqual(["out", "in"]);
  });

  it("restores write order for two inbound messages that arrived swapped", () => {
    const first = message(
      "first",
      "inbound",
      "2026-07-03T10:40:10.000Z",
      "2026-07-03T10:43:00.000Z",
      "2026-07-03T10:40:10.000Z",
    );
    const second = message(
      "second",
      "inbound",
      "2026-07-03T10:40:20.000Z",
      "2026-07-03T10:40:22.000Z",
      "2026-07-03T10:40:20.000Z",
    );

    expect(
      [second, first].sort(compareMessagesByDisplayOrder).map((item) => item.message_id),
    ).toEqual(["first", "second"]);
  });

  it("reads the display position straight from the row", () => {
    const inbound = message(
      "in",
      "inbound",
      "2026-07-03T10:40:18.000Z",
      "2026-07-03T10:40:55.000Z",
      "2026-07-03T10:40:18.000Z",
    );
    expect(messageDisplayTimestamp(inbound)).toBe("2026-07-03T10:40:18.000Z");
  });

  it("takes arrival from received_at for inbound and created_at for outbound", () => {
    const inbound = message(
      "in",
      "inbound",
      "2026-07-03T10:40:18.000Z",
      "2026-07-03T10:40:55.000Z",
    );
    const outbound = message("out", "outbound", "2026-07-03T10:40:30.000Z");
    expect(messageArrivalTimestamp(inbound)).toBe("2026-07-03T10:40:55.000Z");
    expect(messageArrivalTimestamp(outbound)).toBe("2026-07-03T10:40:30.000Z");
  });

  it("falls back to created_at for legacy inbound rows without received_at", () => {
    const inbound = message("in", "inbound", "2026-07-03T10:40:18.000Z");
    expect(messageArrivalTimestamp(inbound)).toBe(inbound.created_at);
  });

  // The delta cursor must be the NEWEST arrival, which a delayed message makes
  // different from the last array element — keying off the tail would ask for
  // rows after an older timestamp and re-fetch them forever.
  it("takes the delta watermark from the newest arrival, not the last row", () => {
    const outbound = message("out", "outbound", "2026-07-03T10:40:30.000Z");
    const delayedInbound = message(
      "in",
      "inbound",
      "2026-07-03T10:40:18.000Z",
      "2026-07-03T10:40:55.000Z",
      "2026-07-03T10:40:18.000Z",
    );
    const ordered = [delayedInbound, outbound].sort(compareMessagesByDisplayOrder);

    expect(ordered[ordered.length - 1].message_id).toBe("out");
    expect(latestArrivalTimestamp(ordered)).toBe("2026-07-03T10:40:55.000Z");
  });

  it("detects a newly received inbound message regardless of its array position", () => {
    const existing = message("out", "outbound", "2026-07-03T10:40:30.000Z");
    const inbound = message("in", "inbound", "2026-07-03T10:40:18.000Z");

    expect(hasNewInboundMessage([existing], [inbound, existing])).toBe(true);
  });
});
