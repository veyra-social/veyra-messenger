import { describe, expect, it } from "vitest";
import { activeDeliveryPathTag, chatHeaderSubtitle } from "./format";
import type { ActiveDeliveryPath } from "./types";
import i18n from "../i18n";

const directChat = { chat_type: "direct" };
const onlineContact = { presence_status: "online", last_seen_at: null };

describe("direct chat network indicator", () => {
  it("does not turn an online lease plus historical route into a tagged path", () => {
    expect(chatHeaderSubtitle(directChat, onlineContact, null)).toBe(i18n.t("presence.online"));
  });

  it("shows the fixed tag set only for an explicit active delivery path", () => {
    const expected: Array<[ActiveDeliveryPath, string]> = [
      ["lan", "LAN"],
      ["tcp", "TCP"],
      ["quic", "QUIC"],
      ["wss", "WSS"],
      ["relay", "Relay"],
      ["relay_quic", "R-QUIC"],
      ["relay_wss", "R-WSS"],
      ["web_rtc", "WebRTC"],
      ["https", "HTTPS"],
      ["crypto_http", "C-HTTP"],
      ["transit", "Transit"],
    ];
    for (const [path, tag] of expected) {
      expect(activeDeliveryPathTag(path)).toBe(tag);
      expect(chatHeaderSubtitle(directChat, onlineContact, path)).toBe(
        i18n.t("presence.onlineVia", { kind: tag }),
      );
    }
  });

  it("falls back to a globe for a path value outside the known union", () => {
    const unknown = "quantum_tunnel" as ActiveDeliveryPath;
    expect(activeDeliveryPathTag(unknown)).toBe("🌐");
    expect(chatHeaderSubtitle(directChat, onlineContact, unknown)).toBe(
      i18n.t("presence.onlineVia", { kind: "🌐" }),
    );
  });

  it("never adds a path tag while the contact is offline", () => {
    expect(
      chatHeaderSubtitle(
        directChat,
        { presence_status: "offline", last_seen_at: null },
        "lan",
      ),
    ).toBe(i18n.t("presence.offline"));
  });
});
