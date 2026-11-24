import { describe, expect, it, vi } from "vitest";
import { markActiveChatRead, markInboxEventReadIfVisible } from "./chatReadState";

describe("open chat unread state", () => {
  it("marks an incoming message read when its chat is open and visible", async () => {
    const markChatOpened = vi.fn(async () => undefined);
    const onChatRead = vi.fn();

    await expect(
      markInboxEventReadIfVisible(
        {
          activeChatId: "chat-1",
          eventChatId: "chat-1",
          markReadActive: true,
          pageHidden: false,
        },
        markChatOpened,
        onChatRead,
      ),
    ).resolves.toBe(true);
    expect(markChatOpened).toHaveBeenCalledOnce();
    expect(markChatOpened).toHaveBeenCalledWith("chat-1");
    expect(onChatRead).toHaveBeenCalledWith("chat-1");
  });

  it.each([
    ["another chat", "chat-2", true, false],
    ["inactive chat surface", "chat-1", false, false],
    ["hidden application", "chat-1", true, true],
  ])("keeps the message unread for %s", async (_case, eventChatId, markReadActive, pageHidden) => {
    const markChatOpened = vi.fn(async () => undefined);
    const onChatRead = vi.fn();

    await expect(
      markInboxEventReadIfVisible(
        {
          activeChatId: "chat-1",
          eventChatId,
          markReadActive,
          pageHidden,
        },
        markChatOpened,
        onChatRead,
      ),
    ).resolves.toBe(false);
    expect(markChatOpened).not.toHaveBeenCalled();
    expect(onChatRead).not.toHaveBeenCalled();
  });

  // The message arrived while the window was hidden, so it was correctly left
  // unread — but the chat is on screen and the user is now back at it. Nothing
  // else will mark it: the inbox event already refreshed the snapshot the state
  // poll uses to notice new rows.
  it("marks the open chat read when the window comes back", async () => {
    const markChatOpened = vi.fn(async () => undefined);
    const onChatRead = vi.fn();

    await expect(
      markActiveChatRead(
        { activeChatId: "chat-1", markReadActive: true, pageHidden: false },
        markChatOpened,
        onChatRead,
      ),
    ).resolves.toBe(true);
    expect(markChatOpened).toHaveBeenCalledWith("chat-1");
    expect(onChatRead).toHaveBeenCalledWith("chat-1");
  });

  it.each([
    ["no chat open", null, true, false],
    ["inactive chat surface", "chat-1", false, false],
    ["hidden application", "chat-1", true, true],
  ])(
    "does not mark the active chat read for %s",
    async (_case, activeChatId, markReadActive, pageHidden) => {
      const markChatOpened = vi.fn(async () => undefined);
      const onChatRead = vi.fn();

      await expect(
        markActiveChatRead(
          { activeChatId, markReadActive, pageHidden },
          markChatOpened,
          onChatRead,
        ),
      ).resolves.toBe(false);
      expect(markChatOpened).not.toHaveBeenCalled();
      expect(onChatRead).not.toHaveBeenCalled();
    },
  );
});
