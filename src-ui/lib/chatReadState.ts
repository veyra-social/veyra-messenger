type ActiveChatReadContext = {
  activeChatId: string | null;
  markReadActive: boolean;
  pageHidden: boolean;
};

type InboxReadContext = ActiveChatReadContext & {
  eventChatId: string;
};

/**
 * The user is demonstrably looking at this chat right now — the window just
 * regained visibility, or they just sent a message into it — so its inbound
 * rows count as read even though no new event will arrive to say so.
 *
 * This is not a nicety: the `inbox-changed` listener refreshes the message
 * snapshot even while the window is hidden, which disarms the state poll's
 * fallback ("the snapshot already matches, nothing new to discover"). Without
 * a trigger on the way back the badge for the OPEN chat would sit there until
 * the user left and re-entered it.
 */
export async function markActiveChatRead(
  context: ActiveChatReadContext,
  markChatOpened: (chatId: string) => Promise<void>,
  onChatRead?: (chatId: string) => void,
): Promise<boolean> {
  const { activeChatId, markReadActive, pageHidden } = context;
  if (!activeChatId || !markReadActive || pageHidden) {
    return false;
  }

  await markChatOpened(activeChatId);
  onChatRead?.(activeChatId);
  return true;
}

export async function markInboxEventReadIfVisible(
  context: InboxReadContext,
  markChatOpened: (chatId: string) => Promise<void>,
  onChatRead?: (chatId: string) => void,
): Promise<boolean> {
  if (context.eventChatId !== context.activeChatId) {
    return false;
  }
  return markActiveChatRead(context, markChatOpened, onChatRead);
}
