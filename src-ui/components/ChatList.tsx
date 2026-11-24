import { memo, useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AlertCircle, Pin, ShieldCheck } from "lucide-react";
import type { Chat, Contact } from "../lib/types";
import { UserAvatar } from "./UserAvatar";
import { ChatContextMenu, type ChatMenuAction } from "./ChatContextMenu";

type Props = {
  chats: Chat[];
  contacts: Contact[];
  selectedChatId: string | null;
  query: string;
  myDisplayName: string;
  myAvatarJpegBase64?: string | null;
  onSelect: (id: string) => void;
  onChatMenuAction?: (chat: Chat, action: ChatMenuAction) => void;
  onAddContact?: () => void;
};

type RowProps = {
  chatId: string;
  title: string;
  subtitle: string;
  timeLabel: string;
  online: boolean;
  verified: boolean;
  unreadCount: number;
  failedCount: number;
  isSelfChat: boolean;
  selfDisplayName: string;
  selfAvatarJpegBase64?: string | null;
  peerAvatarJpegBase64?: string | null;
  isPinned: boolean;
  selected: boolean;
  onSelect: (id: string) => void;
  onOpenMenu: (event: { clientX: number; clientY: number }, chatId: string) => void;
};

// Threshold (px) above which a pointermove cancels the pending long-press —
// this lets the user scroll the chat list with touch without triggering a
// context menu by accident.
const LONG_PRESS_MOVE_TOLERANCE = 8;
// 550ms matches Android system long-press feel without lagging desktop users
// who right-click instead.
const LONG_PRESS_DELAY_MS = 550;

const ChatListRow = memo(function ChatListRow({
  chatId,
  title,
  subtitle,
  timeLabel,
  online,
  verified,
  unreadCount,
  failedCount,
  isSelfChat,
  selfDisplayName,
  selfAvatarJpegBase64,
  peerAvatarJpegBase64,
  isPinned,
  selected,
  onSelect,
  onOpenMenu,
}: RowProps) {
  const { t } = useTranslation();
  const longPressTimer = useRef<number | undefined>(undefined);
  const longPressFired = useRef(false);
  const pressOrigin = useRef<{ x: number; y: number } | null>(null);

  const cancelLongPress = useCallback(() => {
    if (longPressTimer.current !== undefined) {
      window.clearTimeout(longPressTimer.current);
      longPressTimer.current = undefined;
    }
    pressOrigin.current = null;
  }, []);

  const handlePointerDown = useCallback(
    (event: React.PointerEvent<HTMLButtonElement>) => {
      if (event.pointerType === "mouse") return;
      longPressFired.current = false;
      pressOrigin.current = { x: event.clientX, y: event.clientY };
      const clientX = event.clientX;
      const clientY = event.clientY;
      longPressTimer.current = window.setTimeout(() => {
        longPressFired.current = true;
        onOpenMenu({ clientX, clientY }, chatId);
      }, LONG_PRESS_DELAY_MS);
    },
    [chatId, onOpenMenu],
  );

  const handlePointerMove = useCallback(
    (event: React.PointerEvent<HTMLButtonElement>) => {
      const origin = pressOrigin.current;
      if (!origin) return;
      const dx = event.clientX - origin.x;
      const dy = event.clientY - origin.y;
      if (dx * dx + dy * dy > LONG_PRESS_MOVE_TOLERANCE * LONG_PRESS_MOVE_TOLERANCE) {
        cancelLongPress();
      }
    },
    [cancelLongPress],
  );

  const handlePointerEnd = useCallback(() => {
    cancelLongPress();
  }, [cancelLongPress]);

  const handleClick = useCallback(() => {
    // If long-press fired during this gesture, swallow the synthetic click so
    // the row doesn't also navigate into the chat.
    if (longPressFired.current) {
      longPressFired.current = false;
      return;
    }
    onSelect(chatId);
  }, [chatId, onSelect]);

  const handleContextMenu = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      // preventDefault suppresses the WebView2 native context menu;
      // stopPropagation keeps the event from reaching any ancestor handlers
      // that might also react to right-click (the chat list's own context
      // menu close-outside watcher used to live there and would race the
      // open with an immediate close).
      event.preventDefault();
      event.stopPropagation();
      onOpenMenu({ clientX: event.clientX, clientY: event.clientY }, chatId);
    },
    [chatId, onOpenMenu],
  );

  return (
    <button
      type="button"
      className={`list-row chat-row-button ${selected ? "selected" : ""}`}
      onClick={handleClick}
      onContextMenu={handleContextMenu}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerEnd}
      onPointerCancel={handlePointerEnd}
      onPointerLeave={handlePointerEnd}
    >
      <span className="chat-row-avatar" aria-hidden="true">
        {isSelfChat ? (
          <UserAvatar displayName={selfDisplayName} avatarJpegBase64={selfAvatarJpegBase64} />
        ) : (
          <UserAvatar displayName={title} avatarJpegBase64={peerAvatarJpegBase64} />
        )}
        {!isSelfChat && <span className={`chat-row-presence ${online ? "online" : "offline"}`} />}
      </span>
      <span className="chat-row-copy">
        <span className="chat-row-title">
          <span>{title}</span>
          {!isSelfChat && verified && <ShieldCheck size={13} className="verified-tick" aria-label={t("common.verified")} />}
        </span>
        <small>
          {subtitle}
        </small>
      </span>
      <span className="chat-row-side">
        {timeLabel && <span className="chat-row-time">{timeLabel}</span>}
        <span className="chat-row-side-badges">
          {isPinned && !isSelfChat && (
            <Pin
              size={13}
              className="chat-row-pin"
              aria-label={t("chatMenu.pinnedHint")}
            />
          )}
          {failedCount > 0 && (
            <span
              className="chat-error-badge"
              aria-label={t("chat.failedMessages", { count: failedCount })}
              title={t("chat.failedMessages", { count: failedCount })}
            >
              <AlertCircle size={14} aria-hidden="true" />
            </span>
          )}
          {unreadCount > 0 && (
            <span
              className="unread-badge"
              aria-label={t("chat.unread", { count: unreadCount })}
            >
              {unreadCount > 99 ? "99+" : unreadCount}
            </span>
          )}
        </span>
      </span>
    </button>
  );
});

function shortChatTime(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const sameDay = date.toDateString() === new Date().toDateString();
  return new Intl.DateTimeFormat(
    undefined,
    sameDay
      ? { hour: "2-digit", minute: "2-digit" }
      : { day: "2-digit", month: "2-digit", year: "2-digit" },
  ).format(date);
}

export function ChatList({
  chats,
  contacts,
  selectedChatId,
  query,
  myDisplayName,
  myAvatarJpegBase64,
  onSelect,
  onChatMenuAction,
  onAddContact,
}: Props) {
  const { t } = useTranslation();
  const [menuFor, setMenuFor] = useState<{ chatId: string; x: number; y: number } | null>(null);

  const closeMenu = useCallback(() => setMenuFor(null), []);

  const handleOpenMenu = useCallback((event: { clientX: number; clientY: number }, chatId: string) => {
    setMenuFor({ chatId, x: event.clientX, y: event.clientY });
  }, []);

  if (!chats.length)
    return (
      <div className="contacts-empty">
        <p>{t("chat.noChats")}</p>
        <p className="hint">{t("chat.noChatsHint")}</p>
        {onAddContact && (
          <button type="button" onClick={onAddContact}>
            {t("menu.addContact")}
          </button>
        )}
      </div>
    );
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const rows = chats
    .map((chat) => {
      const directContact =
        chat.chat_type === "direct"
          ? contacts.find((c) => chat.member_contact_ids.includes(c.local_id))
          : null;
      const title =
        chat.is_self_chat
          ? t("chat.notes")
          : chat.title || directContact?.display_name || t("chat.directChat");
      const subtitle = chat.last_message_text?.trim() || t("chat.noMessagesYet");
      const timeLabel = shortChatTime(chat.last_message_at ?? chat.updated_at);
      return { chat, directContact, title, subtitle, timeLabel };
    })
    .filter(({ title, directContact, subtitle }) => {
      if (!normalizedQuery) return true;
      return (
        title.toLocaleLowerCase().includes(normalizedQuery) ||
        directContact?.display_name.toLocaleLowerCase().includes(normalizedQuery) ||
        subtitle.toLocaleLowerCase().includes(normalizedQuery)
      );
    });
  if (!rows.length) return <div className="empty">{t("chat.noSearchResults")}</div>;
  const menuChat = menuFor ? chats.find((chat) => chat.id === menuFor.chatId) ?? null : null;
  return (
    <div className="list">
      {rows.map(({ chat, directContact, title, subtitle, timeLabel }) => {
        const online = directContact?.presence_status === "online";
        const verified = directContact?.trust_status === "verified";
        return (
          <ChatListRow
            key={chat.id}
            chatId={chat.id}
            title={title}
            subtitle={subtitle}
            timeLabel={timeLabel}
            online={!!online}
            verified={!!verified}
            unreadCount={chat.unread_count}
            failedCount={chat.failed_count ?? 0}
            isSelfChat={!!chat.is_self_chat}
            selfDisplayName={myDisplayName}
            selfAvatarJpegBase64={myAvatarJpegBase64}
            peerAvatarJpegBase64={directContact?.peer_avatar_jpeg_base64}
            isPinned={!!chat.pinned_at}
            selected={chat.id === selectedChatId}
            onSelect={onSelect}
            onOpenMenu={handleOpenMenu}
          />
        );
      })}
      {menuFor && menuChat && (
        <ChatContextMenu
          chat={menuChat}
          x={menuFor.x}
          y={menuFor.y}
          onAction={(action) => {
            closeMenu();
            onChatMenuAction?.(menuChat, action);
          }}
          onClose={closeMenu}
        />
      )}
    </div>
  );
}
