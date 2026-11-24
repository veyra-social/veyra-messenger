import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Pencil, Pin, PinOff, ShieldOff, Trash2 } from "lucide-react";
import type { Chat } from "../lib/types";

export type ChatMenuAction = "rename" | "block" | "delete" | "togglePin";

type Props = {
  chat: Chat;
  x: number;
  y: number;
  onAction: (action: ChatMenuAction) => void;
  onClose: () => void;
};

// Per-chat-type menu composition: direct contacts get Pin/Rename/Block/Delete,
// and the local Notes self-chat only exposes Delete — pin is meaningless
// because Notes is always sorted on top by virtue of being a self-chat.
function actionsForChat(chat: Chat): ChatMenuAction[] {
  if (chat.is_self_chat) return ["delete"];
  return ["togglePin", "rename", "block", "delete"];
}

export function ChatContextMenu({ chat, x, y, onAction, onClose }: Props) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ left: number; top: number }>({
    left: x,
    top: y,
  });

  // Clamp the popover inside the viewport. Triggered after layout so that
  // measured width/height reflect real content (icon labels can wrap on RU).
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const margin = 8;
    const maxLeft = window.innerWidth - rect.width - margin;
    const maxTop = window.innerHeight - rect.height - margin;
    setPosition({
      left: Math.max(margin, Math.min(x, maxLeft)),
      top: Math.max(margin, Math.min(y, maxTop)),
    });
  }, [x, y]);

  useEffect(() => {
    function onDocMouseDown(event: MouseEvent) {
      if (!ref.current) return;
      if (!ref.current.contains(event.target as Node)) onClose();
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    // NOTE: only `mousedown` is used for click-outside. We intentionally do
    // NOT listen to the document-level `contextmenu` event — when the user
    // right-clicks a different chat row to switch the menu, that bubbling
    // `contextmenu` event would otherwise be caught here as "click outside"
    // and immediately close the freshly-opened menu (React 18 batches the
    // open/close setState calls and the close wins because it fires last).
    // `mousedown` already fires before `contextmenu`, so it handles
    // switch/click-outside correctly without that race.
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const actions = actionsForChat(chat);
  const isPinned = Boolean(chat.pinned_at);

  return (
    <div
      ref={ref}
      className="chat-context-menu"
      role="menu"
      style={{ left: position.left, top: position.top }}
      onContextMenu={(event) => event.preventDefault()}
    >
      {actions.includes("togglePin") && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("togglePin")}
        >
          {isPinned ? <PinOff size={15} /> : <Pin size={15} />}
          <span>{t(isPinned ? "chatMenu.unpin" : "chatMenu.pin")}</span>
        </button>
      )}
      {actions.includes("rename") && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("rename")}
        >
          <Pencil size={15} />
          <span>{t("chatMenu.rename")}</span>
        </button>
      )}
      {actions.includes("block") && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("block")}
        >
          <ShieldOff size={15} />
          <span>{t("chatMenu.block")}</span>
        </button>
      )}
      {actions.includes("delete") && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item destructive"
          onClick={() => onAction("delete")}
        >
          <Trash2 size={15} />
          <span>{t("chatMenu.delete")}</span>
        </button>
      )}
    </div>
  );
}
