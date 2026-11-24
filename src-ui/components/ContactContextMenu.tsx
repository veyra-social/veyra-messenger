import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Pencil, ShieldOff, ShieldCheck, Trash2 } from "lucide-react";
import type { Contact } from "../lib/types";

export type ContactMenuAction = "rename" | "block" | "unblock" | "delete";

type Props = {
  contact: Contact;
  x: number;
  y: number;
  onAction: (action: ContactMenuAction) => void;
  onClose: () => void;
};

export function ContactContextMenu({ contact, x, y, onAction, onClose }: Props) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ left: number; top: number }>({
    left: x,
    top: y,
  });

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
    // Mirrors ChatContextMenu: only `mousedown` for click-outside so that a
    // bubbled `contextmenu` (right-click on a sibling row) does not race the
    // freshly opened menu into immediate close.
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const isBlocked = contact.trust_status === "blocked";

  return (
    <div
      ref={ref}
      className="chat-context-menu"
      role="menu"
      style={{ left: position.left, top: position.top }}
      onContextMenu={(event) => event.preventDefault()}
    >
      <button
        type="button"
        role="menuitem"
        className="chat-context-menu-item"
        onClick={() => onAction("rename")}
      >
        <Pencil size={15} />
        <span>{t("contactMenu.rename")}</span>
      </button>
      {isBlocked ? (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("unblock")}
        >
          <ShieldCheck size={15} />
          <span>{t("contactMenu.unblock")}</span>
        </button>
      ) : (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("block")}
        >
          <ShieldOff size={15} />
          <span>{t("contactMenu.block")}</span>
        </button>
      )}
      <button
        type="button"
        role="menuitem"
        className="chat-context-menu-item destructive"
        onClick={() => onAction("delete")}
      >
        <Trash2 size={15} />
        <span>{t("contactMenu.delete")}</span>
      </button>
    </div>
  );
}
