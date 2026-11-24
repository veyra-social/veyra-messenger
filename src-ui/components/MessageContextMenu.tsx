import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Download, Forward, Pencil, Quote, RotateCw, Share2, Trash2 } from "lucide-react";

export type MessageMenuAction =
  | "copy"
  | "quote"
  | "edit"
  | "delete"
  | "forward"
  | "share"
  | "save"
  | "resend"
  | "deleteFile";

type Props = {
  messageId: string;
  x: number;
  y: number;
  /** Render the Copy row. */
  canCopy?: boolean;
  /** Render the Quote row. */
  canQuote?: boolean;
  /** Render the Edit row. Caller decides ownership + chat-type policy. */
  canEdit: boolean;
  /** Disable the Edit row but still render it (peer has already replied). */
  editLocked?: boolean;
  /** Render the Delete row. Caller decides ownership + chat-type policy. */
  canDelete: boolean;
  /** Render the Forward row for available attachment messages. */
  canForward?: boolean;
  /** Render the Share row for available attachment messages. */
  canShare?: boolean;
  /** Render the Save row for available attachment messages. */
  canSaveAttachment?: boolean;
  /** Render the Resend row: re-send an outbound file from the first chunk. */
  canResendAttachment?: boolean;
  /** Render the local file Delete row (removes this device's copy only). */
  canDeleteAttachment?: boolean;
  onAction: (action: MessageMenuAction, messageId: string) => void;
  onClose: () => void;
};

export function MessageContextMenu({
  messageId,
  x,
  y,
  canCopy = true,
  canQuote = true,
  canEdit,
  editLocked = false,
  canDelete,
  canForward = false,
  canShare = false,
  canSaveAttachment = false,
  canResendAttachment = false,
  canDeleteAttachment = false,
  onAction,
  onClose,
}: Props) {
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
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="chat-context-menu"
      role="menu"
      style={{ left: position.left, top: position.top }}
      onContextMenu={(event) => event.preventDefault()}
    >
      {canCopy && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("copy", messageId)}
        >
          <Copy size={15} />
          <span>{t("messageMenu.copy")}</span>
        </button>
      )}
      {canQuote && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("quote", messageId)}
        >
          <Quote size={15} />
          <span>{t("messageMenu.quote")}</span>
        </button>
      )}
      {canEdit && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("edit", messageId)}
          disabled={editLocked}
          title={editLocked ? t("messageMenu.editLockedHint") : undefined}
        >
          <Pencil size={15} />
          <span>{t("messageMenu.edit")}</span>
        </button>
      )}
      {canSaveAttachment && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("save", messageId)}
        >
          <Download size={15} />
          <span>{t("attachments.save")}</span>
        </button>
      )}
      {canForward && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("forward", messageId)}
        >
          <Forward size={15} />
          <span>{t("attachments.forward")}</span>
        </button>
      )}
      {canShare && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("share", messageId)}
        >
          <Share2 size={15} />
          <span>{t("attachments.share")}</span>
        </button>
      )}
      {canResendAttachment && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction("resend", messageId)}
        >
          <RotateCw size={15} />
          <span>{t("attachments.resend")}</span>
        </button>
      )}
      {canDeleteAttachment && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item destructive"
          onClick={() => onAction("deleteFile", messageId)}
        >
          <Trash2 size={15} />
          <span>{t("attachments.delete")}</span>
        </button>
      )}
      {canDelete && (
        <button
          type="button"
          role="menuitem"
          className="chat-context-menu-item destructive"
          onClick={() => onAction("delete", messageId)}
        >
          <Trash2 size={15} />
          <span>{t("messageMenu.delete")}</span>
        </button>
      )}
    </div>
  );
}
