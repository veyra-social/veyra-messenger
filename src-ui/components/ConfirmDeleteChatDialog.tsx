import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Chat } from "../lib/types";

type Props = {
  chat: Chat;
  onCancel: () => void;
  onConfirm: () => Promise<void> | void;
};

function messageKeyFor(chat: Chat): string {
  if (chat.is_self_chat) return "chatMenu.deleteConfirmSelf";
  return "chatMenu.deleteConfirmDirect";
}

export function ConfirmDeleteChatDialog({ chat, onCancel, onConfirm }: Props) {
  const { t } = useTranslation();
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function confirm() {
    setError("");
    setSubmitting(true);
    try {
      await onConfirm();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("chatMenu.deleteFailed"));
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <section className="modal" onClick={(event) => event.stopPropagation()}>
        <h1>{t("chatMenu.deleteTitle")}</h1>
        <p>{t(messageKeyFor(chat))}</p>
        {error && <div className="error">{error}</div>}
        <div className="modal-actions">
          <button type="button" onClick={onCancel} disabled={submitting}>
            {t("common.cancel")}
          </button>
          <button
            type="button"
            className="btn-destructive"
            onClick={confirm}
            disabled={submitting}
          >
            {t("chatMenu.delete")}
          </button>
        </div>
      </section>
    </div>
  );
}
