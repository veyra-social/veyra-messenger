import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Contact } from "../lib/types";

type Props = {
  contact: Contact;
  onCancel: () => void;
  onConfirm: () => Promise<void> | void;
};

export function ConfirmDeleteContactDialog({ contact, onCancel, onConfirm }: Props) {
  const { t } = useTranslation();
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function confirm() {
    setError("");
    setSubmitting(true);
    try {
      await onConfirm();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("contactMenu.deleteFailed"));
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <section className="modal" onClick={(event) => event.stopPropagation()}>
        <h1>{t("contactMenu.deleteTitle")}</h1>
        <p>{t("contactMenu.deleteConfirm", { name: contact.display_name })}</p>
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
            {t("contactMenu.delete")}
          </button>
        </div>
      </section>
    </div>
  );
}
