import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

type Props = {
  initialTitle: string;
  onCancel: () => void;
  onSubmit: (title: string) => Promise<void> | void;
};

export function RenameChatDialog({ initialTitle, onCancel, onSubmit }: Props) {
  const { t } = useTranslation();
  const [title, setTitle] = useState(initialTitle);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  async function submit() {
    const trimmed = title.trim();
    if (!trimmed) return;
    setError("");
    setSubmitting(true);
    try {
      await onSubmit(trimmed);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("chatMenu.renameFailed"));
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <section className="modal" onClick={(event) => event.stopPropagation()}>
        <h1>{t("chatMenu.renameTitle")}</h1>
        <label>
          {t("chatMenu.renameLabel")}
          <input
            ref={inputRef}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && title.trim() && !submitting) {
                event.preventDefault();
                void submit();
              }
            }}
            maxLength={120}
            autoComplete="off"
          />
        </label>
        {error && <div className="error">{error}</div>}
        <div className="modal-actions">
          <button type="button" onClick={onCancel} disabled={submitting}>
            {t("common.cancel")}
          </button>
          <button type="button" onClick={submit} disabled={!title.trim() || submitting}>
            {t("common.save")}
          </button>
        </div>
      </section>
    </div>
  );
}
