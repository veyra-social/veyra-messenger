import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Camera, ChevronUp } from "lucide-react";
import type { Contact, ParsedInvite } from "../lib/types";
import { api } from "../lib/tauriApi";
import { QrScanner } from "./QrScanner";
import { useInputContextMenu } from "../lib/useInputContextMenu";
import { InputContextMenu } from "./InputContextMenu";

type Props = {
  onAdded: (contact: Contact) => Promise<void>;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

export function AddContactPage({ onAdded, showMobileBack, onMobileBack }: Props) {
  const { t } = useTranslation();
  const [displayName, setDisplayName] = useState("");
  const [invite, setInvite] = useState("");
  const [autoFilled, setAutoFilled] = useState(false);
  const [parsed, setParsed] = useState<ParsedInvite | null>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showQr, setShowQr] = useState(false);
  const [scannedInvite, setScannedInvite] = useState(false);

  const inviteRef = useRef<HTMLTextAreaElement>(null);
  const inviteMenu = useInputContextMenu();

  useEffect(() => {
    const value = invite.trim();
    if (!value.startsWith("veyra:")) {
      setParsed(null);
      return;
    }
    const handle = window.setTimeout(() => {
      api
        .parseInviteString(value)
        .then((p) => {
          setParsed(p);
          if (!displayName.trim() && p.suggested_display_name) {
            setDisplayName(p.suggested_display_name);
            setAutoFilled(true);
          }
        })
        .catch(() => setParsed(null));
    }, 200);
    return () => window.clearTimeout(handle);
    // displayName intentionally excluded; we only auto-fill when it's empty.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [invite]);

  function onScanned(text: string) {
    setInvite(text);
    setScannedInvite(true);
    setError("");
    // Hide the scanner once we have a value — keeps the main task path lean
    // (invite + display-name + Add visible without scrolling).
    setShowQr(false);
  }

  async function submit() {
    setError("");
    setSubmitting(true);
    let contactAdded = false;
    try {
      const contact = await api.addContact(
        invite.trim(),
        displayName.trim(),
        scannedInvite ? "qr_scan" : "pasted",
      );
      contactAdded = true;
      await onAdded(contact);
    } catch (err) {
      if (contactAdded) {
        const reason = formatErrorMessage(err);
        setError(
          reason
            ? t("addContact.addedNoChatWithReason", { reason })
            : t("addContact.addedNoChat"),
        );
        if (import.meta.env.DEV) {
          console.error("add contact: chat open failed", err);
        }
      } else {
        setError(
          err instanceof Error ? err.message : t("addContact.invalidInvite"),
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="add-contact-page settings-view">
      <header className="settings-header">
        <div className="settings-header-row">
          {showMobileBack && onMobileBack && (
            <button
              type="button"
              className="mobile-back-btn"
              onClick={onMobileBack}
              aria-label={t("common.backToChatList")}
            >
              <ArrowLeft size={22} strokeWidth={2} />
            </button>
          )}
          <div className="settings-header-text">
            <h1>{t("addContact.title")}</h1>
            <small className="hint">{t("addContact.pageHint")}</small>
          </div>
        </div>
      </header>

      <div className="add-contact-form">
        <label className="add-contact-label">
          {t("addContact.inviteString")}
          <textarea
            ref={inviteRef}
            value={invite}
            onChange={(event) => {
              setInvite(event.target.value);
              setScannedInvite(false);
            }}
            rows={3}
            {...inviteMenu.bind}
          />
          <InputContextMenu
            position={inviteMenu.menuPosition}
            onClose={inviteMenu.closeMenu}
            inputRef={inviteRef}
          />
        </label>
        {parsed && (
          <small className="hint">
            {t("addContact.fingerprint", { value: parsed.fingerprint })}
            {parsed.legacy && <span> {t("addContact.legacyInvite")}</span>}
          </small>
        )}

        <button
          type="button"
          className="ghost-toggle add-contact-qr-toggle"
          onClick={() => setShowQr((s) => !s)}
          aria-expanded={showQr}
        >
          {showQr ? (
            <>
              <ChevronUp size={16} /> {t("addContact.toggleQrHide")}
            </>
          ) : (
            <>
              <Camera size={16} /> {t("addContact.toggleQrShow")}
            </>
          )}
        </button>
        {showQr && (
          <div className="add-contact-qr">
            <QrScanner onScan={onScanned} />
          </div>
        )}

        <label className="add-contact-label">
          {t("addContact.displayName")}
          <input
            value={displayName}
            onChange={(event) => {
              setDisplayName(event.target.value);
              setAutoFilled(false);
            }}
          />
        </label>
        {autoFilled && parsed?.suggested_display_name && (
          <small className="hint">{t("addContact.suggestedHint")}</small>
        )}

        {error && <div className="error">{error}</div>}

        <button
          type="button"
          className="primary add-contact-submit"
          onClick={submit}
          disabled={!invite.trim() || submitting}
        >
          {submitting ? t("addContact.adding") : t("common.add")}
        </button>
      </div>
    </div>
  );
}

function formatErrorMessage(err: unknown): string {
  if (err instanceof Error && err.message) {
    return err.message;
  }
  if (typeof err === "string" && err) {
    return err;
  }
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message?: unknown }).message;
    if (typeof message === "string" && message) {
      return message;
    }
  }
  return "";
}
