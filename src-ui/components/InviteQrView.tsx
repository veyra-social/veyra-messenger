import { memo, useCallback, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { QRCodeSVG } from "qrcode.react";
import logoIcon from "../assets/logos/Icon.png";
import { APP_NAME_SHORT } from "../lib/appBrand";

type Props = {
  value: string;
  onClose: () => void;
  // Overlay texts default to the profile-invite wording; flows with a
  // different meaning (device pairing) supply their own.
  title?: string;
  subtitle?: string;
  hint?: string;
};

const QR_RENDER_SIZE = 1040;
const HISTORY_STATE_KEY = "__veyraInviteQr";

function InviteQrViewInner({ value, onClose, title, subtitle, hint }: Props) {
  const { t } = useTranslation();
  const resolvedTitle = title ?? t("profile.qrTitle");
  const resolvedSubtitle = subtitle ?? t("profile.qrWelcome", { appNameShort: APP_NAME_SHORT });
  const resolvedHint = hint ?? t("profile.qrFullscreenHint");
  const [ready, setReady] = useState(false);
  const closingRef = useRef(false);

  const close = useCallback(() => {
    if (closingRef.current) return;
    closingRef.current = true;
    onClose();
    if (typeof window !== "undefined" && window.history.state?.[HISTORY_STATE_KEY]) {
      window.history.back();
    }
  }, [onClose]);

  useEffect(() => {
    setReady(false);
    const id = window.setTimeout(() => setReady(true), 0);
    return () => window.clearTimeout(id);
  }, [value]);

  useEffect(() => {
    const previousState = window.history.state;
    window.history.pushState({ ...previousState, [HISTORY_STATE_KEY]: true }, "");
    const handlePopState = () => {
      if (closingRef.current) return;
      closingRef.current = true;
      onClose();
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    };
    window.addEventListener("popstate", handlePopState);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("popstate", handlePopState);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [close, onClose]);

  return (
    <div className="qr-fullscreen" role="dialog" aria-modal="true" aria-label={resolvedTitle}>
      <button
        type="button"
        className="qr-fullscreen-close"
        onClick={close}
        aria-label={t("common.close")}
        title={t("common.close")}
      >
        <X size={24} strokeWidth={2} />
      </button>
      <header className="qr-fullscreen-header">
        <img src={logoIcon} alt="" aria-hidden="true" />
        <div>
          <h2>{resolvedTitle}</h2>
          <small>{resolvedSubtitle}</small>
        </div>
      </header>
      <main className="qr-fullscreen-main">
        <div className="qr-scan-surface">
          {ready ? (
            <QRCodeSVG
              className="qr-code-svg"
              value={value}
              size={QR_RENDER_SIZE}
              level="M"
              bgColor="#ffffff"
              fgColor="#000000"
              marginSize={6}
            />
          ) : (
            <div className="qr-card-placeholder" aria-busy="true">
              {t("profile.generatingQr")}
            </div>
          )}
        </div>
      </main>
      <small className="qr-fullscreen-hint">{resolvedHint}</small>
    </div>
  );
}

export const InviteQrView = memo(InviteQrViewInner);
