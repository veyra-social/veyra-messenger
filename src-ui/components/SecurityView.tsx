import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Inbox, Loader2, MoreVertical, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { api } from "../lib/tauriApi";
import { BackupRestoreView } from "./BackupRestoreView";
import type { AppStatus, MyProfile } from "../lib/types";

type Props = {
  profile: MyProfile;
  status: AppStatus;
  onBackupImported: () => Promise<void>;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

function errorCode(err: unknown): string | null {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === "string" ? code : null;
  }
  return null;
}

export function SecurityView({
  profile,
  status,
  onBackupImported,
  showMobileBack,
  onMobileBack,
}: Props) {
  const { t } = useTranslation();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [duressMasterPassword, setDuressMasterPassword] = useState("");
  const [duressPassword, setDuressPassword] = useState("");
  const [duressConfirmPassword, setDuressConfirmPassword] = useState("");
  const [duressSaving, setDuressSaving] = useState(false);
  const [duressClearing, setDuressClearing] = useState(false);
  const [duressError, setDuressError] = useState("");
  const [duressSuccess, setDuressSuccess] = useState("");
  const [duressMenuOpen, setDuressMenuOpen] = useState(false);
  const [duressModalOpen, setDuressModalOpen] = useState(false);
  const duressMenuRef = useRef<HTMLDivElement>(null);
  const [offlineDelivery, setOfflineDelivery] = useState(true);
  const [offlineDeliverySaving, setOfflineDeliverySaving] = useState(false);
  const [attachAutoMedia, setAttachAutoMedia] = useState(true);
  const [attachAutoOther, setAttachAutoOther] = useState(false);
  const [attachSettingsSaving, setAttachSettingsSaving] = useState(false);

  useEffect(() => {
    api
      .getAttachmentReceiveSettings()
      .then((settings) => {
        setAttachAutoMedia(settings.media);
        setAttachAutoOther(settings.other);
      })
      .catch(() => undefined);
  }, []);

  async function saveAttachmentSettings(media: boolean, other: boolean) {
    setAttachSettingsSaving(true);
    const prev = { media: attachAutoMedia, other: attachAutoOther };
    setAttachAutoMedia(media);
    setAttachAutoOther(other);
    try {
      await api.setAttachmentReceiveSettings(media, other);
    } catch {
      setAttachAutoMedia(prev.media);
      setAttachAutoOther(prev.other);
    } finally {
      setAttachSettingsSaving(false);
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (!oldPassword || !newPassword) {
      setError(t("security.errors.empty"));
      return;
    }
    if (newPassword !== confirmPassword) {
      setError(t("security.errors.mismatch"));
      return;
    }
    if (newPassword === oldPassword) {
      setError(t("security.errors.sameAsOld"));
      return;
    }
    setSaving(true);
    try {
      await api.changeMasterPassword(oldPassword, newPassword);
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess(t("security.changePassword.success"));
    } catch (err) {
      const code = errorCode(err);
      if (code === "wrong_password") {
        setError(t("security.errors.wrongCurrent"));
      } else if (code === "weak_password") {
        setError(t("security.errors.weak"));
      } else if (code === "duress_password_matches_master") {
        setError(t("security.errors.duressSameAsMaster"));
      } else {
        setError(t("security.errors.failed"));
      }
    } finally {
      setSaving(false);
    }
  }

  async function submitDuress(event: React.FormEvent) {
    event.preventDefault();
    setDuressError("");
    setDuressSuccess("");
    if (!duressMasterPassword || !duressPassword) {
      setDuressError(t("security.errors.duressEmpty"));
      return;
    }
    if (duressPassword !== duressConfirmPassword) {
      setDuressError(t("security.errors.duressMismatch"));
      return;
    }
    if (duressPassword === duressMasterPassword) {
      setDuressError(t("security.errors.duressSameAsMaster"));
      return;
    }
    setDuressSaving(true);
    try {
      await api.setDuressPassword(duressMasterPassword, duressPassword);
      setDuressMasterPassword("");
      setDuressPassword("");
      setDuressConfirmPassword("");
      setDuressSuccess(t("security.duress.success"));
    } catch (err) {
      const code = errorCode(err);
      if (code === "wrong_password") {
        setDuressError(t("security.errors.wrongCurrent"));
      } else if (code === "weak_password") {
        setDuressError(t("security.errors.weak"));
      } else if (code === "duress_password_matches_master") {
        setDuressError(t("security.errors.duressSameAsMaster"));
      } else {
        setDuressError(t("security.errors.duressFailed"));
      }
    } finally {
      setDuressSaving(false);
    }
  }

  async function clearDuress() {
    setDuressError("");
    setDuressSuccess("");
    if (!duressMasterPassword) {
      setDuressError(t("security.errors.duressMasterRequired"));
      return;
    }
    setDuressClearing(true);
    try {
      await api.clearDuressPassword(duressMasterPassword);
      setDuressMasterPassword("");
      setDuressPassword("");
      setDuressConfirmPassword("");
      setDuressSuccess(t("security.duress.clearSuccess"));
    } catch (err) {
      const code = errorCode(err);
      if (code === "wrong_password") {
        setDuressError(t("security.errors.wrongCurrent"));
      } else {
        setDuressError(t("security.errors.duressClearFailed"));
      }
    } finally {
      setDuressClearing(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    void api
      .getOfflineDeliveryEnabled()
      .then((value) => {
        if (!cancelled) setOfflineDelivery(value);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function toggleOfflineDelivery(enabled: boolean) {
    setOfflineDelivery(enabled);
    setOfflineDeliverySaving(true);
    try {
      await api.setOfflineDeliveryEnabled(enabled);
    } catch {
      setOfflineDelivery(!enabled);
    } finally {
      setOfflineDeliverySaving(false);
    }
  }

  useEffect(() => {
    if (!duressMenuOpen) return;
    function onDocMouseDown(event: MouseEvent) {
      if (!duressMenuRef.current) return;
      if (!duressMenuRef.current.contains(event.target as Node)) setDuressMenuOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setDuressMenuOpen(false);
    }
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [duressMenuOpen]);

  const canSubmit = !!oldPassword && !!newPassword && !!confirmPassword && !saving;
  const duressBusy = duressSaving || duressClearing;
  const canSubmitDuress =
    !!duressMasterPassword && !!duressPassword && !!duressConfirmPassword && !duressBusy;
  const busy = saving || duressBusy;

  const duressForm = (
    <form className="auth-form" onSubmit={submitDuress}>
      <label>
        {t("security.duress.master")}
        <input
          type="password"
          autoComplete="current-password"
          value={duressMasterPassword}
          onChange={(event) => setDuressMasterPassword(event.target.value)}
          disabled={duressBusy}
        />
      </label>
      <label>
        {t("security.duress.password")}
        <input
          type="password"
          autoComplete="new-password"
          value={duressPassword}
          onChange={(event) => setDuressPassword(event.target.value)}
          disabled={duressBusy}
        />
      </label>
      <label>
        {t("security.duress.confirm")}
        <input
          type="password"
          autoComplete="new-password"
          value={duressConfirmPassword}
          onChange={(event) => setDuressConfirmPassword(event.target.value)}
          disabled={duressBusy}
        />
      </label>
      {duressError && <p className="security-callout is-error">{duressError}</p>}
      {duressSuccess && <p className="security-callout is-success">{duressSuccess}</p>}
      <button type="submit" disabled={!canSubmitDuress}>
        {duressSaving ? t("security.duress.saving") : t("security.duress.submit")}
      </button>
      <button
        type="button"
        className="secondary"
        onClick={clearDuress}
        disabled={!duressMasterPassword || duressBusy}
      >
        {duressClearing ? t("security.duress.clearing") : t("security.duress.clear")}
      </button>
    </form>
  );

  return (
    <div className="settings-view">
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
            <h1>{t("security.title")}</h1>
            <small className="hint">{t("security.subtitle")}</small>
          </div>
        </div>
      </header>
      <div className="settings-content">
        <section className="settings-section">
          <div className="security-section-heading">
            <h2>
              <ShieldCheck size={18} aria-hidden="true" /> {t("security.changePassword.title")}
            </h2>
            <div className="security-overflow" ref={duressMenuRef}>
              <button
                type="button"
                className="security-overflow-btn"
                aria-label={t("security.duress.menuLabel")}
                aria-haspopup="menu"
                aria-expanded={duressMenuOpen}
                onClick={() => setDuressMenuOpen((open) => !open)}
              >
                <MoreVertical size={18} aria-hidden="true" />
              </button>
              {duressMenuOpen && (
                <div
                  className="chat-context-menu security-overflow-menu"
                  role="menu"
                  onContextMenu={(event) => event.preventDefault()}
                >
                  <button
                    type="button"
                    role="menuitem"
                    className="chat-context-menu-item"
                    onClick={() => {
                      setDuressMenuOpen(false);
                      setDuressModalOpen(true);
                    }}
                  >
                    <ShieldAlert size={15} aria-hidden="true" />
                    <span>{t("security.duress.menuLabel")}</span>
                  </button>
                </div>
              )}
            </div>
          </div>
          <p className="hint">{t("security.changePassword.hint")}</p>
          <p className="security-callout is-warning">{t("security.backupWarning")}</p>
          <form className="auth-form" onSubmit={submit}>
            <label>
              {t("security.changePassword.current")}
              <input
                type="password"
                autoComplete="current-password"
                value={oldPassword}
                onChange={(event) => setOldPassword(event.target.value)}
                disabled={saving}
              />
            </label>
            <label>
              {t("security.changePassword.new")}
              <input
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                disabled={saving}
              />
            </label>
            <label>
              {t("security.changePassword.confirm")}
              <input
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                disabled={saving}
              />
            </label>
            {error && <p className="security-callout is-error">{error}</p>}
            {success && <p className="security-callout is-success">{success}</p>}
            <button type="submit" disabled={!canSubmit}>
              {saving
                ? t("security.changePassword.saving")
                : t("security.changePassword.submit")}
            </button>
          </form>
        </section>
        <section className="settings-section">
          <h2>
            <Inbox size={18} aria-hidden="true" /> {t("security.offlineDelivery.title")}
          </h2>
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={offlineDelivery}
              disabled={offlineDeliverySaving}
              onChange={(event) => {
                void toggleOfflineDelivery(event.target.checked);
              }}
            />
            {t("security.offlineDelivery.label")}
          </label>
          <small className="hint">{t("security.offlineDelivery.description")}</small>
          {!offlineDelivery && (
            <p className="security-callout is-warning">
              {t("security.offlineDelivery.disabledNote")}
            </p>
          )}
        </section>
        <section className="settings-section">
          <h2>
            <Inbox size={18} aria-hidden="true" /> {t("security.attachments.title")}
          </h2>
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={attachAutoMedia}
              disabled={attachSettingsSaving}
              onChange={(event) =>
                void saveAttachmentSettings(event.target.checked, attachAutoOther)
              }
            />
            {t("security.attachments.autoMedia")}
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={attachAutoOther}
              disabled={attachSettingsSaving}
              onChange={(event) =>
                void saveAttachmentSettings(attachAutoMedia, event.target.checked)
              }
            />
            {t("security.attachments.autoOther")}
          </label>
          <small className="hint">{t("security.attachments.hint")}</small>
        </section>
        <BackupRestoreView
          profile={profile}
          backupFormatVersion={status.backup_format_version}
          onImported={onBackupImported}
        />
      </div>
      {duressModalOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <section className="modal security-duress-modal">
            <button
              type="button"
              className="security-modal-close"
              onClick={() => setDuressModalOpen(false)}
              aria-label={t("common.close")}
              disabled={duressBusy}
            >
              <X size={18} aria-hidden="true" />
            </button>
            <h2>
              <ShieldAlert size={18} aria-hidden="true" /> {t("security.duress.title")}
            </h2>
            <p className="hint">{t("security.duress.hint")}</p>
            <p className="security-callout is-error">{t("security.duress.warning")}</p>
            <p className="security-callout is-warning">{t("security.duress.backupWarning")}</p>
            {duressForm}
          </section>
        </div>
      )}
      {busy && (
        <div
          className="modal-backdrop"
          role="alertdialog"
          aria-busy="true"
          aria-live="assertive"
        >
          <section className="modal security-progress-modal">
            <Loader2 className="spin" size={30} aria-hidden="true" />
            <h1>
              {saving
                ? t("security.changePassword.progressTitle")
                : t("security.duress.progressTitle")}
            </h1>
            <p>
              {saving
                ? t("security.changePassword.progressHint")
                : t("security.duress.progressHint")}
            </p>
            <p className="security-progress-danger">
              {saving
                ? t("security.changePassword.progressDanger")
                : t("security.duress.progressDanger")}
            </p>
          </section>
        </div>
      )}
    </div>
  );
}
