import { useEffect, useState } from "react";
import { ArrowLeft, Play, Square } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { NotificationPrefs, NotificationPreviewMode } from "../lib/types";
import { api } from "../lib/tauriApi";
import {
  previewCallRingtone,
  previewInviteSound,
  previewMessageSound,
  setNotificationSoundPrefs,
  stopSoundPreview,
  subscribeSoundPreview,
  type SoundPreviewKey,
} from "../lib/notificationSounds";
import {
  isSystemNotificationPermissionGranted,
  sendTestSystemNotification,
  setSystemNotificationPrefs,
} from "../lib/systemNotifications";
import { setHapticPrefs } from "../lib/haptics";
import {
  isBatteryExemptionSupported,
  isIgnoringBatteryOptimizations,
  openBatteryOptimizationSettings,
  requestBatteryExemption,
} from "../lib/nativeBridge";

// Foreground haptics only make sense on phones; hide the toggle on desktop.
const isMobile =
  typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

const PREVIEW_MODES: NotificationPreviewMode[] = ["private", "sender", "message"];

type Props = {
  showMobileBack?: boolean;
  onMobileBack?: () => void;
  onPrefsChanged?: (prefs: NotificationPrefs) => void;
};

export function NotificationsView({ showMobileBack, onMobileBack, onPrefsChanged }: Props) {
  const { t } = useTranslation();
  const [prefs, setPrefs] = useState<NotificationPrefs | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [permissionGranted, setPermissionGranted] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  // Phase B: Android battery-optimization exemption. `batterySupported` is true
  // only where the native bridge exposes it (Android); `batteryExempt` mirrors
  // the current OS state and is re-read when the user returns from the system
  // dialog (window focus / visibility change).
  const batterySupported = isBatteryExemptionSupported();
  const [batteryExempt, setBatteryExempt] = useState<boolean | null>(null);
  // Which cue is currently previewing; the play button becomes a stop button.
  const [previewPlaying, setPreviewPlaying] = useState<SoundPreviewKey | null>(null);

  useEffect(() => {
    const unsubscribe = subscribeSoundPreview(setPreviewPlaying);
    return () => {
      unsubscribe();
      stopSoundPreview();
    };
  }, []);

  useEffect(() => {
    let alive = true;
    Promise.all([api.getNotificationPrefs(), isSystemNotificationPermissionGranted()])
      .then(([next, granted]) => {
        if (!alive) return;
        setPrefs(next);
        setPermissionGranted(granted);
        setNotificationSoundPrefs(next);
        setSystemNotificationPrefs(next);
        setHapticPrefs(next);
        onPrefsChanged?.(next);
      })
      .catch((err) => {
        if (!alive) return;
        setError(err instanceof Error ? err.message : t("notifications.loadFailed"));
      });
    return () => {
      alive = false;
    };
  }, [onPrefsChanged, t]);

  useEffect(() => {
    if (!batterySupported) return;
    const refresh = () => setBatteryExempt(isIgnoringBatteryOptimizations());
    refresh();
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [batterySupported]);

  const updatePref = async <K extends keyof NotificationPrefs>(
    key: K,
    value: NotificationPrefs[K],
  ) => {
    if (!prefs || saving) return;
    const previous = prefs;
    const next = { ...previous, [key]: value };
    setPrefs(next);
    setNotificationSoundPrefs(next);
    setSystemNotificationPrefs(next);
    setHapticPrefs(next);
    onPrefsChanged?.(next);
    setError("");
    setSaving(true);
    try {
      await api.setNotificationPrefs(next);
    } catch (err) {
      setPrefs(previous);
      setNotificationSoundPrefs(previous);
      setSystemNotificationPrefs(previous);
      setHapticPrefs(previous);
      onPrefsChanged?.(previous);
      setError(err instanceof Error ? err.message : t("notifications.saveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const testSystemNotification = async () => {
    if (!prefs || testing) return;
    setError("");
    setTesting(true);
    try {
      const sent = await sendTestSystemNotification({
        appTitle: "Veyra",
        newMessage: t("notifications.newMessage"),
        newInvite: t("notifications.newInvite"),
        incomingCall: t("notifications.incomingCall"),
        testBody: t("notifications.testBody"),
        sampleSender: t("notifications.sampleSender"),
        sampleMessage: t("notifications.sampleMessage"),
      });
      setPermissionGranted(sent);
      if (!sent) {
        setError(t("notifications.permissionDenied"));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t("notifications.testFailed"));
    } finally {
      setTesting(false);
    }
  };

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
            <h1>{t("notifications.title")}</h1>
            <small className="hint">{t("notifications.hint")}</small>
          </div>
        </div>
      </header>
      <div className="settings-content">
        {!prefs && !error && (
          <section className="settings-section">
            <small className="hint">{t("common.loading")}</small>
          </section>
        )}
        {prefs && (
          <>
            <section className="settings-section">
              <h2>{t("notifications.systemTitle")}</h2>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  role="switch"
                  checked={prefs.notificationsEnabled}
                  disabled={saving}
                  onChange={(event) => {
                    void updatePref("notificationsEnabled", event.target.checked);
                  }}
                />
                {t("notifications.systemEnabled")}
              </label>
              <small className="hint">{t("notifications.systemHint")}</small>
              <small className="hint">
                {permissionGranted === null
                  ? t("common.loading")
                  : permissionGranted
                    ? t("notifications.permissionGranted")
                    : t("notifications.permissionMissing")}
              </small>
              <button
                type="button"
                onClick={() => void testSystemNotification()}
                disabled={saving || testing || !prefs.notificationsEnabled}
              >
                {t("notifications.testSystem")}
              </button>
            </section>
            <section className="settings-section">
              <h2>{t("notifications.previewTitle")}</h2>
              <div
                className="preview-mode-picker"
                role="radiogroup"
                aria-label={t("notifications.previewTitle")}
              >
                {PREVIEW_MODES.map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    role="radio"
                    aria-checked={prefs.notificationPreviewMode === mode}
                    className={`preview-mode-option${
                      prefs.notificationPreviewMode === mode ? " selected" : ""
                    }`}
                    disabled={saving || !prefs.notificationsEnabled}
                    onClick={() => {
                      void updatePref("notificationPreviewMode", mode);
                    }}
                  >
                    <span className="preview-mode-label">
                      {t(`notifications.preview.${mode}`)}
                    </span>
                    <span className="preview-mode-desc">
                      {t(`notifications.preview.${mode}Hint`)}
                    </span>
                  </button>
                ))}
              </div>
              <small className="hint">{t("notifications.previewHint")}</small>
            </section>
            <section className="settings-section">
              <h2>{t("notifications.soundsTitle")}</h2>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  role="switch"
                  checked={prefs.notificationSoundsEnabled}
                  disabled={saving || !prefs.notificationsEnabled}
                  onChange={(event) => {
                    void updatePref("notificationSoundsEnabled", event.target.checked);
                  }}
                />
                {t("notifications.soundsEnabled")}
              </label>
              <div className="notification-cue-row">
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={prefs.messageSoundEnabled}
                    disabled={
                      saving || !prefs.notificationsEnabled || !prefs.notificationSoundsEnabled
                    }
                    onChange={(event) => {
                      void updatePref("messageSoundEnabled", event.target.checked);
                    }}
                  />
                  {t("notifications.messageSound")}
                </label>
                <button
                  type="button"
                  className="cue-test-btn"
                  onClick={() =>
                    previewPlaying === "message" ? stopSoundPreview() : previewMessageSound()
                  }
                  aria-label={
                    previewPlaying === "message"
                      ? t("notifications.stopSoundAria")
                      : t("notifications.testSoundAria")
                  }
                >
                  {previewPlaying === "message" ? (
                    <Square size={14} aria-hidden="true" />
                  ) : (
                    <Play size={14} aria-hidden="true" />
                  )}
                </button>
              </div>
              <div className="notification-cue-row">
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={prefs.inviteSoundEnabled}
                    disabled={
                      saving || !prefs.notificationsEnabled || !prefs.notificationSoundsEnabled
                    }
                    onChange={(event) => {
                      void updatePref("inviteSoundEnabled", event.target.checked);
                    }}
                  />
                  {t("notifications.inviteSound")}
                </label>
                <button
                  type="button"
                  className="cue-test-btn"
                  onClick={() =>
                    previewPlaying === "invite" ? stopSoundPreview() : previewInviteSound()
                  }
                  aria-label={
                    previewPlaying === "invite"
                      ? t("notifications.stopSoundAria")
                      : t("notifications.testSoundAria")
                  }
                >
                  {previewPlaying === "invite" ? (
                    <Square size={14} aria-hidden="true" />
                  ) : (
                    <Play size={14} aria-hidden="true" />
                  )}
                </button>
              </div>
              <div className="notification-cue-row">
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={prefs.callRingtoneEnabled}
                    disabled={
                      saving || !prefs.notificationsEnabled || !prefs.notificationSoundsEnabled
                    }
                    onChange={(event) => {
                      void updatePref("callRingtoneEnabled", event.target.checked);
                    }}
                  />
                  {t("notifications.callRingtone")}
                </label>
                <button
                  type="button"
                  className="cue-test-btn"
                  onClick={() =>
                    previewPlaying === "call" ? stopSoundPreview() : previewCallRingtone()
                  }
                  aria-label={
                    previewPlaying === "call"
                      ? t("notifications.stopSoundAria")
                      : t("notifications.testSoundAria")
                  }
                >
                  {previewPlaying === "call" ? (
                    <Square size={14} aria-hidden="true" />
                  ) : (
                    <Play size={14} aria-hidden="true" />
                  )}
                </button>
              </div>
            </section>
            {isMobile && (
              <section className="settings-section">
                <h2>{t("notifications.vibrationTitle")}</h2>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={prefs.vibrationEnabled}
                    disabled={saving || !prefs.notificationsEnabled}
                    onChange={(event) => {
                      void updatePref("vibrationEnabled", event.target.checked);
                    }}
                  />
                  {t("notifications.vibrationEnabled")}
                </label>
                <small className="hint">{t("notifications.vibrationHint")}</small>
              </section>
            )}
            {batterySupported && (
              <section className="settings-section">
                <h2>{t("notifications.backgroundTitle")}</h2>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={batteryExempt === true}
                    onChange={(event) => {
                      if (event.target.checked) {
                        requestBatteryExemption();
                      } else {
                        openBatteryOptimizationSettings();
                      }
                    }}
                  />
                  {t("notifications.allowBackground")}
                </label>
                <small className="hint">{t("notifications.backgroundHint")}</small>
                <small className="hint">
                  {batteryExempt === null
                    ? t("common.loading")
                    : batteryExempt
                      ? t("notifications.backgroundExempt")
                      : t("notifications.backgroundRestricted")}
                </small>
              </section>
            )}
          </>
        )}
        {error && <div className="error inline">{error}</div>}
      </div>
    </div>
  );
}
