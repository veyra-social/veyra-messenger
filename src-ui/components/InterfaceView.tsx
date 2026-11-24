import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useLocale } from "../i18n/LocaleProvider";
import { LanguageSelect } from "./LanguageSelect";
import { useUiPrefs } from "../lib/UiPrefsProvider";
import { UI_SKINS, type UiFontScale, type UiSkin, type UiTheme } from "../lib/uiPrefs";
import { SkinPreview } from "./SkinPreview";
import { api } from "../lib/tauriApi";
import type { DesktopIntegrationPrefs } from "../lib/types";

type Props = {
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

const THEME_OPTIONS: UiTheme[] = ["auto", "light", "dark"];
const FONT_OPTIONS: UiFontScale[] = ["sm", "md", "lg", "xl"];

// Close-to-tray and login autostart only exist on desktop; phones neither
// have a tray nor allow that kind of autostart, so the whole section hides.
const isMobilePlatform =
  typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

export function InterfaceView({ showMobileBack, onMobileBack }: Props) {
  const { t } = useTranslation();
  const { locale, setLocale } = useLocale();
  const {
    prefs,
    setTheme,
    setUiFontScale,
    setChatFontScale,
    setSkin,
    setVideoAutoplayMuted,
    setKeepScreenOn,
  } = useUiPrefs();
  const [desktopPrefs, setDesktopPrefs] = useState<DesktopIntegrationPrefs | null>(null);
  const [desktopPrefsError, setDesktopPrefsError] = useState("");
  const [desktopPrefsSaving, setDesktopPrefsSaving] = useState(false);

  useEffect(() => {
    if (isMobilePlatform) return;
    let alive = true;
    api
      .getDesktopIntegrationPrefs()
      .then((next) => {
        if (alive) setDesktopPrefs(next);
      })
      .catch(() => {
        if (alive) setDesktopPrefs(null);
      });
    return () => {
      alive = false;
    };
  }, []);

  const updateCloseToTray = async (enabled: boolean) => {
    if (!desktopPrefs || desktopPrefsSaving) return;
    const previous = desktopPrefs;
    setDesktopPrefs({ ...previous, closeToTray: enabled });
    setDesktopPrefsError("");
    setDesktopPrefsSaving(true);
    try {
      await api.setCloseToTrayEnabled(enabled);
    } catch (err) {
      setDesktopPrefs(previous);
      setDesktopPrefsError(
        err instanceof Error ? err.message : t("interface.desktopIntegration.saveFailed"),
      );
    } finally {
      setDesktopPrefsSaving(false);
    }
  };

  const updateAutostart = async (enabled: boolean) => {
    if (!desktopPrefs || desktopPrefsSaving) return;
    const previous = desktopPrefs;
    setDesktopPrefs({ ...previous, autostart: enabled });
    setDesktopPrefsError("");
    setDesktopPrefsSaving(true);
    try {
      await api.setAutostartEnabled(enabled);
    } catch (err) {
      setDesktopPrefs(previous);
      setDesktopPrefsError(
        err instanceof Error ? err.message : t("interface.desktopIntegration.autostartFailed"),
      );
    } finally {
      setDesktopPrefsSaving(false);
    }
  };

  const skinKey = (skin: UiSkin): string => {
    switch (skin) {
      case "classic-imessage":
        return "classicImessage";
      default:
        return skin;
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
            <h1>{t("interface.title")}</h1>
            <small className="hint">{t("interface.hint")}</small>
          </div>
        </div>
      </header>
      <div className="settings-content">
        <section className="settings-section">
          <h2>{t("interface.languageLabel")}</h2>
          <LanguageSelect
            value={locale}
            onChange={(next) => {
              void setLocale(next, { persistToBackend: true });
            }}
          />
        </section>
        <section className="settings-section">
          <h2>{t("interface.theme.title")}</h2>
          <div className="theme-picker" role="radiogroup" aria-label={t("interface.theme.title")}>
            {THEME_OPTIONS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={prefs.theme === option}
                className={`theme-option${prefs.theme === option ? " selected" : ""}`}
                onClick={() => {
                  void setTheme(option);
                }}
              >
                <span className={`theme-swatch theme-swatch-${option}`} aria-hidden="true">
                  <span className="swatch-bubble" />
                </span>
                <span className="theme-option-label">{t(`interface.theme.${option}`)}</span>
              </button>
            ))}
          </div>
        </section>
        <section className="settings-section">
          <h2>{t("interface.fontSize.ui")}</h2>
          <div
            className="font-scale-picker"
            role="radiogroup"
            aria-label={t("interface.fontSize.ui")}
          >
            {FONT_OPTIONS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={prefs.uiFontScale === option}
                className={`font-scale-option${prefs.uiFontScale === option ? " selected" : ""}`}
                onClick={() => {
                  void setUiFontScale(option);
                }}
              >
                <span className={`font-scale-preview font-scale-preview-${option}`}>Aa</span>
                <span className="font-scale-option-label">{t(`interface.fontSize.${option}`)}</span>
              </button>
            ))}
          </div>
        </section>
        <section className="settings-section">
          <h2>{t("interface.fontSize.chat")}</h2>
          <div
            className="font-scale-picker"
            role="radiogroup"
            aria-label={t("interface.fontSize.chat")}
          >
            {FONT_OPTIONS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={prefs.chatFontScale === option}
                className={`font-scale-option${prefs.chatFontScale === option ? " selected" : ""}`}
                onClick={() => {
                  void setChatFontScale(option);
                }}
              >
                <span className={`font-scale-preview font-scale-preview-${option}`}>Aa</span>
                <span className="font-scale-option-label">{t(`interface.fontSize.${option}`)}</span>
              </button>
            ))}
          </div>
          <small className="hint">{t("interface.fontSize.chatHint")}</small>
        </section>
        <section className="settings-section">
          <h2>{t("interface.skin.title")}</h2>
          <div className="skin-picker" role="radiogroup" aria-label={t("interface.skin.title")}>
            {UI_SKINS.map((skin) => (
              <button
                key={skin}
                type="button"
                role="radio"
                aria-checked={prefs.skin === skin}
                className={`skin-option${prefs.skin === skin ? " selected" : ""}`}
                onClick={() => {
                  void setSkin(skin);
                }}
              >
                <SkinPreview skin={skin} />
                <span className="skin-option-label">{t(`interface.skin.${skinKey(skin)}`)}</span>
              </button>
            ))}
          </div>
        </section>
        <section className="settings-section">
          <h2>{t("interface.messages.title")}</h2>
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={prefs.videoAutoplayMuted}
              onChange={(event) => {
                void setVideoAutoplayMuted(event.target.checked);
              }}
            />
            {t("interface.messages.videoAutoplayMuted")}
          </label>
          <small className="hint">{t("interface.messages.videoAutoplayMutedHint")}</small>
        </section>
        {isMobilePlatform && (
          <section className="settings-section">
            <h2>{t("interface.screen.title")}</h2>
            <label className="checkbox-row">
              <input
                type="checkbox"
                role="switch"
                checked={prefs.keepScreenOn}
                onChange={(event) => {
                  void setKeepScreenOn(event.target.checked);
                }}
              />
              {t("interface.screen.keepScreenOn")}
            </label>
            <small className="hint">{t("interface.screen.keepScreenOnHint")}</small>
          </section>
        )}
        {!isMobilePlatform && desktopPrefs && (
          <section className="settings-section">
            <h2>{t("interface.desktopIntegration.title")}</h2>
            <label className="checkbox-row">
              <input
                type="checkbox"
                role="switch"
                checked={desktopPrefs.closeToTray}
                disabled={desktopPrefsSaving}
                onChange={(event) => {
                  void updateCloseToTray(event.target.checked);
                }}
              />
              {t("interface.desktopIntegration.closeToTray")}
            </label>
            <small className="hint">{t("interface.desktopIntegration.closeToTrayHint")}</small>
            <label className="checkbox-row">
              <input
                type="checkbox"
                role="switch"
                checked={desktopPrefs.autostart}
                disabled={desktopPrefsSaving}
                onChange={(event) => {
                  void updateAutostart(event.target.checked);
                }}
              />
              {t("interface.desktopIntegration.autostart")}
            </label>
            <small className="hint">{t("interface.desktopIntegration.autostartHint")}</small>
            {desktopPrefsError && <div className="error inline">{desktopPrefsError}</div>}
          </section>
        )}
      </div>
    </div>
  );
}
