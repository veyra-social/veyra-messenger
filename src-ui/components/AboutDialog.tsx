import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ExternalLink, X } from "lucide-react";
import logo from "../assets/logos/Full.png";
import { api } from "../lib/tauriApi";
import type { UpdateCheckStatus, VersionInfo as VersionInfoType } from "../lib/types";
import { VersionInfo } from "./VersionInfo";

type Props = {
  onClose: () => void;
};

export function AboutDialog({ onClose }: Props) {
  const { t } = useTranslation();
  const [version, setVersion] = useState<VersionInfoType | null>(null);
  const [update, setUpdate] = useState<UpdateCheckStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkFailed, setCheckFailed] = useState(false);

  useEffect(() => {
    api.getVersionInfo().then(setVersion).catch(() => setVersion(null));
    api.getUpdateCheckStatus().then(setUpdate).catch(() => setUpdate(null));
  }, []);

  const runCheck = async () => {
    setChecking(true);
    setCheckFailed(false);
    try {
      setUpdate(await api.checkAppUpdate());
    } catch {
      setCheckFailed(true);
    } finally {
      setChecking(false);
    }
  };

  const toggleAutoCheck = async (enabled: boolean) => {
    try {
      setUpdate(await api.setUpdateAutoCheck(enabled));
    } catch {
      // keep the previous state; the checkbox re-renders from `update`
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section className="modal about-dialog" onClick={(event) => event.stopPropagation()}>
        <button className="modal-close" onClick={onClose} title={t("common.close")}>
          <X size={18} />
        </button>
        <img className="about-logo" src={logo} alt="Veyra" />
        <h1>{t("about.title")}</h1>
        {version ? <VersionInfo version={version} /> : <p className="hint">{t("common.loading")}</p>}
        <div className="about-updates">
          {update?.latest_version &&
            (update.update_available ? (
              <p className="about-update-recommend">{t("about.updateRecommended")}</p>
            ) : (
              <p className="hint">{t("about.upToDate")}</p>
            ))}
          {checkFailed && <p className="hint about-update-error">{t("about.checkFailed")}</p>}
          <button
            type="button"
            className="about-check-updates-btn"
            onClick={runCheck}
            disabled={checking}
          >
            {checking ? t("about.checking") : t("about.checkUpdates")}
          </button>
          <label className="about-autocheck">
            <input
              type="checkbox"
              role="switch"
              checked={update?.auto_check_enabled ?? true}
              onChange={(event) => toggleAutoCheck(event.target.checked)}
              disabled={!update}
            />
            <span>{t("about.autoCheck")}</span>
          </label>
          <small className="hint about-autocheck-hint">{t("about.autoCheckHint")}</small>
        </div>
        <a className="update-link" href="https://veyra.social" target="_blank" rel="noreferrer">
          {t("about.visitWebsite")}
          <ExternalLink size={15} />
        </a>
        <a
          className="update-link"
          href="https://veyra.social/privacy"
          target="_blank"
          rel="noreferrer"
        >
          {t("about.privacyPolicy")}
          <ExternalLink size={15} />
        </a>
      </section>
    </div>
  );
}
