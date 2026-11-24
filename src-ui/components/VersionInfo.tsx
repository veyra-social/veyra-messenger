import { useTranslation } from "react-i18next";
import type { VersionInfo as VersionInfoType } from "../lib/types";
import { isDebugUi } from "../uiMode";

/// Which artifact is this, in the terms the build actually has?
///
/// Two independent axes: the Rust profile (`debug_assertions`) and the UI
/// branch (`buildall -DebugUi`, which leaves the binary on the release
/// profile). A `-debugui` Windows build is therefore a release binary with
/// the developer UI — reporting just "Release" for it contradicts the
/// artifact's own name, so when the two disagree the label says both.
function buildLabel(debugBuild: boolean): string {
  const profile = debugBuild ? "Debug" : "Release";
  if (debugBuild === isDebugUi) return profile;
  return `${profile} · ${isDebugUi ? "debug-UI" : "release-UI"}`;
}

// Release UI keeps the About box to what a user can act on: app version and
// protocol version. The full component-version grid (envelope, DB schema,
// backup format, crypto suite) is a debug-UI diagnostic.
export function VersionInfo({ version }: { version: VersionInfoType }) {
  const { t } = useTranslation();
  return (
    <div className="version-grid">
      <span>{t("version.app")}</span>
      <strong>{version.app_version}</strong>
      <span>{t("version.build")}</span>
      <strong>{buildLabel(version.debug_build)}</strong>
      <span>{t("version.protocol")}</span>
      <strong>{version.protocol_version}</strong>
      {isDebugUi && (
        <>
          <span>{t("version.envelope")}</span>
          <strong>{version.message_envelope_version}</strong>
          <span>{t("version.dbSchema")}</span>
          <strong>{version.database_schema_version}</strong>
          <span>{t("version.backupFormat")}</span>
          <strong>{version.backup_format_version}</strong>
          <span>{t("version.cryptoSuite")}</span>
          <strong>{version.crypto_suite_version}</strong>
        </>
      )}
    </div>
  );
}
