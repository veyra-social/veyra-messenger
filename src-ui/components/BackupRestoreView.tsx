import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirm, open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { Loader2 } from "lucide-react";
import { api } from "../lib/tauriApi";
import { setBackupKeepScreenOn } from "../lib/nativeBridge";
import { useIsAndroid, useIsIOS } from "../lib/usePlatform";
import {
  base64ToBytes,
  hasNativeBackupPickers,
  pickBackupExportPath,
  pickBackupImportPath,
  safeFileStem,
  timestampForFilename,
  writeTempFileToPath,
  writeBytesToPath,
} from "../lib/backupIO";
import {
  openBackupSource,
  inspectBackupSource,
  importBackupSource,
  releaseBackupSource,
  type BackupSource,
} from "../lib/backupSource";
import type { BackupImportMode, BackupMetadata, MyProfile } from "../lib/types";

type Props = {
  profile: MyProfile;
  backupFormatVersion: number;
  onImported: () => Promise<void>;
};

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

// The done screen names the saved file. SAF picks come back as encoded
// content:// URIs, so decode first and take the last path-ish segment.
function displayFileName(path: string): string {
  let value = path;
  try {
    value = decodeURIComponent(path);
  } catch {
    // keep the raw path
  }
  const segments = value.split(/[/\\:]/).filter(Boolean);
  return segments[segments.length - 1] || value;
}

type ExportProgress = { stage: string; done: number; total: number };

export function BackupRestoreView({ profile, backupFormatVersion, onImported }: Props) {
  const { t } = useTranslation();
  const isAndroid = useIsAndroid();
  const isIOS = useIsIOS();
  const [exportKind, setExportKind] = useState<"full" | "identity" | "identity_contacts" | null>(null);
  const [exportPath, setExportPath] = useState<string | null>(null);
  const [exportPassword, setExportPassword] = useState("");
  const [exportStatus, setExportStatus] = useState<"password" | "exporting" | "done">("password");
  const [exportProgress, setExportProgress] = useState<ExportProgress | null>(null);
  const [exportedSize, setExportedSize] = useState<number | null>(null);
  // Once the flow reaches the frontend-owned "save" stage (SAF/plugin-fs copy),
  // late backend stage events must not flip the label back.
  const exportSaveStageRef = useRef(false);
  const [importPath, setImportPath] = useState<string | null>(null);
  const [importMetadata, setImportMetadata] = useState<BackupMetadata | null>(null);
  const [importPreparing, setImportPreparing] = useState<"read" | "inspect" | null>(null);
  const [importSource, setImportSource] = useState<BackupSource | null>(null);
  const [importPassword, setImportPassword] = useState("");
  const [importMode, setImportMode] = useState<BackupImportMode>("restore");
  const [importStatus, setImportStatus] = useState<"password" | "importing" | "restarting">(
    "password",
  );
  const [message, setMessage] = useState("");
  const [isError, setIsError] = useState(false);

  function backupErrorMessage(err: unknown, fallbackKey: string) {
    const code =
      err && typeof err === "object" && "code" in err
        ? String((err as { code: unknown }).code)
        : "";
    if (code === "backup_path_must_be_file") {
      return t("backup.pathMustBeFile");
    }
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
    return t(fallbackKey);
  }

  function exportStageLabel(progress: ExportProgress | null): string {
    const stage = progress?.stage ?? "collect";
    if (stage === "encrypt") {
      return t("backup.exportStageEncrypt", {
        size: formatFileSize(progress?.total ?? 0),
      });
    }
    if (stage === "pack") return t("backup.exportStagePack");
    if (stage === "write") return t("backup.exportStageWrite");
    if (stage === "save") return t("backup.exportStageSave");
    return t("backup.exportStageCollect");
  }

  function backupKindLabel(kind: string) {
    if (kind === "identity") return t("backup.kindIdentity");
    if (kind === "identity_contacts") return t("backup.kindIdentityContacts");
    return t("backup.kindFull");
  }

  function backupProfileLabel(metadata?: BackupMetadata | null) {
    return metadata?.profile_display_name || t("backup.unnamedProfile");
  }

  async function chooseExportPath(kind: "full" | "identity" | "identity_contacts") {
    setMessage("");
    setIsError(false);
    try {
      const defaultFilename = `${safeFileStem(profile.display_name)}-${timestampForFilename()}.${backupFormatVersion}.vmb`;
      let path: string | null = null;
      if (isAndroid && hasNativeBackupPickers()) {
        path = await pickBackupExportPath(defaultFilename);
      } else {
        const chosenPath = await save({
          title: t("backup.saveDialogTitle"),
          defaultPath: defaultFilename,
          filters: [{ name: t("backup.vmbFiles"), extensions: ["vmb"] }],
        });
        if (!chosenPath) return;
        path =
          chosenPath.toLowerCase().endsWith(".vmb") || chosenPath.startsWith("content://")
            ? chosenPath
            : `${chosenPath}.vmb`;
      }
      if (!path) return;
      setExportKind(kind);
      setExportPath(path);
      setExportPassword("");
      setExportStatus("password");
    } catch (err) {
      setIsError(true);
      setMessage(backupErrorMessage(err, "backup.exportFailed"));
    }
  }

  function enterExportSaveStage() {
    exportSaveStageRef.current = true;
    setExportProgress({ stage: "save", done: 0, total: 0 });
  }

  async function exportBackup() {
    if (!exportPath || !exportPassword || !exportKind) return;
    setMessage("");
    setIsError(false);
    exportSaveStageRef.current = false;
    setExportProgress({ stage: "collect", done: 0, total: 0 });
    setExportedSize(null);
    // Subscribe before invoking the export command so no early stage is lost.
    const unlisten = await listen<ExportProgress>("backup-export-progress", (event) => {
      if (event.payload.stage === "done") {
        setExportedSize(event.payload.total);
        return;
      }
      if (!exportSaveStageRef.current) {
        setExportProgress(event.payload);
      }
    });
    setBackupKeepScreenOn(true);
    try {
      setExportStatus("exporting");
      if (isAndroid) {
        let tempPath: string | null = null;
        try {
          tempPath = await api.exportBackupTempFile(exportPassword, exportKind);
          enterExportSaveStage();
          const copiedFromTemp = await writeTempFileToPath(exportPath, tempPath);
          if (!copiedFromTemp) {
            const b64 = await api.serializeBackup(exportPassword, exportKind);
            const bytes = base64ToBytes(b64);
            setExportedSize(bytes.length);
            enterExportSaveStage();
            await writeBytesToPath(exportPath, bytes);
          }
        } finally {
          if (tempPath) {
            void api.deleteBackupTempFile(tempPath).catch(() => {});
          }
        }
      } else if (isIOS) {
        const b64 = await api.serializeBackup(exportPassword, exportKind);
        const bytes = base64ToBytes(b64);
        setExportedSize(bytes.length);
        enterExportSaveStage();
        await writeBytesToPath(exportPath, bytes);
      } else {
        await api.exportBackup(exportPath, exportPassword, exportKind);
      }
      setExportStatus("done");
      setMessage(t("backup.exported"));
    } catch (err) {
      setExportStatus("password");
      setIsError(true);
      setMessage(backupErrorMessage(err, "backup.exportFailed"));
    } finally {
      setBackupKeepScreenOn(false);
      // The final "done" event races the command resolution on desktop by a
      // hair; give the event queue one beat before unsubscribing.
      await new Promise((resolve) => setTimeout(resolve, 50));
      unlisten();
      setExportProgress(null);
    }
  }

  async function chooseImportFile() {
    setMessage("");
    setIsError(false);
    try {
      // Android's SAF picker silently filters out `.vmb` when we pass an
      // extension filter, because MimeTypeMap has no mapping for `vmb` and
      // the resulting MIME filter excludes every file we care about. Even
      // passing `filters: []` makes Tauri set an empty MIME list, which
      // Android then interprets as "match nothing". The only way to let
      // the user pick a .vmb on Android is to omit `filters` entirely so
      // the Intent falls back to `*/*`. Desktop platforms keep the
      // friendlier extension filter.
      const chosenPath =
        isAndroid && hasNativeBackupPickers()
          ? await pickBackupImportPath()
          : await open({
              title: t("backup.openDialogTitle"),
              multiple: false,
              directory: false,
              ...(isAndroid
                ? {}
                : {
                    filters: [
                      { name: t("backup.vmbFiles"), extensions: ["vmb"] },
                      { name: t("backup.legacyFiles"), extensions: ["veyra-backup"] },
                    ],
                  }),
            });
      if (!chosenPath || Array.isArray(chosenPath)) return;
      const path = chosenPath;
      // Materialize the pick once while the dialog's URI grant is still
      // active (Android streams it into a backend temp file, desktop keeps
      // the path, iOS keeps bytes). The subsequent inspect + import calls
      // reuse that source -- re-opening the same content URI after the
      // dialog flow ends fails with SecurityException / EBADF.
      let source: BackupSource | null = null;
      setImportPreparing("read");
      setBackupKeepScreenOn(true);
      try {
        source = await openBackupSource(path, isIOS);
        setImportPreparing("inspect");
        const metadata = await inspectBackupSource(source);
        setImportPath(path);
        setImportMetadata(metadata);
        setImportSource(source);
        setImportPassword("");
        setImportStatus("password");
      } catch (err) {
        releaseBackupSource(source);
        throw err;
      } finally {
        setImportPreparing(null);
        setBackupKeepScreenOn(false);
      }
    } catch (err) {
      setIsError(true);
      setMessage(backupErrorMessage(err, "backup.importFailed"));
    }
  }

  function closeImportDialog() {
    releaseBackupSource(importSource);
    setImportPath(null);
    setImportMetadata(null);
    setImportSource(null);
    setImportPassword("");
  }

  async function importBackup() {
    if (!importSource || !importPassword) return;
    setMessage("");
    setIsError(false);
    try {
      if (
        !(await confirm(
          t("backup.replaceConfirm", {
            name: backupProfileLabel(importMetadata),
          }),
          { title: t("backup.replaceTitle"), kind: "warning" },
        ))
      ) {
        return;
      }
      setImportStatus("importing");
      setBackupKeepScreenOn(true);
      try {
        await importBackupSource(importSource, importPassword, importMode);
      } finally {
        setBackupKeepScreenOn(false);
      }
      // The libp2p node keeps its in-memory identity for the process
      // lifetime, so a restart is required before the swarm matches the
      // imported database (multi-device Round 0). Fallback: if programmatic
      // restart is unavailable on this platform, fall back to the old
      // in-place refresh after a short beat.
      setImportStatus("restarting");
      void api.restartApp().catch(() => {});
      window.setTimeout(() => {
        closeImportDialog();
        setImportStatus("password");
        void onImported().then(() => setMessage(t("backup.imported")));
      }, 2500);
    } catch (err) {
      setImportStatus("password");
      setIsError(true);
      setMessage(backupErrorMessage(err, "backup.importFailed"));
    }
  }

  return (
    <section className="settings-section">
      <h2>{t("backup.title")}</h2>
      {isAndroid && (
        <p className="hint backup-android-folder-hint">
          {t("backup.androidFolderHint")}
        </p>
      )}
      <div className="backup-flow-grid">
        <div className="backup-flow-card">
          <div className="backup-flow-head">
            <h3>{t("backup.exportTitle")}</h3>
            <p className="hint">{t("backup.exportFlowHint")}</p>
          </div>
          <div className="backup-kind-picker">
            <div className="backup-kind-heading">{t("backup.kindTitle")}</div>
            <button type="button" className="backup-kind-card" onClick={() => void chooseExportPath("identity")}>
              <span className="backup-kind-title">{t("backup.kindIdentity")}</span>
              <span className="backup-kind-copy">{t("backup.kindIdentityHint")}</span>
            </button>
            <button type="button" className="backup-kind-card" onClick={() => void chooseExportPath("identity_contacts")}>
              <span className="backup-kind-title">{t("backup.kindIdentityContacts")}</span>
              <span className="backup-kind-copy">{t("backup.kindIdentityContactsHint")}</span>
            </button>
            <button type="button" className="backup-kind-card" onClick={() => void chooseExportPath("full")}>
              <span className="backup-kind-title">{t("backup.kindFull")}</span>
              <span className="backup-kind-copy">{t("backup.kindFullHint")}</span>
            </button>
          </div>
        </div>

        <div className="backup-flow-card">
          <div className="backup-flow-head">
            <h3>{t("backup.importTitle")}</h3>
            <p className="hint">{t("backup.importFlowHint")}</p>
          </div>
          <button onClick={chooseImportFile}>{t("backup.chooseImportFile")}</button>
        </div>
      </div>
      {message && <div className={isError ? "error" : "hint"}>{message}</div>}
      {exportPath && (
        <div
          className="modal-backdrop"
          onClick={exportStatus === "password" ? () => setExportPath(null) : undefined}
        >
          <section className="modal backup-export-dialog" onClick={(event) => event.stopPropagation()}>
            {exportStatus === "password" && (
              <>
                <h1>{t("backup.exportPasswordTitle")}</h1>
                <p className="hint">
                  {t("backup.exportPasswordHint", { kind: backupKindLabel(exportKind || "full") })}
                </p>
                <label>
                  {t("backup.backupPassword")}
                  <input
                    type="password"
                    value={exportPassword}
                    onChange={(event) => setExportPassword(event.target.value)}
                    autoComplete="new-password"
                    autoFocus
                  />
                </label>
                <div className="modal-actions">
                  <button
                    type="button"
                    onClick={() => {
                      setExportPath(null);
                      setExportKind(null);
                      setExportPassword("");
                    }}
                  >
                    {t("common.cancel")}
                  </button>
                  <button onClick={exportBackup} disabled={!exportPassword}>
                    {t("backup.export")}
                  </button>
                </div>
              </>
            )}
            {exportStatus === "exporting" && (
              <>
                <h1>{t("backup.exportingTitle")}</h1>
                <div className="backup-export-progress" role="status" aria-live="polite">
                  <Loader2 size={20} className="spin" />
                  <span>{exportStageLabel(exportProgress)}</span>
                </div>
                {(() => {
                  const determinate =
                    exportProgress != null && exportProgress.total > 0 && exportProgress.done > 0;
                  return (
                    <>
                      <div className="backup-progress-track" aria-hidden="true">
                        <div
                          className={
                            determinate ? "backup-progress-fill" : "backup-progress-fill indeterminate"
                          }
                          style={
                            determinate && exportProgress
                              ? {
                                  width: `${Math.min(100, Math.round((exportProgress.done / exportProgress.total) * 100))}%`,
                                }
                              : undefined
                          }
                        />
                      </div>
                      {determinate && exportProgress && (
                        <p className="hint backup-progress-bytes">
                          {t("backup.exportProgressBytes", {
                            done: formatFileSize(exportProgress.done),
                            total: formatFileSize(exportProgress.total),
                          })}
                        </p>
                      )}
                    </>
                  );
                })()}
              </>
            )}
            {exportStatus === "done" && (
              <>
                <h1>{t("backup.exportDoneTitle")}</h1>
                <p className="hint">
                  {exportedSize != null
                    ? t("backup.exportDoneDetail", {
                        name: displayFileName(exportPath),
                        size: formatFileSize(exportedSize),
                      })
                    : t("backup.exportDoneHint")}
                </p>
                <div className="modal-actions">
                  <button
                    onClick={() => {
                      setExportPath(null);
                      setExportKind(null);
                      setExportPassword("");
                      setExportStatus("password");
                      setExportedSize(null);
                    }}
                  >
                    {t("common.ok")}
                  </button>
                </div>
              </>
            )}
          </section>
        </div>
      )}
      {importPreparing && (
        <div className="modal-backdrop">
          <section className="modal backup-export-dialog">
            <h1>{t("backup.importPreparingTitle")}</h1>
            <div className="backup-export-progress" role="status" aria-live="polite">
              <Loader2 size={20} className="spin" />
              <span>
                {importPreparing === "read"
                  ? t("backup.importStageRead")
                  : t("backup.importStageInspect")}
              </span>
            </div>
            <div className="backup-progress-track" aria-hidden="true">
              <div className="backup-progress-fill indeterminate" />
            </div>
          </section>
        </div>
      )}
      {importPath && importMetadata && (
        <div
          className="modal-backdrop"
          onClick={importStatus === "password" ? closeImportDialog : undefined}
        >
          <section className="modal backup-export-dialog" onClick={(event) => event.stopPropagation()}>
            {importStatus === "password" && (
              <>
                <h1>{t("backup.importPasswordTitle")}</h1>
                <p className="hint">
                  {t("backup.importSelected", {
                    kind: backupKindLabel(importMetadata.backup_kind),
                    name: backupProfileLabel(importMetadata),
                  })}
                </p>
                <div
                  className="preview-mode-picker"
                  role="radiogroup"
                  aria-label={t("backup.importModeTitle")}
                >
                  {(["restore", "link"] as const).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      role="radio"
                      aria-checked={importMode === mode}
                      className={`preview-mode-option${importMode === mode ? " selected" : ""}`}
                      onClick={() => setImportMode(mode)}
                    >
                      <span className="preview-mode-label">
                        {t(mode === "link" ? "backup.importModeLink" : "backup.importModeRestore")}
                      </span>
                      <span className="preview-mode-desc">
                        {t(
                          mode === "link"
                            ? "backup.importModeLinkHint"
                            : "backup.importModeRestoreHint",
                        )}
                      </span>
                    </button>
                  ))}
                </div>
                <label>
                  {t("backup.backupPassword")}
                  <input
                    type="password"
                    value={importPassword}
                    onChange={(event) => setImportPassword(event.target.value)}
                    autoComplete="new-password"
                    autoFocus
                  />
                </label>
                <div className="modal-actions">
                  <button type="button" onClick={closeImportDialog}>
                    {t("common.cancel")}
                  </button>
                  <button onClick={importBackup} disabled={!importPassword}>
                    {t("backup.import")}
                  </button>
                </div>
              </>
            )}
            {importStatus === "importing" && (
              <>
                <h1>{t("backup.importingTitle")}</h1>
                <div className="backup-export-progress" role="status" aria-live="polite">
                  <Loader2 size={20} className="spin" />
                  <span>{t("backup.importingHint")}</span>
                </div>
              </>
            )}
            {importStatus === "restarting" && (
              <>
                <h1>{t("backup.importingTitle")}</h1>
                <div className="backup-export-progress" role="status" aria-live="polite">
                  <Loader2 size={20} className="spin" />
                  <span>{t("backup.importRestarting")}</span>
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </section>
  );
}
