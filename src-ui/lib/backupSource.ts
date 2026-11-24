import { api } from "./tauriApi";
import {
  bytesToBase64,
  hasReadPathToTempFileBridge,
  readBytesFromPath,
  readPathToTempFile,
} from "./backupIO";
import type { BackupImportMode, BackupMetadata } from "./types";

// One opened backup pick, in the cheapest representation the platform allows.
// Android streams the SAF content:// pick into a backend temp file via the
// native bridge and uses the path-based commands — carrying the container
// through WebView base64 blew the Java heap on multi-hundred-MB profiles.
// Desktop uses the picked filesystem path directly. iOS (`preferBytes`, no
// bridge, security-scoped URL that only plugin-fs can open) keeps the
// in-memory bytes flow.
export type BackupSource =
  | { kind: "path"; path: string; temp: boolean }
  | { kind: "bytes"; b64: string };

export async function openBackupSource(
  chosenPath: string,
  preferBytes = false,
): Promise<BackupSource> {
  if (hasReadPathToTempFileBridge()) {
    const tempPath = await api.createBackupImportTempFile();
    // The bridge copy below is a synchronous WebView call that blocks the JS
    // thread for the whole stream; give the renderer one beat to paint the
    // caller's "reading file" UI first (CSS animations keep running on the
    // compositor while the thread is blocked).
    await new Promise((resolve) => setTimeout(resolve, 66));
    try {
      await readPathToTempFile(chosenPath, tempPath);
      return { kind: "path", path: tempPath, temp: true };
    } catch (err) {
      void api.deleteBackupTempFile(tempPath).catch(() => {});
      throw err;
    }
  }
  if (preferBytes || chosenPath.startsWith("content://") || chosenPath.startsWith("file://")) {
    const bytes = await readBytesFromPath(chosenPath);
    return { kind: "bytes", b64: bytesToBase64(bytes) };
  }
  return { kind: "path", path: chosenPath, temp: false };
}

export async function inspectBackupSource(source: BackupSource): Promise<BackupMetadata> {
  return source.kind === "path"
    ? api.inspectBackup(source.path)
    : api.inspectBackupBytes(source.b64);
}

export async function importBackupSource(
  source: BackupSource,
  backupPassword: string,
  mode: BackupImportMode,
): Promise<void> {
  if (source.kind === "path") {
    await api.importBackup(source.path, backupPassword, true, mode);
  } else {
    await api.importBackupBytes(source.b64, backupPassword, true, mode);
  }
}

export function releaseBackupSource(source: BackupSource | null): void {
  if (source?.kind === "path" && source.temp) {
    void api.deleteBackupTempFile(source.path).catch(() => {});
  }
}
