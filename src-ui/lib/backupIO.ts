import { readFile, writeFile } from "@tauri-apps/plugin-fs";

// Base64 encode/decode that stays safe for multi-MB payloads. The browser
// `btoa` only accepts binary strings, and a naive
// `String.fromCharCode(...bytes)` blows the call stack; 32 KiB chunks keep
// the call safe while staying fast enough for the largest backup we ship.
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(
      null,
      Array.from(bytes.subarray(i, i + chunkSize)),
    );
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Filename helpers shared by every backup-export surface (Backup page,
// pre-delete profile backup).
export function safeFileStem(value: string) {
  const normalized = value
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return normalized || "veyra-profile";
}

export function timestampForFilename(date = new Date()) {
  const pad = (value: number) => value.toString().padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

// Android-specific bridge exposed by MainActivity.kt via
// `WebView.addJavascriptInterface`. Calling `readFile` / `writeFile` from
// plugin-fs against a SAF `content://` URI fails with
//   "SecurityException ... requires android.permission.MANAGE_DOCUMENTS or
//    grant UriPermissions()"
// because plugin-fs reaches DocumentsProvider from a context that has lost
// the transient URI permission grant returned by the dialog's
// ACTION_OPEN_DOCUMENT / ACTION_CREATE_DOCUMENT intent. The bridge runs
// inside our Activity, where that grant is still active, so we route the
// backup-restore flow through it on Android. Desktop keeps using plugin-fs.
type VeyraNativeBridge = {
  setStatusBarLight?: (light: boolean) => void;
  pickBackupExportUri?: (defaultName: string) => string;
  pickBackupImportUri?: () => string;
  readContentUri?: (uri: string) => string;
  readContentUriToFile?: (uri: string, destPath: string) => string;
  writeContentUri?: (uri: string, b64: string) => string;
  writeContentUriFromFile?: (uri: string, sourcePath: string) => string;
};

function getNativeBridge(): VeyraNativeBridge | null {
  const bridge = (window as unknown as { VeyraNative?: VeyraNativeBridge }).VeyraNative;
  return bridge ?? null;
}

type NativeResult =
  | { ok: true; b64?: string; uri?: string; cancelled?: boolean }
  | { ok: false; error: string };

function parseNativeResult(raw: string): NativeResult {
  try {
    return JSON.parse(raw) as NativeResult;
  } catch {
    return { ok: false, error: `VeyraNative returned non-JSON payload: ${raw.slice(0, 200)}` };
  }
}

export async function readBytesFromPath(path: string): Promise<Uint8Array> {
  const bridge = getNativeBridge();
  if (bridge?.readContentUri) {
    const result = parseNativeResult(bridge.readContentUri(path));
    if (!result.ok) throw new Error(`VeyraNative.readContentUri: ${result.error}`);
    if (!result.b64) throw new Error("VeyraNative.readContentUri returned empty payload");
    return base64ToBytes(result.b64);
  }
  return await readFile(path);
}

export async function writeBytesToPath(path: string, bytes: Uint8Array): Promise<void> {
  const bridge = getNativeBridge();
  if (bridge?.writeContentUri) {
    const b64 = bytesToBase64(bytes);
    const result = parseNativeResult(bridge.writeContentUri(path, b64));
    if (!result.ok) throw new Error(`VeyraNative.writeContentUri: ${result.error}`);
    return;
  }
  await writeFile(path, bytes);
}

export function hasReadPathToTempFileBridge(): boolean {
  return typeof getNativeBridge()?.readContentUriToFile === "function";
}

export function hasNativeBackupPickers(): boolean {
  const bridge = getNativeBridge();
  return (
    typeof bridge?.pickBackupExportUri === "function" &&
    typeof bridge.pickBackupImportUri === "function"
  );
}

export async function pickBackupExportPath(defaultName: string): Promise<string | null> {
  const bridge = getNativeBridge();
  if (!bridge?.pickBackupExportUri) {
    return null;
  }
  const result = parseNativeResult(bridge.pickBackupExportUri(defaultName));
  if (!result.ok) throw new Error(`VeyraNative.pickBackupExportUri: ${result.error}`);
  if (result.cancelled) return null;
  if (!result.uri) throw new Error("VeyraNative.pickBackupExportUri returned empty URI");
  return result.uri;
}

export async function pickBackupImportPath(): Promise<string | null> {
  const bridge = getNativeBridge();
  if (!bridge?.pickBackupImportUri) {
    return null;
  }
  const result = parseNativeResult(bridge.pickBackupImportUri());
  if (!result.ok) throw new Error(`VeyraNative.pickBackupImportUri: ${result.error}`);
  if (result.cancelled) return null;
  if (!result.uri) throw new Error("VeyraNative.pickBackupImportUri returned empty URI");
  return result.uri;
}

// Streams a SAF content:// source into a backend-minted temp file without
// materializing it as a giant Java/JS base64 string — `readBytesFromPath` on a
// ~200 MB backup exhausted the Android Java heap ("Failed to allocate").
// Returns false when the bridge is unavailable (desktop/iOS) so the caller can
// fall back to a platform-appropriate flow.
export async function readPathToTempFile(path: string, destPath: string): Promise<boolean> {
  const bridge = getNativeBridge();
  if (!bridge?.readContentUriToFile) {
    return false;
  }
  const result = parseNativeResult(bridge.readContentUriToFile(path, destPath));
  if (!result.ok) throw new Error(`VeyraNative.readContentUriToFile: ${result.error}`);
  return true;
}

export async function writeTempFileToPath(path: string, sourcePath: string): Promise<boolean> {
  const bridge = getNativeBridge();
  if (!bridge?.writeContentUriFromFile) {
    return false;
  }
  const result = parseNativeResult(bridge.writeContentUriFromFile(path, sourcePath));
  if (!result.ok) throw new Error(`VeyraNative.writeContentUriFromFile: ${result.error}`);
  return true;
}
