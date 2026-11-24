import { api } from "./tauriApi";
import type { ChatMessage } from "./types";

// Must match the backend `MAX_ATTACHMENT_BYTES` policy cap (protocol.rs).
export const MAX_ATTACHMENT_BYTES = 1024 * 1024 * 1024;

// Files at or below this size take the single-shot path (one base64 blob is
// cheap and keeps the common case simple). Larger files stream in slices so
// the WebView never holds the whole file plus its base64 at once — the memory
// wall that made large attachments fail to send.
const INLINE_SEND_MAX_BYTES = 8 * 1024 * 1024;
// Slice size for the streamed path. 4 MiB keeps peak JS memory bounded (one
// slice + its ~5.3 MiB base64) regardless of total file size.
const UPLOAD_SLICE_BYTES = 4 * 1024 * 1024;

export type UploadProgress = (sentBytes: number, totalBytes: number) => void;

// Base64 via FileReader.readAsDataURL: the browser encodes natively off the
// JS thread, unlike a hand-rolled String.fromCharCode loop that froze the UI
// for seconds on multi-MB files.
function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.onerror = () => reject(reader.error ?? new Error("file read failed"));
    reader.readAsDataURL(blob);
  });
}

function yieldToPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => resolve());
  });
}

export async function sendAttachmentFile(
  chatId: string,
  file: File,
  caption: string,
  quotedMessageId: string | null,
  onProgress?: UploadProgress,
): Promise<ChatMessage> {
  const mimeType = file.type || "application/octet-stream";
  onProgress?.(0, file.size);
  if (file.size <= INLINE_SEND_MAX_BYTES) {
    const b64 = await blobToBase64(file);
    const saved = await api.sendAttachmentMessage(
      chatId,
      file.name,
      mimeType,
      b64,
      caption,
      quotedMessageId,
    );
    onProgress?.(file.size, file.size);
    return saved;
  }

  const uploadId = await api.beginAttachmentUpload();
  try {
    let offset = 0;
    while (offset < file.size) {
      const end = Math.min(offset + UPLOAD_SLICE_BYTES, file.size);
      const b64 = await blobToBase64(file.slice(offset, end));
      await api.appendAttachmentUpload(uploadId, b64);
      offset = end;
      onProgress?.(offset, file.size);
      // Give the renderer a frame between slices so the progress row paints.
      await yieldToPaint();
    }
    return await api.finalizeAttachmentUpload(
      uploadId,
      chatId,
      file.name,
      mimeType,
      caption,
      quotedMessageId,
    );
  } catch (err) {
    void api.abortAttachmentUpload(uploadId).catch(() => {});
    throw err;
  }
}
