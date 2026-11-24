import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Download, FileText, Loader2, MoreVertical, Pause, Phone, Play, ShieldCheck, Video, X } from "lucide-react";
import type {
  CallLogEntry,
  CallStateChangedPayload,
  Chat,
  ChatMessage,
  ChatMessageState,
  ChatTransportStatus,
  Contact,
  CurrentCallSnapshot,
  DeliveryDiagnostic,
  MessageAttachment,
  MyProfile,
} from "../lib/types";
import { useNarrowLayout } from "../lib/useNarrowLayout";
import { ensureMicrophoneAccess } from "../lib/useMicrophoneAvailability";
import { openAppSettings, setChatKeepScreenOn, shareBase64File } from "../lib/nativeBridge";
import { callMediaController } from "../lib/callMedia";
import { base64ToBytes, writeTempFileToPath } from "../lib/backupIO";
import { sendAttachmentFile, MAX_ATTACHMENT_BYTES } from "../lib/attachmentUpload";
import { copyTextToClipboard } from "../lib/clipboard";
import { api } from "../lib/tauriApi";
import {
  veyraMediaUrl,
  veyraVideoPosterUrl,
  veyraVideoUrl,
  attachmentMediaTag,
  mediaUrlShape,
  getCachedPoster,
  setCachedPoster,
  averageLuma,
  PosterJobQueue,
  POSTER_BLACK_LUMA,
  POSTER_VERIFIED_PREFIX,
} from "../lib/attachmentMedia";
import { markActiveChatRead, markInboxEventReadIfVisible } from "../lib/chatReadState";
import {
  compareMessagesByDisplayOrder,
  hasNewInboundMessage,
  latestArrivalTimestamp,
  messageDisplayTimestamp,
} from "../lib/messageOrdering";
import { useUiPrefs } from "../lib/UiPrefsProvider";
import {
  chatHeaderSubtitle,
  formatDayDivider,
  timeShort,
} from "../lib/format";
import { ChatHeaderMenu } from "./ChatHeaderMenu";
import { ChatStatisticsDialog } from "./ChatStatisticsDialog";
import { ContactProfileDialog } from "./ContactProfileDialog";
import { MessageContextMenu, type MessageMenuAction } from "./MessageContextMenu";
import { MessageInput, type ComposerQuotePreview } from "./MessageInput";
import { MessageStatus } from "./MessageStatus";
import { UserAvatar } from "./UserAvatar";

const MESSAGE_LONG_PRESS_DELAY_MS = 550;
const MESSAGE_LONG_PRESS_MOVE_TOLERANCE = 8;
const MESSAGE_PAGE_LIMIT = 40;
const QUOTE_EXCERPT_MAX_CHARS = 280;
const CHAT_KEEP_SCREEN_ON_WINDOW_MS = 10 * 60 * 1000;
const CHAT_KEEP_SCREEN_ON_BRIDGE_REFRESH_MS = 30 * 1000;

function clampExcerpt(text: string): string {
  const trimmed = text.trim();
  if (Array.from(trimmed).length <= QUOTE_EXCERPT_MAX_CHARS) return trimmed;
  return `${Array.from(trimmed).slice(0, QUOTE_EXCERPT_MAX_CHARS).join("")}…`;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}


function diagnosticSnapshot(diagnostic?: DeliveryDiagnostic | null): string {
  if (!diagnostic) return "";
  return [
    diagnostic.state,
    diagnostic.retry_count,
    diagnostic.next_retry_at ?? "",
    diagnostic.pending_recipient_count,
  ].join(":");
}

function stateSnapshot(states: ChatMessageState[]): string {
  return states
    .map((state) =>
      [
        state.message_id,
        state.status,
        state.created_at,
        diagnosticSnapshot(state.delivery_diagnostic),
      ].join("\0"),
    )
    .join("\n");
}

function mergeMessages(prev: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  const byId = new Map(prev.map((message) => [message.message_id, message]));
  for (const message of incoming) {
    byId.set(message.message_id, message);
  }
  return [...byId.values()].sort(compareMessagesByDisplayOrder);
}

function replaceMessage(
  current: ChatMessage[],
  oldMessageId: string,
  nextMessage: ChatMessage,
): ChatMessage[] {
  let replaced = false;
  const next = current.map((message) => {
    if (message.message_id !== oldMessageId) return message;
    replaced = true;
    return nextMessage;
  });
  return mergeMessages(replaced ? next : current, [nextMessage]);
}

// Attachment uploads in flight, keyed by chat + file identity. The backend
// commits the message row before the (long) chunk-encryption finishes, so a
// periodic refresh would fetch the real row while the optimistic "preparing"
// bubble is still on screen — two bubbles for one file. While a signature is
// in flight, fetched copies of that message are dropped; the optimistic row
// is replaced by the saved one when the upload command returns.
const inFlightAttachmentUploads = new Set<string>();

function attachmentUploadSignature(chatId: string, fileName: string, sizeBytes: number): string {
  return `${chatId}\0${fileName}\0${sizeBytes}`;
}

function mergeFetchedMessages(
  current: ChatMessage[],
  incoming: ChatMessage[],
  chatId: string,
): ChatMessage[] {
  const filtered = inFlightAttachmentUploads.size
    ? incoming.filter(
        (message) =>
          !(
            message.direction === "outbound" &&
            message.attachment &&
            inFlightAttachmentUploads.has(
              attachmentUploadSignature(
                chatId,
                message.attachment.file_name,
                message.attachment.size_bytes,
              ),
            )
          ),
      )
    : incoming;
  return mergeMessages(
    current.filter((message) => message.chat_id === chatId),
    filtered,
  );
}

function stateSnapshotFromMessages(messages: ChatMessage[]): string {
  return stateSnapshot(
    messages.map((message) => ({
      message_id: message.message_id,
      status: message.status,
      created_at: message.created_at,
      direction: message.direction,
      delivery_diagnostic: message.delivery_diagnostic,
    })),
  );
}

function applyStatuses(messages: ChatMessage[], states: ChatMessageState[]): ChatMessage[] {
  const stateById = new Map(states.map((state) => [state.message_id, state]));
  return messages.map((message) => {
    const nextState = stateById.get(message.message_id);
    if (!nextState) return message;
    const nextDiagnostic = nextState.delivery_diagnostic ?? null;
    const diagnosticChanged =
      diagnosticSnapshot(message.delivery_diagnostic) !== diagnosticSnapshot(nextDiagnostic);
    if (nextState.status === message.status && !diagnosticChanged) return message;
    return {
      ...message,
      status: nextState.status,
      delivery_diagnostic: nextDiagnostic,
    };
  });
}

type TransportLoadState = "loading" | "ready" | "error";

/// Phases the backend reports while a history restore runs.
type RestorePhase = "own_devices" | "asking" | "awaiting_consent" | "receiving";

type RestoreProgressDetail = {
  /** own_devices: which sibling device is being dialed, and how many there are. */
  current?: number;
  total?: number;
  /** awaiting_consent: how long the contact still has to answer. */
  seconds_left?: number;
  /** receiving: messages restored so far. */
  applied?: number;
};

type RestoreProgressPayload = RestoreProgressDetail & {
  chat_id: string;
  phase: RestorePhase;
};

type RestoreProgress = RestoreProgressDetail & {
  chatId: string;
  phase: RestorePhase;
};

type OutboxChangedPayload = {
  chatId: string;
  messageId: string;
  status: string;
  deliveryDiagnostic?: DeliveryDiagnostic | null;
};

type AttachmentTransferChangedPayload = {
  chatId: string;
  messageId: string;
  attachmentId: string;
  status: string;
  bytesTransferred: number;
  totalBytes: number;
};

type ChatTimelineItem =
  | {
      kind: "message";
      id: string;
      at: string;
      message: ChatMessage;
    }
  | {
      kind: "callEnded";
      id: string;
      at: string;
      call: CallLogEntry;
    };

type Props = {
  profile: MyProfile;
  chat: Chat | null;
  contacts: Contact[];
  currentCall?: CurrentCallSnapshot | null;
  onRefresh: () => Promise<void>;
  onChatRead?: (chatId: string) => void;
  markReadActive?: boolean;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
  /// Calls are unavailable while a proxy carries the traffic — WebRTC would
  /// gather candidates outside the tunnel and hand the peer our real address.
  proxyEnabled?: boolean;
};

type CallBlockedReason =
  | "not_direct"
  | "unverified"
  | "transport_loading"
  | "peer_offline"
  | "already_in_call"
  | "proxy_active";

function callErrorCode(err: unknown): string | null {
  if (!err || typeof err !== "object" || !("code" in err)) return null;
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

function mergeCallLog(prev: CallLogEntry[], incoming: CallLogEntry[]): CallLogEntry[] {
  const byId = new Map(prev.map((entry) => [entry.call_id, entry]));
  incoming.forEach((entry) => byId.set(entry.call_id, entry));
  return Array.from(byId.values()).sort((a, b) => Date.parse(b.ended_at) - Date.parse(a.ended_at));
}

function shouldShowCallEndedEvent(entry: CallLogEntry): boolean {
  return entry.end_reason !== "peer_offline" && entry.end_reason !== "unverified";
}

function afterFirstPaint(callback: () => void, delayMs = 0): number {
  return window.setTimeout(() => {
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(callback);
    });
  }, delayMs);
}

function formatAttachmentSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function safeFileName(name: string): string {
  return name.replace(/[\\/:*?"<>|]/g, "_").trim() || "attachment";
}

type VideoPosterResult = {
  poster: string | null;
  /// True only when the poster is trustworthy for good: a lit frame was
  /// found, or the multi-frame probe ran to completion and every frame is
  /// honestly black. Timeout / unknown-duration / error truncations return
  /// false so the caller does not mark the poster as verified.
  verified: boolean;
};

const videoPosterQueue = new PosterJobQueue<VideoPosterResult>(2, (stats) => {
  console.debug("veyra-media poster queue", stats);
});

class PosterMediaError extends Error {
  constructor(readonly code: number) {
    super(`media element failed with code ${code}`);
    this.name = "MediaError";
  }
}

function posterAbortError(): Error {
  const error = new Error("poster generation cancelled");
  error.name = "AbortError";
  return error;
}

function waitForVideoEvent(
  video: HTMLVideoElement,
  eventName: "loadedmetadata" | "loadeddata" | "seeked",
  signal: AbortSignal,
): Promise<void> {
  if (eventName === "loadedmetadata" && video.readyState >= HTMLMediaElement.HAVE_METADATA) {
    return Promise.resolve();
  }
  if (eventName === "loadeddata" && video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
    return Promise.resolve();
  }
  if (eventName === "seeked" && !video.seeking) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      video.removeEventListener(eventName, onReady);
      video.removeEventListener("error", onError);
      signal.removeEventListener("abort", onAbort);
    };
    const onReady = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(new PosterMediaError(video.error?.code ?? 0));
    };
    const onAbort = () => {
      cleanup();
      reject(posterAbortError());
    };
    video.addEventListener(eventName, onReady, { once: true });
    video.addEventListener("error", onError, { once: true });
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function waitForDecodedVideoFrame(video: HTMLVideoElement, signal: AbortSignal): Promise<void> {
  type FrameVideo = HTMLVideoElement & {
    requestVideoFrameCallback?: (callback: () => void) => number;
    cancelVideoFrameCallback?: (handle: number) => void;
  };
  const frameVideo = video as FrameVideo;
  if (!frameVideo.requestVideoFrameCallback) {
    return new Promise((resolve, reject) => {
      const handle = window.requestAnimationFrame(() => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      });
      const onAbort = () => {
        window.cancelAnimationFrame(handle);
        reject(posterAbortError());
      };
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }
  return new Promise((resolve, reject) => {
    const handle = frameVideo.requestVideoFrameCallback!(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    });
    const onAbort = () => {
      frameVideo.cancelVideoFrameCallback?.(handle);
      reject(posterAbortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function createVideoPoster(
  url: string,
  signal: AbortSignal,
  attachmentId: string,
): Promise<VideoPosterResult> {
  const video = document.createElement("video");
  const canvas = document.createElement("canvas");
  const tag = attachmentMediaTag(attachmentId);
  const work = new AbortController();
  let timedOut = false;
  let stage = "created";
  let lastCapture: string | null = null;
  const onCancel = () => work.abort();
  signal.addEventListener("abort", onCancel, { once: true });
  const timer = window.setTimeout(() => {
    timedOut = true;
    work.abort();
  }, 12_000);

  const logStage = (nextStage: string, extra: Record<string, unknown> = {}) => {
    stage = nextStage;
    console.debug("veyra-media poster", { attachment: tag, stage, ...extra });
  };
  const capture = (): { poster: string; black: boolean } | null => {
    const width = video.videoWidth;
    const height = video.videoHeight;
    if (!width || !height) {
      console.warn("veyra-media poster", { attachment: tag, stage: "zero-dimensions" });
      return null;
    }
    const maxWidth = 640;
    const scale = Math.min(1, maxWidth / width);
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    const context = canvas.getContext("2d");
    if (!context) return null;
    try {
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const luma = averageLuma(
        context.getImageData(0, 0, canvas.width, canvas.height).data,
      );
      return {
        poster: canvas.toDataURL("image/jpeg", 0.82),
        black: luma < POSTER_BLACK_LUMA,
      };
    } catch (error) {
      console.warn("veyra-media poster", {
        attachment: tag,
        stage: "canvas-exception",
        error: error instanceof Error ? error.name : "unknown",
      });
      return null;
    }
  };

  video.muted = true;
  video.playsInline = true;
  video.preload = "auto";
  logStage("load-start", { url: mediaUrlShape(url) });
  try {
    video.src = url;
    video.load();
    await waitForVideoEvent(video, "loadedmetadata", work.signal);
    logStage("loadedmetadata", { duration: Number.isFinite(video.duration) ? video.duration : null });
    await waitForVideoEvent(video, "loadeddata", work.signal);
    logStage("loadeddata");
    await waitForDecodedVideoFrame(video, work.signal);
    logStage("decoded-frame", { currentTime: video.currentTime });

    const first = capture();
    if (first && !first.black) return { poster: first.poster, verified: true };
    lastCapture = first?.poster ?? null;
    const duration = Number.isFinite(video.duration) ? video.duration : 0;
    if (duration <= 0) return { poster: lastCapture, verified: false };
    const clamp = (time: number) =>
      Math.min(Math.max(time, 0.1), Math.max(duration - 0.1, 0.1));
    const candidates = [
      ...new Set([
        clamp(Math.min(1, duration * 0.1)),
        clamp(duration * 0.25),
        clamp(duration * 0.5),
      ]),
    ];
    for (const currentTime of candidates) {
      stage = "seeking";
      video.currentTime = currentTime;
      await waitForVideoEvent(video, "seeked", work.signal);
      logStage("seeked", { currentTime });
      await waitForDecodedVideoFrame(video, work.signal);
      logStage("decoded-frame", { currentTime });
      const shot = capture();
      if (shot && !shot.black) return { poster: shot.poster, verified: true };
      if (shot) lastCapture = shot.poster;
    }
    return { poster: lastCapture, verified: true };
  } catch (error) {
    if (signal.aborted) throw posterAbortError();
    if (timedOut) {
      console.warn("veyra-media poster", { attachment: tag, stage: "timeout", waitingFor: stage });
    } else if (error instanceof PosterMediaError) {
      console.warn("veyra-media poster", {
        attachment: tag,
        stage: "media-error",
        waitingFor: stage,
        code: error.code,
      });
    }
    return { poster: lastCapture, verified: false };
  } finally {
    window.clearTimeout(timer);
    signal.removeEventListener("abort", onCancel);
    video.pause();
    video.removeAttribute("src");
    video.load();
    logStage("released");
  }
}

/// True when a stored poster data URI decodes to an effectively black image
/// (or does not decode at all) — those were captured from black first frames
/// by pre-0.9.608 builds and should be regenerated instead of trusted.
function posterLooksBlack(dataUri: string): Promise<boolean> {
  return new Promise((resolve) => {
    const image = new Image();
    image.onload = () => {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.min(64, image.naturalWidth));
        canvas.height = Math.max(1, Math.min(64, image.naturalHeight));
        const context = canvas.getContext("2d");
        if (!context) {
          resolve(false);
          return;
        }
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        const luma = averageLuma(
          context.getImageData(0, 0, canvas.width, canvas.height).data,
        );
        resolve(luma < POSTER_BLACK_LUMA);
      } catch {
        resolve(false);
      }
    };
    image.onerror = () => resolve(true);
    image.src = dataUri;
  });
}

// Slice C transfer controls: pause/resume own side, sender cancel, second
// device chunk request, "send again" after a terminal decline/cancel.
export type AttachmentTransferAction = "pause" | "resume" | "cancel" | "request" | "resend";

type AttachmentViewProps = {
  message: ChatMessage;
  attachment: MessageAttachment;
  canOpenMenu: boolean;
  onOpenMenu: (message: ChatMessage, x: number, y: number) => void;
  onOpenMedia: (attachment: MessageAttachment, url: string, posterUrl?: string | null) => void;
  shouldSuppressClick: () => boolean;
  onDecision?: (action: "accept" | "decline") => Promise<void>;
  onTransfer?: (action: AttachmentTransferAction) => Promise<void>;
};

function MessageAttachmentView({
  message,
  attachment,
  canOpenMenu,
  onOpenMenu,
  onOpenMedia,
  shouldSuppressClick,
  onDecision,
  onTransfer,
}: AttachmentViewProps) {
  const { t } = useTranslation();
  const [mediaUrl, setMediaUrl] = useState<string | null>(null);
  const [videoPosterUrl, setVideoPosterUrl] = useState<string | null>(null);
  const [inView, setInView] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const available = attachment.status === "available";
  const isMedia =
    attachment.media_kind === "image" ||
    attachment.media_kind === "video" ||
    attachment.media_kind === "audio";
  const progress = attachment.total_bytes > 0
    ? Math.min(100, Math.round((attachment.bytes_transferred / attachment.total_bytes) * 100))
    : 0;

  // Viewport-lazy: only attachments near the viewport instantiate media
  // elements, so opening a chat with 40 messages does not spin up dozens of
  // decoders at once. `rootMargin` pre-warms the next screenful.
  useEffect(() => {
    if (!available || !isMedia) return;
    const node = containerRef.current;
    if (!node) return;
    if (typeof IntersectionObserver === "undefined") {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setInView(true);
            observer.disconnect();
            break;
          }
        }
      },
      { root: null, rootMargin: "600px 0px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [available, isMedia, attachment.id]);

  // Media streams from the encrypted store via the veyra-media protocol —
  // zero base64, zero IPC payload, video seeking works, any size. The old
  // PREVIEW_MAX_BYTES cap is gone. Videos additionally get a persistent
  // poster: load the stored one, else generate once (cheap now, since the
  // <video> streams only its first frames) and persist for next time.
  useEffect(() => {
    if (!available || !isMedia || !inView) {
      setMediaUrl(null);
      setVideoPosterUrl(null);
      return;
    }
    const url =
      attachment.media_kind === "video"
        ? veyraVideoUrl(attachment.id)
        : veyraMediaUrl(attachment.id);
    setMediaUrl(url);
    if (attachment.media_kind !== "video") return;

    let cancelled = false;
    const cached = getCachedPoster(attachment.id);
    if (cached) {
      setVideoPosterUrl(cached);
      return;
    }
    const posterController = new AbortController();
    const posterTag = attachmentMediaTag(attachment.id);
    void api
      .getAttachmentPoster(attachment.id)
      .then(async (stored) => {
        if (cancelled) return;
        let legacyBase64: string | null = null;
        if (stored) {
          if (stored.startsWith(POSTER_VERIFIED_PREFIX)) {
            // Already went through the multi-frame probe once — trust it,
            // even when black (the video really is dark at every probe).
            const dataUri = `data:image/jpeg;base64,${stored.slice(POSTER_VERIFIED_PREFIX.length)}`;
            setCachedPoster(attachment.id, dataUri);
            setVideoPosterUrl(dataUri);
            return;
          }
          // Legacy pre-0.9.608 poster: captured from frame 0, possibly a
          // black square. Self-heal exactly once.
          const dataUri = `data:image/jpeg;base64,${stored}`;
          const black = await posterLooksBlack(dataUri);
          if (cancelled) return;
          if (!black) {
            setCachedPoster(attachment.id, dataUri);
            setVideoPosterUrl(dataUri);
            // Re-persist with the marker so the check never runs again.
            void api
              .setAttachmentPoster(attachment.id, POSTER_VERIFIED_PREFIX + stored)
              .then(() => {
                console.debug("veyra-media poster", { attachment: posterTag, stage: "persisted-marker" });
              })
              .catch(() => {
                console.warn("veyra-media poster", { attachment: posterTag, stage: "persistence-error" });
              });
            return;
          }
          legacyBase64 = stored;
        }
        return videoPosterQueue.enqueue(
          attachment.id,
          (signal) => createVideoPoster(veyraVideoPosterUrl(attachment.id), signal, attachment.id),
          posterController.signal,
        ).then(({ poster, verified }) => {
          if (cancelled) return;
          // Regeneration failed outright: keep showing the stored poster
          // (unmarked, so a later session may retry) instead of the icon.
          const fallbackUri = legacyBase64 ? `data:image/jpeg;base64,${legacyBase64}` : null;
          const finalUri = poster ?? fallbackUri;
          if (!finalUri) return;
          setCachedPoster(attachment.id, finalUri);
          setVideoPosterUrl(finalUri);
          if (!poster) return;
          const base64 = poster.split(",")[1];
          if (base64) {
            // Truncated probes (timeout, unknown duration) persist unmarked
            // so a later session retries; only verified results get the
            // marker that ends the self-heal for good.
            void api
              .setAttachmentPoster(
                attachment.id,
                (verified ? POSTER_VERIFIED_PREFIX : "") + base64,
              )
              .then(() => {
                console.debug("veyra-media poster", {
                  attachment: posterTag,
                  stage: "persisted",
                  verified,
                });
              })
              .catch(() => {
                console.warn("veyra-media poster", { attachment: posterTag, stage: "persistence-error" });
              });
          }
        });
      })
      .catch((error) => {
        if (error instanceof Error && error.name === "AbortError") return;
        console.warn("veyra-media poster", { attachment: posterTag, stage: "pipeline-error" });
      });
    return () => {
      cancelled = true;
      posterController.abort();
    };
  }, [attachment.id, attachment.media_kind, available, isMedia, inView]);

  // File-transfer-polish slice B: the receiver's decision states come before
  // any content rendering — no bytes exist until the transfer is accepted.
  const decision = attachment.receiver_decision ?? "accepted";
  if (message.direction === "inbound" && decision === "awaiting") {
    return (
      <div className="message-attachment attachment-card attachment-card--awaiting">
        <FileText size={24} />
        <div className="attachment-card-body">
          <strong>{attachment.file_name}</strong>
          <span>
            {formatAttachmentSize(attachment.size_bytes)} · {attachment.mime_type}
          </span>
          <span>{t("attachments.awaitingDecision")}</span>
          <div className="attachment-decision-actions">
            <button
              type="button"
              className="primary"
              disabled={deciding || !onDecision}
              onClick={(event) => {
                event.stopPropagation();
                if (!onDecision) return;
                setDeciding(true);
                void onDecision("accept").finally(() => setDeciding(false));
              }}
            >
              {t("attachments.accept")}
            </button>
            <button
              type="button"
              disabled={deciding || !onDecision}
              onClick={(event) => {
                event.stopPropagation();
                if (!onDecision) return;
                setDeciding(true);
                void onDecision("decline").finally(() => setDeciding(false));
              }}
            >
              {t("attachments.decline")}
            </button>
          </div>
        </div>
      </div>
    );
  }
  if (message.direction === "inbound" && decision === "declined") {
    return (
      <div className="message-attachment attachment-card attachment-card--deleted">
        <FileText size={24} />
        <div className="attachment-card-body">
          <strong>{attachment.file_name}</strong>
          <span>
            {formatAttachmentSize(attachment.size_bytes)} · {t("attachments.declinedLocal")}
          </span>
        </div>
      </div>
    );
  }
  if (message.direction === "outbound" && decision === "declined") {
    // Neutral by design: the sender never learns whether it was a manual
    // decline or a contact policy.
    return (
      <div className="message-attachment attachment-card attachment-card--deleted">
        <FileText size={24} />
        <div className="attachment-card-body">
          <strong>{attachment.file_name}</strong>
          <span>
            {formatAttachmentSize(attachment.size_bytes)} · {t("attachments.declinedByPeer")}
          </span>
          {onTransfer && (
            <div className="attachment-decision-actions">
              <button
                type="button"
                disabled={deciding}
                onClick={(event) => {
                  event.stopPropagation();
                  setDeciding(true);
                  void onTransfer("resend").finally(() => setDeciding(false));
                }}
              >
                {t("attachments.sendAgain")}
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Slice C: a transfer the sender cancelled. The receiver's partial content
  // is gone; the sender keeps its local copy and may send it again as a
  // brand-new transfer.
  if (attachment.terminal_reason === "sender_cancelled") {
    return (
      <div className="message-attachment attachment-card attachment-card--deleted">
        <FileText size={24} />
        <div className="attachment-card-body">
          <strong>{attachment.file_name}</strong>
          <span>
            {formatAttachmentSize(attachment.size_bytes)} ·{" "}
            {t(
              message.direction === "outbound"
                ? "attachments.transferCancelledLocal"
                : "attachments.transferCancelledBySender",
            )}
          </span>
          {message.direction === "outbound" && onTransfer && (
            <div className="attachment-decision-actions">
              <button
                type="button"
                disabled={deciding}
                onClick={(event) => {
                  event.stopPropagation();
                  setDeciding(true);
                  void onTransfer("resend").finally(() => setDeciding(false));
                }}
              >
                {t("attachments.sendAgain")}
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Locally deleted file: keep the metadata as a greyed tombstone. No preview,
  // no actions — the content is gone from this device (the peer keeps theirs).
  if (attachment.status === "deleted") {
    return (
      <div className="message-attachment attachment-card attachment-card--deleted">
        <FileText size={24} />
        <div className="attachment-card-body">
          <strong>{attachment.file_name}</strong>
          <span>
            {formatAttachmentSize(attachment.size_bytes)} · {t("attachments.fileDeleted")}
          </span>
        </div>
      </div>
    );
  }

  if (available && attachment.media_kind === "image") {
    return (
      <div className="message-attachment" ref={containerRef}>
        {mediaUrl ? (
          <button
            type="button"
            className="message-attachment-media-button"
            onClick={(event) => {
              event.stopPropagation();
              if (shouldSuppressClick()) return;
              onOpenMedia(attachment, mediaUrl, null);
            }}
          >
            <img className="message-attachment-media" src={mediaUrl} alt={attachment.file_name} />
          </button>
        ) : (
          <span className="message-attachment-media-placeholder" aria-hidden="true" />
        )}
      </div>
    );
  }

  if (available && attachment.media_kind === "video") {
    return (
      <div className="message-attachment" ref={containerRef}>
        <button
          type="button"
          className="message-attachment-media-button"
          disabled={!mediaUrl}
          onClick={(event) => {
            event.stopPropagation();
            if (shouldSuppressClick() || !mediaUrl) return;
            onOpenMedia(attachment, mediaUrl, videoPosterUrl);
          }}
        >
          {videoPosterUrl ? (
            <img className="message-attachment-media" src={videoPosterUrl} alt={attachment.file_name} />
          ) : (
            <span className="message-attachment-video-fallback">
              <Video size={30} />
              <span>{attachment.file_name}</span>
              <small>{formatAttachmentSize(attachment.size_bytes)}</small>
            </span>
          )}
          <span className="message-attachment-play-badge" aria-hidden="true">
            <Play size={22} fill="currentColor" />
          </span>
        </button>
      </div>
    );
  }

  if (available && attachment.media_kind === "audio") {
    // Inline player with an explicit start — never autoplay; the stream
    // comes straight out of the encrypted store like image/video.
    return (
      <div className="message-attachment message-attachment--audio" ref={containerRef}>
        <div className="attachment-card">
          <FileText size={24} />
          <div className="attachment-card-body">
            <strong>{attachment.file_name}</strong>
            <span>{formatAttachmentSize(attachment.size_bytes)}</span>
            {mediaUrl ? (
              <audio
                controls
                preload="metadata"
                src={mediaUrl}
                onClick={(event) => event.stopPropagation()}
              />
            ) : (
              <span className="message-attachment-media-placeholder" aria-hidden="true" />
            )}
          </div>
        </div>
      </div>
    );
  }

  const preparing = message.message_id.startsWith("optimistic-");
  const finalizing = preparing && attachment.transfer_id === "finalizing";
  // Sender-side delivery to the peer: acked bytes grow while chunks stream.
  // `sent_bytes > 0` doubles as the "a transfer actually ran" gate, keeping
  // self-chat rows and pre-tracking history quiet.
  const sentBytes = attachment.sent_bytes ?? 0;
  const uploading =
    !preparing &&
    message.direction === "outbound" &&
    sentBytes > 0 &&
    sentBytes < attachment.size_bytes &&
    message.status !== "failed";
  const uploadProgress =
    attachment.size_bytes > 0
      ? Math.min(100, Math.round((sentBytes / attachment.size_bytes) * 100))
      : 0;
  // Slice C: transfer controls. Own pause is the actionable one — each side
  // clears only its own flag; the peer's pause is a status line.
  const senderPaused = !!attachment.sender_paused;
  const receiverPaused = !!attachment.receiver_paused;
  const ownPaused = message.direction === "outbound" ? senderPaused : receiverPaused;
  const peerPaused = message.direction === "outbound" ? receiverPaused : senderPaused;
  const accepted = (attachment.receiver_decision ?? "accepted") === "accepted";
  const terminal = attachment.terminal_reason != null;
  const outboundTransferActive =
    message.direction === "outbound" &&
    !preparing &&
    !terminal &&
    accepted &&
    (uploading || senderPaused || receiverPaused);
  const inboundTransferActive =
    message.direction === "inbound" && !available && accepted && !terminal;
  // Slice E: a peer known to be legacy would never see our controls — the
  // buttons would silently do nothing on its side, so they are hidden.
  const legacyPeer = attachment.peer_transfer_control === false;
  const showTransferControls =
    !!onTransfer && !legacyPeer && (outboundTransferActive || inboundTransferActive);
  const transferAction =
    (action: AttachmentTransferAction) => (event: { stopPropagation(): void }) => {
      event.stopPropagation();
      if (!onTransfer) return;
      setDeciding(true);
      void onTransfer(action).finally(() => setDeciding(false));
    };
  const card = (
    <div className="message-attachment attachment-card">
      {preparing || uploading ? <Loader2 size={24} className="spin" /> : <FileText size={24} />}
      <div className="attachment-card-body">
        <strong>{attachment.file_name}</strong>
        <span>
          {formatAttachmentSize(attachment.size_bytes)}
          {finalizing
            ? ` · ${t("attachments.finalizing")}`
            : preparing
              ? ` · ${t("attachments.preparing", { progress })}`
              : ownPaused
                ? ` · ${t("attachments.pausedByYou")}`
                : peerPaused
                  ? ` · ${t("attachments.pausedByPeer")}`
                  : uploading
                    ? ` · ${t("attachments.sending", { progress: uploadProgress })}`
                    : !available &&
                      (attachment.bytes_transferred > 0
                        ? ` · ${t("attachments.waiting", { progress })}`
                        : ` · ${t("attachments.waitingRoute")}`)}
        </span>
        {(preparing || uploading || (!available && attachment.bytes_transferred > 0)) && (
          <div className="attachment-progress" aria-label={t("attachments.progress")}>
            <span style={{ width: `${uploading ? uploadProgress : progress}%` }} />
          </div>
        )}
        {legacyPeer && (outboundTransferActive || inboundTransferActive) && (
          <span className="hint">{t("attachments.legacyPeerNoControl")}</span>
        )}
        {showTransferControls && (
          <div className="attachment-decision-actions attachment-transfer-actions">
            <button
              type="button"
              className="attachment-icon-btn"
              disabled={deciding}
              onClick={transferAction(ownPaused ? "resume" : "pause")}
              title={t(ownPaused ? "attachments.resumeTransfer" : "attachments.pauseTransfer")}
              aria-label={t(ownPaused ? "attachments.resumeTransfer" : "attachments.pauseTransfer")}
            >
              {ownPaused ? <Play size={15} /> : <Pause size={15} />}
            </button>
            {message.direction === "outbound" ? (
              <button type="button" disabled={deciding} onClick={transferAction("cancel")}>
                {t("attachments.cancelTransfer")}
              </button>
            ) : (
              // R6 tail: ask the sender to (re)stream to THIS device — how a
              // second device catches up on a journal-synced manifest.
              <button
                type="button"
                className="attachment-icon-btn"
                disabled={deciding}
                onClick={transferAction("request")}
                title={t("attachments.requestFromSender")}
                aria-label={t("attachments.requestFromSender")}
              >
                <Download size={15} />
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );

  if (!canOpenMenu) {
    return card;
  }

  return (
    <button
      type="button"
      className="attachment-card-button"
      onClick={(event) => {
        event.stopPropagation();
        if (shouldSuppressClick()) return;
        onOpenMenu(message, event.clientX, event.clientY);
      }}
    >
      {card}
    </button>
  );
}

export function ChatView({
  profile,
  chat,
  contacts,
  currentCall = null,
  onRefresh,
  onChatRead,
  markReadActive = true,
  showMobileBack,
  onMobileBack,
  proxyEnabled = false,
}: Props) {
  const { t } = useTranslation();
  const { prefs } = useUiPrefs();
  const narrow = useNarrowLayout();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [hasOlderMessages, setHasOlderMessages] = useState(false);
  const [callLog, setCallLog] = useState<CallLogEntry[]>([]);
  const [transportStatus, setTransportStatus] = useState<ChatTransportStatus | null>(null);
  const [transportLoadState, setTransportLoadState] = useState<TransportLoadState>("loading");
  const [error, setError] = useState("");
  const [callStarting, setCallStarting] = useState(false);
  const [showFingerprint, setShowFingerprint] = useState(false);
  const [showVerifyHelp, setShowVerifyHelp] = useState(false);
  const [notice, setNotice] = useState("");
  const [headerMenuRect, setHeaderMenuRect] = useState<DOMRect | null>(null);
  const [profileDialogContact, setProfileDialogContact] = useState<Contact | null>(null);
  const [statsDialogChat, setStatsDialogChat] = useState<Chat | null>(null);
  const [clearChatTarget, setClearChatTarget] = useState<Chat | null>(null);
  const [clearChatSaving, setClearChatSaving] = useState(false);
  const [messageMenu, setMessageMenu] = useState<{
    messageId: string;
    x: number;
    y: number;
  } | null>(null);
  const [quoteTarget, setQuoteTarget] = useState<{
    messageId: string;
    authorName: string;
    excerpt: string;
  } | null>(null);
  const [editTarget, setEditTarget] = useState<{
    messageId: string;
    initialText: string;
  } | null>(null);
  const [editDraft, setEditDraft] = useState("");
  const [editSaving, setEditSaving] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleteSaving, setDeleteSaving] = useState(false);
  const [deleteFileTarget, setDeleteFileTarget] = useState<string | null>(null);
  const [deleteFileSaving, setDeleteFileSaving] = useState(false);
  const [forwardTarget, setForwardTarget] = useState<ChatMessage | null>(null);
  const [forwardChats, setForwardChats] = useState<Chat[]>([]);
  const [forwardSearch, setForwardSearch] = useState("");
  const [mediaViewer, setMediaViewer] = useState<{
    attachment: MessageAttachment;
    url: string;
    posterUrl: string | null;
    playing: boolean;
  } | null>(null);
  const transportDebounceRef = useRef<number | undefined>(undefined);
  const messagesPollInFlight = useRef(false);
  const olderMessagesInFlight = useRef(false);
  const transportInFlight = useRef(false);
  const lastStateSnapshot = useRef("");
  const messagesRef = useRef<ChatMessage[]>([]);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const shouldScrollToLatestRef = useRef(false);
  const initialScrollSettledRef = useRef(false);
  const isNearBottomRef = useRef(true);
  const scrollFrameRef = useRef<number | undefined>(undefined);
  const noticeTimerRef = useRef<number | undefined>(undefined);
  const avatarSyncTimerRef = useRef<number | undefined>(undefined);
  const chatKeepScreenOnTimerRef = useRef<number | undefined>(undefined);
  const renewChatKeepScreenOnRef = useRef<(() => void) | null>(null);
  const avatarSyncContactRef = useRef<string | null>(null);
  const profileCardSyncContactRef = useRef<string | null>(null);
  const sidebarRefreshTimerRef = useRef<number | undefined>(undefined);
  const presenceContact = useMemo(
    () =>
      chat?.chat_type === "direct"
        ? contacts.find((contact) => chat.member_contact_ids.includes(contact.local_id)) ?? null
        : null,
    [chat, contacts],
  );
  useEffect(() => {
    if (!presenceContact || presenceContact.trust_status !== "verified") {
      return;
    }
    let cancelled = false;
    let refreshTimer: number | undefined;
    api
      .refreshContactPresence(presenceContact.local_id)
      .then(() => {
        if (cancelled) return;
        refreshTimer = window.setTimeout(() => {
          void onRefresh().catch(() => undefined);
        }, 1500);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      window.clearTimeout(refreshTimer);
    };
  }, [
    onRefresh,
    presenceContact?.local_id,
    presenceContact?.peer_id,
    presenceContact?.trust_status,
  ]);

  const scrollToLatestMessage = useCallback(() => {
    window.cancelAnimationFrame(scrollFrameRef.current ?? 0);
    scrollFrameRef.current = window.requestAnimationFrame(() => {
      const container = messagesContainerRef.current;
      if (container) {
        container.scrollTop = container.scrollHeight;
        initialScrollSettledRef.current = true;
        // Schedule a late correction pass in case React or the browser
        // is slow to compute the height of the new bubble in the DOM.
        const t = setTimeout(() => {
          container.scrollTop = container.scrollHeight;
          initialScrollSettledRef.current = true;
        }, 50);
      }
    });
  }, []);
  useEffect(() => {
    if (!shouldScrollToLatestRef.current) return;
    shouldScrollToLatestRef.current = false;
    scrollToLatestMessage();
  }, [messages, callLog, scrollToLatestMessage]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    if (!chat?.id || !markReadActive) {
      renewChatKeepScreenOnRef.current = null;
      window.clearTimeout(chatKeepScreenOnTimerRef.current);
      setChatKeepScreenOn(false);
      return;
    }

    let active = true;
    let bridgeEnabled = false;
    let lastBridgeRefreshAt = 0;

    const release = () => {
      window.clearTimeout(chatKeepScreenOnTimerRef.current);
      chatKeepScreenOnTimerRef.current = undefined;
      if (bridgeEnabled) {
        bridgeEnabled = false;
        setChatKeepScreenOn(false);
      }
    };

    const renew = () => {
      if (!active || document.hidden) return;
      const now = Date.now();
      if (!bridgeEnabled || now - lastBridgeRefreshAt >= CHAT_KEEP_SCREEN_ON_BRIDGE_REFRESH_MS) {
        bridgeEnabled = true;
        lastBridgeRefreshAt = now;
        setChatKeepScreenOn(true);
      }
      window.clearTimeout(chatKeepScreenOnTimerRef.current);
      chatKeepScreenOnTimerRef.current = window.setTimeout(() => {
        release();
      }, CHAT_KEEP_SCREEN_ON_WINDOW_MS);
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        release();
      } else {
        renew();
      }
    };

    const onActivity = () => renew();
    const messageContainer = messagesContainerRef.current;

    renewChatKeepScreenOnRef.current = renew;
    renew();
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pointerdown", onActivity, { passive: true });
    window.addEventListener("keydown", onActivity);
    messageContainer?.addEventListener("scroll", onActivity, { passive: true });

    return () => {
      active = false;
      renewChatKeepScreenOnRef.current = null;
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("keydown", onActivity);
      messageContainer?.removeEventListener("scroll", onActivity);
      release();
    };
  }, [chat?.id, markReadActive]);

  useEffect(() => {
    renewChatKeepScreenOnRef.current?.();
  }, [messages.length]);

  const displayTimeline = useMemo<ChatTimelineItem[]>(() => {
    const items: ChatTimelineItem[] = [
      ...messages.map((message) => ({
        kind: "message" as const,
        id: `message:${message.message_id}`,
        at: messageDisplayTimestamp(message),
        message,
      })),
      ...callLog.filter(shouldShowCallEndedEvent).map((call) => ({
        kind: "callEnded" as const,
        id: `call:${call.call_id}`,
        at: call.ended_at,
        call,
      })),
    ];
    return items.sort((a, b) => {
      const byDate = Date.parse(a.at) - Date.parse(b.at);
      return byDate || a.id.localeCompare(b.id);
    });
  }, [messages, callLog]);

  useEffect(() => {
    return () => {
      window.clearTimeout(noticeTimerRef.current);
      window.clearTimeout(avatarSyncTimerRef.current);
      window.clearTimeout(chatKeepScreenOnTimerRef.current);
      window.clearTimeout(sidebarRefreshTimerRef.current);
      window.cancelAnimationFrame(scrollFrameRef.current ?? 0);
    };
  }, []);

  const showNotice = useCallback((message: string) => {
    window.clearTimeout(noticeTimerRef.current);
    setNotice(message);
    noticeTimerRef.current = window.setTimeout(() => setNotice(""), 2200);
  }, []);

  const showDevelopmentNotice = useCallback(() => {
    showNotice(t("common.inDevelopment"));
  }, [showNotice, t]);

  // Multi-device Round 5: pull this conversation's journal events from every
  // paired active device on the LAN (slice 5.1). When no own device is
  // reachable, offer the contact-side restore (slice 5.2) — the contact's
  // user must explicitly allow it on their device.
  const [restoreContactPrompt, setRestoreContactPrompt] = useState<string | null>(null);
  const [restoreContactBusy, setRestoreContactBusy] = useState(false);
  // Both restore flows block for tens of seconds (dialing devices that may not
  // be on this network, waiting for a human to tap "allow" on the other
  // phone). A 2.2 s toast expired long before that and the screen went back to
  // looking idle — the field report was "нажали и как будто ничего не
  // произошло" (2026-07-29). The phase the backend reports is shown for as
  // long as it lasts instead.
  const [restoreProgress, setRestoreProgress] = useState<RestoreProgress | null>(null);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void listen<RestoreProgressPayload>("chat-restore-progress", (event) => {
      const { chat_id: eventChatId, phase, ...detail } = event.payload;
      // A restore only ever runs for the chat the user started it from; an
      // event for another chat belongs to no visible operation.
      setRestoreProgress((current) =>
        current && current.chatId === eventChatId ? { ...current, phase, ...detail } : current,
      );
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const restoreHistoryFromOwnDevices = useCallback(
    async (chatId: string) => {
      setRestoreProgress({ chatId, phase: "own_devices" });
      try {
        const summary = await api.restoreChatHistory(chatId);
        if (summary.devices_reached === 0) {
          setRestoreContactPrompt(chatId);
        } else if (summary.applied === 0) {
          showNotice(t("chat.restoreNothingNew"));
        } else {
          showNotice(t("chat.restoreDone", { count: summary.applied }));
        }
      } catch (err) {
        const message =
          err && typeof err === "object" && "message" in err
            ? String((err as { message: unknown }).message)
            : "";
        if (message === "no_paired_devices") {
          setRestoreContactPrompt(chatId);
        } else if (message === "restore_direct_chats_only") {
          showNotice(t("chat.restoreDirectOnly"));
        } else {
          showNotice(t("chat.restoreFailed"));
        }
      } finally {
        setRestoreProgress(null);
      }
    },
    [showNotice, t],
  );

  const restoreHistoryFromContact = useCallback(
    async (chatId: string) => {
      setRestoreContactPrompt(null);
      setRestoreContactBusy(true);
      // "asking" from the first frame: the request leaves before the backend
      // says anything, and that gap is what read as a dead button.
      setRestoreProgress({ chatId, phase: "asking" });
      try {
        const summary = await api.restoreChatHistoryFromContact(chatId);
        if (summary.applied === 0) {
          showNotice(t("chat.restoreNothingNew"));
        } else {
          showNotice(t("chat.restoreContactDone", { count: summary.applied }));
        }
      } catch (err) {
        const message =
          err && typeof err === "object" && "message" in err
            ? String((err as { message: unknown }).message)
            : "";
        if (message === "declined") {
          showNotice(t("chat.restoreContactDeclined"));
        } else if (message === "consent_timeout") {
          showNotice(t("chat.restoreContactTimeout"));
        } else if (message === "rate_limited") {
          showNotice(t("chat.restoreContactRateLimited"));
        } else if (message === "peer_not_reachable") {
          showNotice(t("chat.restoreContactUnreachable"));
        } else {
          showNotice(t("chat.restoreFailed"));
        }
      } finally {
        setRestoreContactBusy(false);
        setRestoreProgress(null);
      }
    },
    [showNotice, t],
  );

  const openUploadPlaceholder = useCallback(() => {
    showNotice(t("common.inDevelopment"));
  }, [showNotice, t]);

  const memberPeerIdSignature = useMemo(() => {
    if (!chat) return "";
    return chat.member_contact_ids
      .map((contactId) => {
        const contact = contacts.find((entry) => entry.local_id === contactId);
        return contact ? `${contactId}:${contact.peer_id}` : contactId;
      })
      .join("|");
  }, [chat?.member_contact_ids, contacts]);

  const memberPeerIds = useMemo(() => {
    if (!chat) return new Set<string>();
    return new Set(
      chat.member_contact_ids
        .map((contactId) => contacts.find((contact) => contact.local_id === contactId)?.peer_id)
        .filter((peerId): peerId is string => !!peerId),
    );
  }, [chat?.id, memberPeerIdSignature]);

  const fetchTransport = useCallback(async (chatId: string) => {
    if (transportInFlight.current) return;
    transportInFlight.current = true;
    try {
      const next = await api.getChatTransport(chatId);
      setTransportStatus(next);
      setTransportLoadState("ready");
    } catch (err) {
      // Surface as console.warn (not console.debug) in dev builds so the
      // root cause shows up in the default Inspect panel — without this the
      // "Статус канала недоступен" indicator gives no clue why it errored
      // (e.g. SQL schema drift, profile locked, etc.). Stays silent in
      // production builds.
      if (import.meta.env.DEV) {
        console.warn(
          `[getChatTransport] failed for chat ${chatId}:`,
          err instanceof Error ? `${err.name}: ${err.message}` : err,
        );
      }
      setTransportStatus(null);
      setTransportLoadState("error");
    } finally {
      transportInFlight.current = false;
    }
  }, []);

  useEffect(() => {
    setHeaderMenuRect(null);
    setMessageMenu(null);
    setQuoteTarget(null);
    setEditTarget(null);
    setEditDraft("");
    setDeleteTarget(null);
    setMediaViewer(null);
    setMessages([]);
    setHasOlderMessages(false);
    initialScrollSettledRef.current = false;
    setCallLog([]);
    lastStateSnapshot.current = "";
  }, [chat?.id]);

  useEffect(() => {
    if (!mediaViewer) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setMediaViewer(null);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mediaViewer]);

  useEffect(() => {
    if (showMobileBack) return;
    setMediaViewer(null);
  }, [showMobileBack]);

  useEffect(() => {
    if (!chat) {
      setMessages([]);
      setHasOlderMessages(false);
      setCallLog([]);
      setTransportStatus(null);
      setTransportLoadState("loading");
      lastStateSnapshot.current = "";
      return;
    }
    const chatId = chat.id;
    let cancelled = false;
    let deferredTimer: number | undefined;
    (async () => {
      try {
        const next = await api.getChatMessagesPage(chatId, null, MESSAGE_PAGE_LIMIT);
        if (cancelled) return;
        setHasOlderMessages(next.length >= MESSAGE_PAGE_LIMIT);
        shouldScrollToLatestRef.current = true;
        setMessages((current) => {
          const merged = mergeFetchedMessages(current, next, chatId);
          lastStateSnapshot.current = stateSnapshotFromMessages(merged);
          return merged;
        });
        deferredTimer = afterFirstPaint(() => {
          if (cancelled) return;
          api
            .listCallLog(chatId, 30)
            .then((nextCallLog) => {
              if (!cancelled) setCallLog(nextCallLog);
            })
            .catch(() => undefined);
          if (markReadActive) {
            api
              .markChatOpened(chatId)
              .then(() => {
                if (!cancelled) onChatRead?.(chatId);
              })
              .catch(() => undefined);
          }
        });
      } catch {
        if (!cancelled) {
          setMessages((current) => current.filter((message) => message.chat_id === chatId));
          setCallLog((current) => current.filter((entry) => entry.chat_id === chatId));
          lastStateSnapshot.current = "";
        }
      }
    })();
    return () => {
      cancelled = true;
      window.clearTimeout(deferredTimer);
    };
  }, [chat?.id, markReadActive, onChatRead]);

  // A message that lands while the window is hidden is deliberately NOT marked
  // read — the user was not looking. But the `inbox-changed` listener still
  // refreshes the message snapshot, which disarms the state poll's fallback, so
  // nothing marks it read afterwards either: the badge for the chat already on
  // screen stayed until the user left and came back (field 2026-07-27). Coming
  // back to the window is exactly the moment they do read it.
  useEffect(() => {
    if (!chat?.id || !markReadActive) return;
    const chatId = chat.id;
    const onVisible = () => {
      if (document.hidden) return;
      void markActiveChatRead(
        { activeChatId: chatId, markReadActive, pageHidden: false },
        api.markChatOpened,
        onChatRead,
      ).catch(() => undefined);
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onVisible);
    };
  }, [chat?.id, markReadActive, onChatRead]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;
    let unlisten: (() => void) | undefined;
    void listen<CallStateChangedPayload>("call-state-changed", (event) => {
      const ended = event.payload.ended;
      if (!ended || ended.chat_id !== chatId) return;
      if (isNearBottomRef.current) {
        shouldScrollToLatestRef.current = true;
      }
      setCallLog((current) => mergeCallLog(current, [ended]));
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [chat?.id]);

  useEffect(() => {
    if (!chat?.id) {
      setTransportStatus(null);
      setTransportLoadState("loading");
      return;
    }
    let cancelled = false;
    setTransportLoadState("loading");
    const chatId = chat.id;
    const timer = afterFirstPaint(() => {
      if (!cancelled) void fetchTransport(chatId);
    }, narrow ? 550 : 0);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [chat?.id, fetchTransport, narrow]);

  const loadOlderMessages = useCallback(() => {
    if (!chat?.id || !hasOlderMessages || olderMessagesInFlight.current) return;
    const firstMessage = messagesRef.current.find((message) => message.chat_id === chat.id);
    if (!firstMessage) return;
    const container = messagesContainerRef.current;
    const previousScrollHeight = container?.scrollHeight ?? 0;
    olderMessagesInFlight.current = true;
    api
      .getChatMessagesPage(chat.id, messageDisplayTimestamp(firstMessage), MESSAGE_PAGE_LIMIT)
      .then((older) => {
        setHasOlderMessages(older.length >= MESSAGE_PAGE_LIMIT);
        if (older.length === 0) return;
        setMessages((current) => {
          const merged = mergeFetchedMessages(current, older, chat.id);
          lastStateSnapshot.current = stateSnapshotFromMessages(merged);
          window.requestAnimationFrame(() => {
            const nextContainer = messagesContainerRef.current;
            if (!nextContainer) return;
            nextContainer.scrollTop += nextContainer.scrollHeight - previousScrollHeight;
          });
          return merged;
        });
      })
      .catch(() => undefined)
      .finally(() => {
        olderMessagesInFlight.current = false;
      });
  }, [chat?.id, hasOlderMessages]);

  const updateNearBottom = useCallback(() => {
    const container = messagesContainerRef.current;
    if (!container) return;
    if (initialScrollSettledRef.current && container.scrollTop <= 160) {
      loadOlderMessages();
    }
    const distanceFromBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight;
    isNearBottomRef.current = distanceFromBottom <= 48;
  }, [loadOlderMessages]);

  useEffect(() => {
    if (!narrow) return;
    const viewport = window.visualViewport;
    if (!viewport) return;
    const keepBottomAnchored = () => {
      const activeElement = document.activeElement;
      const textEntryFocused =
        activeElement instanceof HTMLInputElement ||
        activeElement instanceof HTMLTextAreaElement;
      if (isNearBottomRef.current || textEntryFocused) {
        scrollToLatestMessage();
      }
    };
    viewport.addEventListener("resize", keepBottomAnchored);
    viewport.addEventListener("scroll", keepBottomAnchored);
    return () => {
      viewport.removeEventListener("resize", keepBottomAnchored);
      viewport.removeEventListener("scroll", keepBottomAnchored);
    };
  }, [narrow, scrollToLatestMessage]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;

    let unlisten: (() => void) | undefined;
    void listen<{ peerId: string }>("chat-transport-changed", (event) => {
      if (!memberPeerIds.has(event.payload.peerId)) return;
      window.clearTimeout(transportDebounceRef.current);
      transportDebounceRef.current = window.setTimeout(() => {
        if (!document.hidden) {
          void fetchTransport(chatId);
        }
      }, 750);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
      window.clearTimeout(transportDebounceRef.current);
    };
  }, [chat?.id, memberPeerIds, fetchTransport]);

  // Inbound mutations (edit/delete from a peer) and fresh inbound messages
  // both ride the `inbox-changed` event from the backend. For a brand-new
  // inbound row the 4-5 s state poll would notice the new message_id and
  // delta-fetch it, but for a mutation the row's `created_at` and `status`
  // do not change — the poll's snapshot stays identical and the
  // delta-fetch's `created_at > watermark` window excludes the mutated
  // older row. Without this listener the peer's open ChatView only sees
  // the edited body / tombstone after they leave and re-enter the chat.
  // We do a single full re-fetch for the active chat — cheap relative to
  // the rarity of mutation events.
  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;
    let unlisten: (() => void) | undefined;
    void listen<{ chatId: string; messageId: string }>(
      "inbox-changed",
      (event) => {
        if (event.payload.chatId !== chatId) return;
        // This event refreshes the message snapshot below, so the fallback poll
        // cannot rediscover the row and clear unread later. Mark it now while
        // the user is actually looking at this chat.
        void markInboxEventReadIfVisible(
          {
            activeChatId: chatId,
            eventChatId: event.payload.chatId,
            markReadActive,
            pageHidden: document.hidden,
          },
          api.markChatOpened,
          onChatRead,
        ).catch(() => undefined);
        api
          .getChatMessagesPage(chatId, null, MESSAGE_PAGE_LIMIT)
          .then((fresh) => {
            setHasOlderMessages(fresh.length >= MESSAGE_PAGE_LIMIT);
            setMessages((current) => {
              const merged = mergeFetchedMessages(current, fresh, chatId);
              lastStateSnapshot.current = stateSnapshotFromMessages(merged);

              const receivedInbound = hasNewInboundMessage(current, merged);
              const activeElement = document.activeElement;
              const textEntryFocused =
                activeElement instanceof HTMLInputElement ||
                activeElement instanceof HTMLTextAreaElement;
              if (receivedInbound && (isNearBottomRef.current || textEntryFocused)) {
                shouldScrollToLatestRef.current = true;
              }

              return merged;
            });
          })
          .catch(() => undefined);
      },
    ).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [chat?.id, markReadActive, onChatRead]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;
    let unlisten: (() => void) | undefined;
    void listen<AttachmentTransferChangedPayload>(
      "attachment-transfer-changed",
      (event) => {
        if (event.payload.chatId !== chatId) return;
        api
          .getChatMessagesPage(chatId, null, MESSAGE_PAGE_LIMIT)
          .then((fresh) => {
            setHasOlderMessages(fresh.length >= MESSAGE_PAGE_LIMIT);
            setMessages((current) => {
              const merged = mergeFetchedMessages(current, fresh, chatId);
              lastStateSnapshot.current = stateSnapshotFromMessages(merged);
              return merged;
            });
          })
          .catch(() => undefined);
      },
    ).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [chat?.id]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;

    let unlisten: (() => void) | undefined;
    void listen<OutboxChangedPayload>("outbox-changed", (event) => {
      if (event.payload.chatId !== chatId) return;
      void fetchTransport(chatId);
      setMessages((current) => {
        let mutated = false;
        const next = current.map((message) => {
          if (message.message_id !== event.payload.messageId) return message;
          const nextDiagnostic = event.payload.deliveryDiagnostic ?? null;
          const diagnosticChanged =
            diagnosticSnapshot(message.delivery_diagnostic) !== diagnosticSnapshot(nextDiagnostic);
          if (message.status === event.payload.status && !diagnosticChanged) return message;
          mutated = true;
          return {
            ...message,
            status: event.payload.status,
            delivery_diagnostic: nextDiagnostic,
          };
        });
        if (!mutated) return current;
        lastStateSnapshot.current = stateSnapshotFromMessages(next);
        return next;
      });
      // Sidebar (unread counters + last preview) gets a debounced
      // coalescer instead of a per-event full refresh. We never re-fetch
      // the chat message list on a status flip — the inline patch above
      // already covers the only field that changed.
      window.clearTimeout(sidebarRefreshTimerRef.current);
      sidebarRefreshTimerRef.current = window.setTimeout(() => {
        void onRefresh().catch(() => undefined);
      }, 400);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
      window.clearTimeout(sidebarRefreshTimerRef.current);
    };
  }, [chat?.id, fetchTransport, onRefresh]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;
    const pollMs = narrow ? 9000 : 6000;
    const timer = window.setInterval(() => {
      if (document.hidden || messagesPollInFlight.current) return;
      messagesPollInFlight.current = true;
      api
        .getChatMessageStates(chatId)
        .then(async (states) => {
          const nextSnapshot = stateSnapshot(states);
          if (nextSnapshot === lastStateSnapshot.current) {
            return;
          }
          const previous = messagesRef.current;
          // Fast path covers BOTH "status changed" and "new rows arrived":
          // we always delta-fetch from the latest known timestamp instead of
          // re-reading every message in the chat. Page re-fetch is reserved
          // for the rare shrink/empty cases where the delta window cannot
          // reconstruct the visible slice.
          // Arrival, not display position: a message written earlier but
          // delivered late sits ABOVE the last bubble, so a display-order
          // watermark would leave it below the cursor and never fetch it.
          const watermark = latestArrivalTimestamp(previous);
          let nextMessages = previous;
          if (states.length < previous.length) {
            const fresh = await api.getChatMessagesPage(chatId, null, MESSAGE_PAGE_LIMIT);
            setHasOlderMessages(fresh.length >= MESSAGE_PAGE_LIMIT);
            nextMessages = mergeFetchedMessages(previous, fresh, chatId).filter(
              (message) =>
                states.some((state) => state.message_id === message.message_id),
            );
          } else if (watermark) {
            const delta = await api.getChatMessagesDelta(chatId, watermark);
            if (delta.length > 0) {
              nextMessages = mergeMessages(previous, delta);
            }
          } else if (states.length > 0) {
            // No previous rows but the backend already has messages — first
            // visit can't use a watermark, so read the latest page once.
            const fresh = await api.getChatMessagesPage(chatId, null, MESSAGE_PAGE_LIMIT);
            setHasOlderMessages(fresh.length >= MESSAGE_PAGE_LIMIT);
            nextMessages = mergeFetchedMessages(previous, fresh, chatId);
          }
          nextMessages = applyStatuses(nextMessages, states);
          const receivedInbound = hasNewInboundMessage(previous, nextMessages);
          const activeElement = document.activeElement;
          const textEntryFocused =
            activeElement instanceof HTMLInputElement ||
            activeElement instanceof HTMLTextAreaElement;
          if (receivedInbound && (isNearBottomRef.current || textEntryFocused)) {
            shouldScrollToLatestRef.current = true;
          }
          setMessages(nextMessages);
          lastStateSnapshot.current = nextSnapshot;
          if (receivedInbound && markReadActive) {
            api
              .markChatOpened(chatId)
              .then(() => onChatRead?.(chatId))
              .catch(() => undefined);
          }
        })
        .catch(() => undefined)
        .finally(() => {
          messagesPollInFlight.current = false;
        });
    }, pollMs);
    return () => window.clearInterval(timer);
  }, [chat?.id, markReadActive, narrow, onChatRead]);

  useEffect(() => {
    if (!chat?.id) return;
    const chatId = chat.id;
    function onVisible() {
      if (!document.hidden) {
        void fetchTransport(chatId);
      }
    }
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [chat?.id, fetchTransport]);

  // MUST stay before the early return below — calling `useEffect`
  // conditionally based on `chat` would change the hook count between
  // renders and trigger React's "rendered fewer hooks than expected"
  // crash (whole tree unmounts → white screen) on every transition from
  // an open chat to no chat, e.g. after deleting the active direct chat.
  useEffect(() => {
    if (!chat || chat.is_self_chat || chat.chat_type !== "direct") return;
    const contactId = chat.member_contact_ids[0];
    if (!contactId) return;
    const contact = contacts.find((entry) => entry.local_id === contactId);
    if (!contact || contact.trust_status !== "verified") return;
    if (avatarSyncContactRef.current === contactId && profileCardSyncContactRef.current === contactId) return;
    avatarSyncContactRef.current = contactId;
    profileCardSyncContactRef.current = contactId;
    window.clearTimeout(avatarSyncTimerRef.current);
    avatarSyncTimerRef.current = window.setTimeout(() => {
      void api.syncPeerAvatarForContact(contactId).catch(() => undefined);
      void api.syncPeerProfileCardForContact(contactId).catch(() => undefined);
    }, 1200);
  }, [
    chat?.id,
    chat?.chat_type,
    chat?.is_self_chat,
    chat?.member_contact_ids,
    contacts,
  ]);

  useEffect(() => {
    if (!forwardTarget) {
      setForwardSearch("");
      return;
    }
    api
      .listChats()
      .then(setForwardChats)
      .catch(() => setForwardChats([]));
  }, [forwardTarget]);

  // Forward picker options: recent direct chats + Notes, each resolved to a
  // display name and avatar. Default view shows the 10 most recent (listChats
  // is recency-ordered) displayed by name; a search filters all of them by
  // name and caps the result at 10.
  const forwardOptions = useMemo(() => {
    const query = forwardSearch.trim().toLocaleLowerCase();
    const base = forwardChats
      .filter((entry) => entry.is_self_chat || entry.chat_type === "direct")
      .map((entry) => {
        const contact = entry.is_self_chat
          ? null
          : contacts.find((c) => entry.member_contact_ids.includes(c.local_id)) ?? null;
        const name = entry.is_self_chat
          ? t("chat.notes")
          : contact?.display_name || entry.title || t("chat.directChat");
        return {
          id: entry.id,
          name,
          avatar: contact?.peer_avatar_jpeg_base64 ?? null,
          isSelf: !!entry.is_self_chat,
        };
      });
    const filtered = query
      ? base.filter((option) => option.name.toLocaleLowerCase().includes(query))
      : base.slice(0, 10);
    return filtered
      .sort((a, b) => {
        if (a.isSelf !== b.isSelf) return a.isSelf ? -1 : 1;
        return a.name.localeCompare(b.name);
      })
      .slice(0, 10);
  }, [forwardChats, forwardSearch, contacts, t]);

  // All `useCallback` / `useRef` hooks below MUST stay above the early
  // return for the same reason — when the active chat is deleted from the
  // chat list, `chat` flips from non-null to null and the early return
  // fires. Any hook declared *after* the return is skipped on that render,
  // React notices a smaller hook count, and the whole subtree unmounts
  // into the top-level ErrorBoundary (the "Continue / Reload window"
  // screen reported on Android). 0.9.149 fixed the avatar-sync hook
  // above; 0.9.207 fixed the rest after the 0.9.205 edit/delete slice
  // added several new callbacks below the return. If you ever add another
  // hook, keep it inside this block — not below the `if (!chat)` line.

  const canEditOwnMessage = useCallback(
    (message: ChatMessage): boolean => {
      if (message.direction !== "outbound") return false;
      if (message.sender_public_key !== profile.public_key) return false;
      if (message.message_id.startsWith("optimistic-")) return false;
      if (message.status === "failed") return false;
      if (message.deleted_at) return false;
      return true;
    },
    [profile.public_key],
  );

  const isEditLockedByLaterInbound = useCallback(
    (message: ChatMessage): boolean => {
      const ts = Date.parse(message.created_at);
      if (!Number.isFinite(ts)) return false;
      return messagesRef.current.some((other) => {
        if (other.direction !== "inbound") return false;
        const otherTs = Date.parse(other.created_at);
        return Number.isFinite(otherTs) && otherTs > ts;
      });
    },
    [],
  );

  const canDeleteOwnMessage = useCallback(
    (message: ChatMessage): boolean => {
      if (message.direction !== "outbound") return false;
      if (message.sender_public_key !== profile.public_key) return false;
      if (message.message_id.startsWith("optimistic-")) return false;
      if (message.deleted_at) return false;
      return true;
    },
    [profile.public_key],
  );

  const beginEdit = useCallback((target: ChatMessage) => {
    setEditTarget({
      messageId: target.message_id,
      initialText: target.text,
    });
    setEditDraft(target.text);
  }, []);

  const cancelEdit = useCallback(() => {
    setEditTarget(null);
    setEditDraft("");
  }, []);

  const submitEdit = useCallback(async () => {
    if (!editTarget) return;
    const trimmed = editDraft.trim();
    if (!trimmed || trimmed === editTarget.initialText.trim()) {
      cancelEdit();
      return;
    }
    setEditSaving(true);
    try {
      const updated = await api.editMessage(editTarget.messageId, trimmed);
      setMessages((current) =>
        current.map((message) =>
          message.message_id === updated.message_id ? updated : message,
        ),
      );
      cancelEdit();
      showNotice(t("messageMenu.editSaved"));
      void onRefresh().catch(() => undefined);
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as { code?: unknown }).code
          : undefined;
      if (code === "message_mutation_locked") {
        showNotice(t("messageMenu.editLocked"));
        cancelEdit();
      } else {
        showNotice(t("messageMenu.editFailed"));
      }
    } finally {
      setEditSaving(false);
    }
  }, [cancelEdit, editDraft, editTarget, onRefresh, showNotice, t]);

  const submitDelete = useCallback(async () => {
    if (!deleteTarget) return;
    setDeleteSaving(true);
    try {
      const updated = await api.deleteMessage(deleteTarget);
      setMessages((current) =>
        current.map((message) =>
          message.message_id === updated.message_id ? updated : message,
        ),
      );
      setDeleteTarget(null);
      showNotice(t("messageMenu.deleted"));
      void onRefresh().catch(() => undefined);
    } catch {
      showNotice(t("messageMenu.deleteFailed"));
    } finally {
      setDeleteSaving(false);
    }
  }, [deleteTarget, onRefresh, showNotice, t]);

  const submitDeleteFile = useCallback(async () => {
    if (!deleteFileTarget) return;
    setDeleteFileSaving(true);
    try {
      const updated = await api.deleteAttachmentLocal(deleteFileTarget);
      setMessages((current) =>
        current.map((message) =>
          message.message_id === updated.message_id ? updated : message,
        ),
      );
      setDeleteFileTarget(null);
      showNotice(t("attachments.deleted"));
      void onRefresh().catch(() => undefined);
    } catch {
      showNotice(t("attachments.deleteFailed"));
    } finally {
      setDeleteFileSaving(false);
    }
  }, [deleteFileTarget, onRefresh, showNotice, t]);

  const submitClearChat = useCallback(async () => {
    if (!clearChatTarget) return;
    setClearChatSaving(true);
    try {
      await api.clearChatHistory(clearChatTarget.id);
      setMessages([]);
      setCallLog([]);
      setHasOlderMessages(false);
      setClearChatTarget(null);
      showNotice(t("chatHeaderMenu.clearDone"));
      void onRefresh().catch(() => undefined);
    } catch {
      showNotice(t("chatHeaderMenu.clearFailed"));
    } finally {
      setClearChatSaving(false);
    }
  }, [clearChatTarget, onRefresh, showNotice, t]);

  const canForwardAttachment = useCallback((message: ChatMessage): boolean => {
    return !!message.attachment
      && message.attachment.status === "available"
      && !message.deleted_at
      && !message.message_id.startsWith("optimistic-");
  }, []);

  const canShareAttachment = useCallback((message: ChatMessage): boolean => {
    return canForwardAttachment(message);
  }, [canForwardAttachment]);

  const canSaveAttachment = useCallback((message: ChatMessage): boolean => {
    return canForwardAttachment(message);
  }, [canForwardAttachment]);

  // Local file delete is available to whoever holds a stored copy — sender or
  // recipient — for any not-yet-tombstoned attachment.
  const canDeleteAttachmentLocal = useCallback((message: ChatMessage): boolean => {
    return (
      !!message.attachment &&
      message.attachment.status !== "deleted" &&
      !message.deleted_at &&
      !message.message_id.startsWith("optimistic-")
    );
  }, []);

  // Resend-from-start only makes sense for the sender's own outbound file that
  // still holds its content locally.
  const canResendAttachment = useCallback(
    (message: ChatMessage): boolean => {
      return (
        message.direction === "outbound" &&
        message.sender_public_key === profile.public_key &&
        !!message.attachment &&
        message.attachment.status !== "deleted" &&
        !message.deleted_at &&
        !message.message_id.startsWith("optimistic-")
      );
    },
    [profile.public_key],
  );

  const saveAttachment = useCallback(async (message: ChatMessage) => {
    const attachment = message.attachment;
    if (!attachment || !canSaveAttachment(message)) return;
    const destination = await save({ defaultPath: safeFileName(attachment.file_name) });
    if (!destination) return;
    try {
      // Stream the file to the destination without buffering it as base64 in
      // the WebView (the memory wall on large attachments). On Android the
      // Activity bridge copies a backend temp file into the SAF destination;
      // on desktop the backend writes the plaintext directly.
      let tempPath: string | null = null;
      try {
        tempPath = await api.exportAttachmentToTemp(attachment.id);
        const streamed = await writeTempFileToPath(destination, tempPath);
        if (!streamed) {
          await api.saveAttachment(attachment.id, destination);
        }
      } finally {
        if (tempPath) void api.deleteAttachmentTempFile(tempPath).catch(() => {});
      }
      showNotice(t("attachments.saved"));
    } catch {
      showNotice(t("attachments.saveFailed"));
    }
  }, [canSaveAttachment, showNotice, t]);

  const shareAttachment = useCallback(async (message: ChatMessage) => {
    const attachment = message.attachment;
    if (!attachment || !canShareAttachment(message)) return;
    try {
      const payload = await api.getAttachmentBytes(attachment.id);
      if (shareBase64File(payload.file_name, payload.mime_type, payload.bytes_b64)) {
        return;
      }
      const bytes = base64ToBytes(payload.bytes_b64);
      const fileBytes = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(fileBytes).set(bytes);
      const sharedFile = new File([fileBytes], payload.file_name, { type: payload.mime_type });
      if (navigator.canShare?.({ files: [sharedFile] })) {
        await navigator.share({ files: [sharedFile], title: payload.file_name });
        return;
      }
      await api.shareAttachment(attachment.id);
    } catch {
      showNotice(t("attachments.shareFailed"));
    }
  }, [canShareAttachment, showNotice, t]);

  const submitForward = useCallback(
    (targetChatId: string) => {
      if (!forwardTarget) return;
      const sourceMessageId = forwardTarget.message_id;
      const currentChatId = chat?.id;
      // Close the picker immediately and re-encrypt/store in the background so
      // the UI stays responsive — forwarding a large file re-encrypts it, which
      // is not instant on mobile.
      setForwardTarget(null);
      showNotice(t("attachments.forwardStarted"));
      api
        .forwardAttachmentMessage(sourceMessageId, targetChatId)
        .then((forwarded) => {
          if (currentChatId === targetChatId) {
            setMessages((current) => mergeMessages(current, [forwarded]));
          }
          showNotice(t("attachments.forwarded"));
          void onRefresh().catch(() => undefined);
        })
        .catch(() => showNotice(t("attachments.forwardFailed")));
    },
    [chat?.id, forwardTarget, onRefresh, showNotice, t],
  );

  const handleMessageMenuAction = useCallback(
    (action: MessageMenuAction, messageId: string) => {
      setMessageMenu(null);
      const target = messagesRef.current.find(
        (message) => message.message_id === messageId,
      );
      if (!target) return;
      if (action === "copy") {
        void copyTextToClipboard(target.text)
          .then(() => showNotice(t("messageMenu.copied")))
          .catch(() => showNotice(t("messageMenu.copyFailed")));
        return;
      }
      if (action === "quote") {
        // `authorNameForPublicKey` is a function declaration further down
        // in the component body — JS hoists `function fn()` declarations
        // to the top of the enclosing function scope, so calling it from
        // here works even though source order places it below.
        const authorName =
          target.direction === "outbound"
            ? profile.display_name
            : authorNameForPublicKey(target.sender_public_key);
        setQuoteTarget({
          messageId: target.message_id,
          authorName,
          excerpt: clampExcerpt(target.text),
        });
        return;
      }
      if (action === "edit") {
        if (!canEditOwnMessage(target)) return;
        if (isEditLockedByLaterInbound(target)) {
          showNotice(t("messageMenu.editLocked"));
          return;
        }
        beginEdit(target);
        return;
      }
      if (action === "delete") {
        if (!canDeleteOwnMessage(target)) return;
        setDeleteTarget(target.message_id);
        return;
      }
      if (action === "save") {
        void saveAttachment(target);
        return;
      }
      if (action === "forward") {
        if (!canForwardAttachment(target)) return;
        setForwardTarget(target);
        return;
      }
      if (action === "share") {
        void shareAttachment(target);
        return;
      }
      if (action === "resend") {
        if (!canResendAttachment(target)) return;
        api
          .resendAttachment(target.message_id)
          .then((updated) => {
            setMessages((current) =>
              current.map((message) =>
                message.message_id === updated.message_id ? updated : message,
              ),
            );
            showNotice(t("attachments.resendStarted"));
            void onRefresh().catch(() => undefined);
          })
          .catch(() => showNotice(t("attachments.resendFailed")));
        return;
      }
      if (action === "deleteFile") {
        if (!canDeleteAttachmentLocal(target)) return;
        setDeleteFileTarget(target.message_id);
        return;
      }
    },
    [
      beginEdit,
      canDeleteAttachmentLocal,
      canDeleteOwnMessage,
      canEditOwnMessage,
      canForwardAttachment,
      canResendAttachment,
      saveAttachment,
      shareAttachment,
      contacts,
      isEditLockedByLaterInbound,
      onRefresh,
      profile.display_name,
      profile.public_key,
      showNotice,
      t,
    ],
  );

  const longPressRef = useRef<{
    timer: number | undefined;
    fired: boolean;
    origin: { x: number; y: number } | null;
  }>({ timer: undefined, fired: false, origin: null });

  const cancelMessageLongPress = useCallback(() => {
    if (longPressRef.current.timer !== undefined) {
      window.clearTimeout(longPressRef.current.timer);
      longPressRef.current.timer = undefined;
    }
    longPressRef.current.origin = null;
  }, []);

  const beginMessageLongPress = useCallback(
    (event: React.PointerEvent<HTMLElement>, messageId: string) => {
      // Mouse uses right-click; pen and touch use the long-press timer.
      if (event.pointerType === "mouse") return;
      longPressRef.current.fired = false;
      longPressRef.current.origin = { x: event.clientX, y: event.clientY };
      const cx = event.clientX;
      const cy = event.clientY;
      longPressRef.current.timer = window.setTimeout(() => {
        longPressRef.current.fired = true;
        setMessageMenu({ messageId, x: cx, y: cy });
      }, MESSAGE_LONG_PRESS_DELAY_MS);
    },
    [],
  );

  const trackMessageLongPressMove = useCallback(
    (event: React.PointerEvent<HTMLElement>) => {
      const origin = longPressRef.current.origin;
      if (!origin) return;
      const dx = event.clientX - origin.x;
      const dy = event.clientY - origin.y;
      if (
        dx * dx + dy * dy >
        MESSAGE_LONG_PRESS_MOVE_TOLERANCE * MESSAGE_LONG_PRESS_MOVE_TOLERANCE
      ) {
        cancelMessageLongPress();
      }
    },
    [cancelMessageLongPress],
  );

  const consumeLongPressClick = useCallback(() => {
    if (!longPressRef.current.fired) return false;
    longPressRef.current.fired = false;
    return true;
  }, []);

  const isQuotableMessage = useCallback((message: ChatMessage): boolean => {
    // Optimistic placeholders cannot be quoted — their message_id is local
    // and will be replaced once the backend confirms the send. Tombstones
    // have no body to quote, copy or further mutate.
    if (message.deleted_at) return false;
    return !message.message_id.startsWith("optimistic-") && message.status !== "failed";
  }, []);

  // Must stay ABOVE the `if (!chat)` early return: a hook skipped on the
  // blank-state render would change the hook count between renders
  // (React error #310). It depends on nothing chat-specific.
  const retryMessage = useCallback(
    (messageId: string) => {
      // Optimistically flip the row out of the failed state; the backend clears
      // the failed marker and re-queues the outbox, and onRefresh reconciles.
      setMessages((current) =>
        current.map((message) =>
          message.message_id === messageId ? { ...message, status: "pending" } : message,
        ),
      );
      api
        .retryMessage(messageId)
        .then(() => onRefresh())
        .catch(() => {
          showNotice(t("messageStatus.retryFailed"));
          void onRefresh().catch(() => undefined);
        });
    },
    [onRefresh, showNotice, t],
  );

  if (!chat) {
    return <div className="blank-state">{t("chat.blankState")}</div>;
  }
  const activeChat = chat;
  const isSelfChat = !!activeChat.is_self_chat;

  const directContact = presenceContact;
  const profileDialogLiveContact = profileDialogContact
    ? contacts.find((contact) => contact.local_id === profileDialogContact.local_id) ?? profileDialogContact
    : null;
  const unverifiedDirect =
    !isSelfChat && !!directContact && directContact.trust_status !== "verified" && directContact.trust_status !== "blocked";
  // The added side has no protocol-level "accepted your request" signal, so
  // only state facts: the peer has never been seen online and nothing has
  // ever arrived from them — most likely the request is still unaccepted.
  const awaitingFirstContact =
    unverifiedDirect &&
    !!directContact &&
    directContact.trust_status !== "pending" &&
    !directContact.last_seen_at &&
    directContact.presence_status !== "online" &&
    !messages.some((message) => message.direction === "inbound");

  async function trustDirect() {
    if (!directContact) return;
    try {
      await api.verifyContact(directContact.local_id);
      await onRefresh();
      setShowFingerprint(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("chat.verifyFailed"));
    }
  }

  async function rejectRequest() {
    if (!directContact) return;
    try {
      await api.rejectContactRequest(directContact.local_id);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отклонить запрос");
    }
  }

  async function blockContact() {
    if (!directContact) return;
    try {
      await api.blockContact(directContact.local_id);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось заблокировать контакт");
    }
  }

  async function send(text: string) {
    const pendingId = `optimistic-${Date.now()}`;
    const quoteAtSendTime = quoteTarget;
    const optimisticQuote = quoteAtSendTime
      ? {
          message_id: quoteAtSendTime.messageId,
          excerpt: quoteAtSendTime.excerpt,
          author_public_key: "",
        }
      : null;
    const pendingMessage: ChatMessage = {
      local_id: pendingId,
      message_id: pendingId,
      chat_id: activeChat.id,
      sender_public_key: profile.public_key,
      direction: "outbound",
      text,
      status: "pending",
      protocol_version: "",
      envelope_version: 1,
      crypto_suite_version: "",
      created_at: new Date().toISOString(),
      display_at: new Date().toISOString(),
      quote: optimisticQuote,
    };
    shouldScrollToLatestRef.current = true;
    flushSync(() => {
      setMessages((current) => mergeMessages(current, [pendingMessage]));
    });
    // Clear the composer chip eagerly so the user sees the quote attach to
    // the optimistic pending bubble instead of hanging above the composer.
    setQuoteTarget(null);
    scrollToLatestMessage();
    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => resolve());
      });
    });

    let savedMessage: ChatMessage;
    try {
      savedMessage = await api.sendMessage(
        activeChat.id,
        text,
        quoteAtSendTime?.messageId ?? null,
      );
    } catch {
      setMessages((current) =>
        current.map((message) =>
          message.message_id === pendingId ? { ...message, status: "failed" } : message,
        ),
      );
      return;
    }

    shouldScrollToLatestRef.current = true;
    flushSync(() => {
      setMessages((current) => replaceMessage(current, pendingId, savedMessage));
    });
    scrollToLatestMessage();
    // Answering is the strongest possible proof the chat has been read; the
    // badge must not outlive the reply.
    void markActiveChatRead(
      { activeChatId: activeChat.id, markReadActive, pageHidden: document.hidden },
      api.markChatOpened,
      onChatRead,
    ).catch(() => undefined);
    void onRefresh().catch(() => undefined);
  }

  async function sendAttachment(file: File, caption: string) {
    const quoteAtSendTime = quoteTarget;
    setQuoteTarget(null);
    // Instant feedback: put an optimistic bubble with a "preparing" progress
    // row into the chat before any file reading starts, then run the actual
    // read/encode/upload detached so the composer is free immediately.
    const pendingId = `optimistic-${Date.now()}`;
    const pendingMessage: ChatMessage = {
      local_id: pendingId,
      message_id: pendingId,
      chat_id: activeChat.id,
      sender_public_key: profile.public_key,
      direction: "outbound",
      text: caption,
      status: "pending",
      protocol_version: "",
      envelope_version: 1,
      crypto_suite_version: "",
      created_at: new Date().toISOString(),
      display_at: new Date().toISOString(),
      attachment: {
        id: `${pendingId}-attachment`,
        transfer_id: "",
        file_name: file.name,
        mime_type: file.type || "application/octet-stream",
        media_kind: "file",
        size_bytes: file.size,
        sha256_b64: "",
        status: "pending",
        bytes_transferred: 0,
        total_bytes: file.size,
      },
    };
    shouldScrollToLatestRef.current = true;
    flushSync(() => {
      setMessages((current) => mergeMessages(current, [pendingMessage]));
    });
    scrollToLatestMessage();
    const uploadSignature = attachmentUploadSignature(activeChat.id, file.name, file.size);
    inFlightAttachmentUploads.add(uploadSignature);
    void (async () => {
      try {
        // Streams large files into a backend temp file in bounded slices so
        // the WebView never buffers the whole file + base64 at once; small
        // files take the single-shot path.
        const savedMessage = await sendAttachmentFile(
          activeChat.id,
          file,
          caption,
          quoteAtSendTime?.messageId ?? null,
          (sentBytes, totalBytes) => {
            setMessages((current) =>
              current.map((message) =>
                message.message_id === pendingId && message.attachment
                  ? {
                      ...message,
                      attachment: {
                        ...message.attachment,
                        bytes_transferred: sentBytes,
                        total_bytes: totalBytes,
                        // All slices delivered: the backend is now encrypting
                        // and chunking, which takes a while for big files —
                        // switch the row to the honest "saving" phase.
                        transfer_id:
                          sentBytes >= totalBytes && totalBytes > 0
                            ? "finalizing"
                            : message.attachment.transfer_id,
                      },
                    }
                  : message,
              ),
            );
          },
        );
        setMessages((current) => replaceMessage(current, pendingId, savedMessage));
        void onRefresh().catch(() => undefined);
      } catch (err) {
        // Nothing was persisted; drop the optimistic row instead of leaving a
        // dead bubble that no retry can revive.
        setMessages((current) =>
          current.filter((message) => message.message_id !== pendingId),
        );
        showNotice(
          callErrorCode(err) === "attachment_too_large"
            ? t("attachments.tooLarge", { size: formatFileSize(MAX_ATTACHMENT_BYTES) })
            : t("attachments.sendFailed"),
        );
      } finally {
        inFlightAttachmentUploads.delete(uploadSignature);
      }
    })();
  }

  const title =
    isSelfChat ? t("chat.notes") : activeChat.title ||
    directContact?.display_name ||
    t("chat.directChat");
  const online = directContact?.presence_status === "online";
  const verified = !isSelfChat && directContact?.trust_status === "verified";
  const headerSubtitle = chatHeaderSubtitle(
    activeChat,
    directContact,
    transportStatus?.active_delivery_path,
  );
  const callBlockedReason: CallBlockedReason | null = (() => {
    if (isSelfChat || activeChat.chat_type !== "direct" || !directContact) return "not_direct";
    if (currentCall) return "already_in_call";
    // Said before the attempt rather than after it: the backend refuses too,
    // but a disabled button with a reason beats a failed call.
    if (proxyEnabled) return "proxy_active";
    if (directContact.trust_status !== "verified") return "unverified";
    if (transportLoadState === "loading") return "transport_loading";
    // Presence is best-effort: a peer can be offline in the header while a
    // relay/bootstrap route is still dialable. Let start_call try the route
    // graph and surface PeerNotReachable only after the backend attempt fails.
    // microphone state is NOT a hard block here — leaving the button
    // enabled lets `startVoiceCall` run `ensureMicrophoneAccess`, detect
    // a `denied` Permissions API state, and offer the App-info Settings
    // deep-link recovery prompt. Hard-disabling the button at this layer
    // would hide that recovery path on Android USER_FIXED state.
    return null;
  })();

  function callBlockedMessage(reason: CallBlockedReason) {
    switch (reason) {
      case "already_in_call":
        return t("calls.eligibility.alreadyInCall");
      case "proxy_active":
        return t("calls.eligibility.proxyActive");
      case "peer_offline":
        return t("calls.result.unreachable");
      case "transport_loading":
        return t("calls.eligibility.transportLoading");
      case "unverified":
        return t("calls.result.failed");
      case "not_direct":
        return t("calls.eligibility.notDirect");
    }
  }

  function callFailureMessage(err: unknown) {
    switch (callErrorCode(err)) {
      case "already_in_call":
        return t("calls.eligibility.alreadyInCall");
      case "no_local_microphone":
        return t("calls.eligibility.noLocalMic");
      case "calls_disabled_by_proxy":
        return t("calls.eligibility.proxyActive");
      case "not_verified":
        return t("calls.result.failed");
      case "peer_not_reachable":
        return t("calls.result.unreachable");
      default:
        return t("calls.result.failed");
    }
  }

  async function startVoiceCall() {
    if (!directContact) return;
    if (callBlockedReason) {
      showNotice(callBlockedMessage(callBlockedReason));
      return;
    }
    setCallStarting(true);
    let callId: string | null = null;
    try {
      callMediaController.setSetupPhase("checking_microphone");
      callId = await api.beginCall(activeChat.id, directContact.public_key);
      const micResult = await ensureMicrophoneAccess();
      if (!micResult.ok) {
        await api.noMicrophoneCall(callId).catch(() => undefined);
        // `denied` covers both Permissions API "denied" and the Android
        // USER_FIXED state where `getUserMedia` rejects with NotAllowedError
        // because `onPermissionRequest` can no longer show a system dialog.
        // The only recovery path is the App-info Settings deep-link.
        if (micResult.denied && window.confirm(t("calls.openMicSettingsPrompt"))) {
          if (!openAppSettings()) {
            showNotice(t("calls.eligibility.noLocalMic"));
          }
        } else {
          showNotice(t("calls.eligibility.noLocalMic"));
        }
        return;
      }
      const offerSdp = await callMediaController.prepareOutboundOffer(directContact.peer_id);
      await api.sendCallOffer(callId, offerSdp);
      callMediaController.bindCall(callId);
      await onRefresh();
    } catch (err) {
      callMediaController.cleanup(callId ?? undefined);
      if (callId) {
        await api.hangupCall(callId).catch(() => undefined);
      }
      showNotice(callFailureMessage(err));
    } finally {
      setCallStarting(false);
    }
  }

  const callButtonTitle = callBlockedReason
    ? callBlockedMessage(callBlockedReason)
    : t("chat.voiceCall");

  function authorForMessage(message: ChatMessage) {
    if (message.direction === "outbound") {
      return {
        name: profile.display_name,
        initial: profile.display_name.slice(0, 1).toUpperCase() || "V",
        avatarJpegBase64: profile.avatar_jpeg_base64,
      };
    }
    const contact =
      activeChat.chat_type === "direct"
        ? directContact
        : contacts.find((entry) => entry.public_key === message.sender_public_key);
    const name = contact?.display_name || t("chat.unknownSender");
    return {
      name,
      initial: name.slice(0, 1).toUpperCase() || "?",
      avatarJpegBase64: contact?.peer_avatar_jpeg_base64,
    };
  }

  function authorNameForPublicKey(publicKey: string): string {
    if (publicKey === profile.public_key) return profile.display_name;
    const contact = contacts.find((entry) => entry.public_key === publicKey);
    return contact?.display_name || t("chat.unknownSender");
  }

  const quotePreview: ComposerQuotePreview | null = quoteTarget
    ? { authorName: quoteTarget.authorName, excerpt: quoteTarget.excerpt }
    : null;

  return (
    <section className="chat-view">
      <header className="chat-header">
        <div className="chat-header-row">
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
          <div className="chat-header-title">
            <h1>
              {!isSelfChat && directContact && (
                <span className={`presence-dot ${online ? "online" : "offline"}`} />
              )}
              <span className="chat-header-name">{title}</span>
              {verified && (
                <ShieldCheck size={16} className="verified-tick" aria-label={t("common.verified")} />
              )}
            </h1>
            {headerSubtitle && (
              <span className="chat-header-presence">{headerSubtitle}</span>
            )}
          </div>
          {!isSelfChat && (
            <div className="chat-header-actions">
              <button
                type="button"
                onClick={startVoiceCall}
                title={callButtonTitle}
                aria-label={callButtonTitle}
                disabled={callStarting}
              >
                <Phone size={17} />
              </button>
              <button
                type="button"
                onClick={(event) => {
                  // Capture rect synchronously: React nulls out
                  // `event.currentTarget` after the handler returns, so reading
                  // it inside a setState updater crashes on the second open
                  // (TypeError: ... reading 'getBoundingClientRect').
                  const rect = event.currentTarget.getBoundingClientRect();
                  setHeaderMenuRect((current) => (current ? null : rect));
                }}
                title={t("chatHeaderMenu.title")}
                aria-haspopup="menu"
                aria-expanded={!!headerMenuRect}
              >
                <MoreVertical size={17} />
              </button>
            </div>
          )}
        </div>
      </header>
      {headerMenuRect && (
        <ChatHeaderMenu
          anchorRect={headerMenuRect}
          onAction={(action) => {
            setHeaderMenuRect(null);
            if (action === "call") {
              void startVoiceCall();
              return;
            }
            if (action === "profile") {
              if (directContact) {
                setProfileDialogContact(directContact);
              } else {
                showDevelopmentNotice();
              }
              return;
            }
            if (action === "stats") {
              setStatsDialogChat(activeChat);
              return;
            }
            if (action === "restore") {
              void restoreHistoryFromOwnDevices(activeChat.id);
              return;
            }
            if (action === "clear") {
              setClearChatTarget(activeChat);
              return;
            }
            showDevelopmentNotice();
          }}
          onClose={() => setHeaderMenuRect(null)}
        />
      )}
      {restoreProgress && (
        // No close handler and no cancel: the operation cannot be interrupted
        // from here, and a button that pretends otherwise is worse than none.
        <div className="modal-backdrop" role="alertdialog" aria-busy="true" aria-live="polite">
          <section className="modal security-progress-modal">
            <Loader2 className="spin" size={30} aria-hidden="true" />
            <h1>{t("chat.restoreProgressTitle")}</h1>
            <p>
              {restoreProgress.phase === "own_devices"
                ? t("chat.restoreProgressDevices", {
                    current: restoreProgress.current ?? 1,
                    total: restoreProgress.total ?? 1,
                  })
                : restoreProgress.phase === "asking"
                  ? t("chat.restoreProgressAsking")
                  : restoreProgress.phase === "awaiting_consent"
                    ? t("chat.restoreProgressWaiting", {
                        seconds: restoreProgress.seconds_left ?? 0,
                      })
                    : t("chat.restoreProgressReceiving", {
                        count: restoreProgress.applied ?? 0,
                      })}
            </p>
            <p className="hint">
              {restoreProgress.phase === "own_devices"
                ? t("chat.restoreProgressDevicesHint")
                : restoreProgress.phase === "awaiting_consent"
                  ? t("chat.restoreProgressWaitingHint")
                  : t("chat.restoreProgressKeepOpenHint")}
            </p>
          </section>
        </div>
      )}
      {restoreContactPrompt && (
        <div
          className="modal-backdrop"
          onClick={() => !restoreContactBusy && setRestoreContactPrompt(null)}
        >
          <section className="modal" onClick={(event) => event.stopPropagation()}>
            <h1>{t("chat.restoreAskContactTitle")}</h1>
            <p>{t("chat.restoreAskContactBody")}</p>
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => setRestoreContactPrompt(null)}
                disabled={restoreContactBusy}
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary"
                onClick={() => void restoreHistoryFromContact(restoreContactPrompt)}
                disabled={restoreContactBusy}
              >
                {t("chat.restoreAskContactConfirm")}
              </button>
            </div>
          </section>
        </div>
      )}
      {unverifiedDirect && directContact && (
        <div className="warning trust-banner">
          <span>
            {directContact.trust_status === "pending"
              ? t("contactRequests.incoming")
              : t("chat.unverifiedBanner")}
          </span>
          <div className="trust-banner-actions">
            <button onClick={() => setShowFingerprint((v) => !v)}>
              {showFingerprint ? t("chat.hideFingerprint") : t("chat.showFingerprint")}
            </button>
            <button onClick={() => setShowVerifyHelp((v) => !v)}>
              {t("chat.howToVerify")}
            </button>
            <button className="primary" onClick={trustDirect}>
              {t("chat.trust")}
            </button>
            {directContact.trust_status === "pending" && (
              <>
                <button onClick={rejectRequest}>
                  {t("contactRequests.reject")}
                </button>
                <button className="danger" onClick={blockContact}>
                  {t("common.block")}
                </button>
              </>
            )}
          </div>
          {showVerifyHelp && (
            <p className="hint trust-banner-help">{t("chat.howToVerifyHint")}</p>
          )}
          {showFingerprint && (
            <code className="fingerprint-reveal">{directContact.fingerprint}</code>
          )}
          {awaitingFirstContact && (
            <p className="hint trust-banner-help">{t("chat.awaitingFirstContact")}</p>
          )}
        </div>
      )}
      <div className="messages" ref={messagesContainerRef} onScroll={updateNearBottom}>
        {displayTimeline.map((item, index) => {
          const prevItem = index > 0 ? displayTimeline[index - 1] : null;
          const dividerLabel = formatDayDivider(item.at, prevItem?.at ?? null);
          if (item.kind === "callEnded") {
            return (
              <Fragment key={item.id}>
                {dividerLabel !== null && (
                  <div className="message-day-divider" role="separator">
                    <span>{dividerLabel}</span>
                  </div>
                )}
                <div className="message-system-event" role="status">
                  <span>{t("calls.chatEnded")}</span>
                </div>
              </Fragment>
            );
          }
          const message = item.message;
          const author = authorForMessage(message);
          const prev = prevItem?.kind === "message" ? prevItem.message : null;
          const nextItem = index < displayTimeline.length - 1 ? displayTimeline[index + 1] : null;
          const next = nextItem?.kind === "message" ? nextItem.message : null;
          const sameGroup = (a: ChatMessage, b: ChatMessage) => {
            const keyA = a.direction === "outbound" ? "out" : `in:${a.sender_public_key ?? ""}`;
            const keyB = b.direction === "outbound" ? "out" : `in:${b.sender_public_key ?? ""}`;
            if (keyA !== keyB) return false;
            const gap = Math.abs(Date.parse(b.created_at) - Date.parse(a.created_at));
            return Number.isFinite(gap) && gap <= 5 * 60 * 1000;
          };
          // A new day always opens a new series — even when 5-minute grouping
          // window would otherwise glue the new message onto the previous one.
          const isFirstInGroup =
            isSelfChat || !prev || !sameGroup(prev, message) || dividerLabel !== null;
          const isLastInGroup = isSelfChat || !next || !sameGroup(message, next);
          const rowClass = [
            "message-row",
            message.direction,
            message.attachment && !message.deleted_at ? "has-attachment" : "",
            isSelfChat ? "self-note" : "",
            isFirstInGroup ? "" : "continued",
            isLastInGroup ? "" : "no-meta",
          ]
            .filter(Boolean)
            .join(" ");
          const isOutbound = message.direction === "outbound";
          const hasBubbleContent = !!message.deleted_at || !!message.quote || !!message.text;
          return (
            <Fragment key={message.message_id}>
              {dividerLabel !== null && (
                <div className="message-day-divider" role="separator">
                  <span>{dividerLabel}</span>
                </div>
              )}
              <article
                className={rowClass}
                data-message-id={message.message_id}
                onPointerDown={
                  isQuotableMessage(message)
                    ? (event) => beginMessageLongPress(event, message.message_id)
                    : undefined
                }
                onPointerMove={
                  isQuotableMessage(message) ? trackMessageLongPressMove : undefined
                }
                onPointerUp={
                  isQuotableMessage(message) ? cancelMessageLongPress : undefined
                }
                onPointerCancel={
                  isQuotableMessage(message) ? cancelMessageLongPress : undefined
                }
                onPointerLeave={
                  isQuotableMessage(message) ? cancelMessageLongPress : undefined
                }
                onContextMenu={
                  isQuotableMessage(message)
                    ? (event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        setMessageMenu({
                          messageId: message.message_id,
                          x: event.clientX,
                          y: event.clientY,
                        });
                      }
                    : undefined
                }
              >
                {!isSelfChat && isFirstInGroup && (
                  <strong className="message-author">
                    <span
                      className={`message-author-name ${isOutbound ? "message-author-name--self" : ""}`}
                    >
                      {author.name}
                    </span>
                    <span className="message-author-time">{timeShort(message.created_at)}</span>
                  </strong>
                )}
                {!isSelfChat && (
                  <div className="message-avatar" aria-hidden="true">
                    {isFirstInGroup
                      ? isOutbound
                        ? (
                          <UserAvatar
                            displayName={profile.display_name}
                            avatarJpegBase64={profile.avatar_jpeg_base64}
                          />
                        )
                        : (
                          <UserAvatar
                            displayName={author.name}
                            avatarJpegBase64={author.avatarJpegBase64}
                          />
                        )
                      : ""}
                  </div>
                )}
                <div className="message-stack">
                  {message.attachment && !message.deleted_at && (
                    <MessageAttachmentView
                      message={message}
                      attachment={message.attachment}
                      canOpenMenu={
                        canEditOwnMessage(message)
                        || canDeleteOwnMessage(message)
                        || canSaveAttachment(message)
                        || canForwardAttachment(message)
                        || canShareAttachment(message)
                      }
                      onOpenMenu={(targetMessage, x, y) => {
                        setMessageMenu({
                          messageId: targetMessage.message_id,
                          x,
                          y,
                        });
                      }}
                      onOpenMedia={(attachment, url, posterUrl) => {
                        setMediaViewer({
                          attachment,
                          url,
                          posterUrl: posterUrl ?? null,
                          playing: attachment.media_kind !== "video",
                        });
                      }}
                      shouldSuppressClick={consumeLongPressClick}
                      onDecision={async (action) => {
                        try {
                          const updated =
                            action === "accept"
                              ? await api.acceptAttachment(
                                  message.message_id,
                                  message.attachment!.transfer_id,
                                )
                              : await api.declineAttachment(
                                  message.message_id,
                                  message.attachment!.transfer_id,
                                );
                          setMessages((prev) =>
                            prev.map((item) =>
                              item.message_id === updated.message_id ? updated : item,
                            ),
                          );
                        } catch {
                          showNotice(t("attachments.decisionFailed"));
                        }
                      }}
                      onTransfer={async (action) => {
                        try {
                          if (action === "resend") {
                            // A brand-new message (fresh ids/key); the old
                            // card stays a terminal tombstone.
                            const created = await api.resendAttachmentAsNew(message.message_id);
                            setMessages((prev) => [...prev, created]);
                            return;
                          }
                          const transferId = message.attachment!.transfer_id;
                          const updated =
                            action === "pause"
                              ? await api.pauseAttachmentTransfer(message.message_id, transferId)
                              : action === "resume"
                                ? await api.resumeAttachmentTransfer(
                                    message.message_id,
                                    transferId,
                                  )
                                : action === "cancel"
                                  ? await api.cancelAttachmentTransfer(
                                      message.message_id,
                                      transferId,
                                    )
                                  : await api.requestAttachmentTransfer(
                                      message.message_id,
                                      transferId,
                                    );
                          setMessages((prev) =>
                            prev.map((item) =>
                              item.message_id === updated.message_id ? updated : item,
                            ),
                          );
                        } catch {
                          showNotice(t("attachments.transferActionFailed"));
                        }
                      }}
                    />
                  )}
                  {hasBubbleContent && (
                    <div
                      className={`message-bubble${message.deleted_at ? " message-bubble--tombstone" : ""}`}
                    >
                      {message.deleted_at ? (
                        <p className="message-tombstone">
                          <em>{t("messageMenu.deletedPlaceholder")}</em>
                        </p>
                      ) : (
                        <>
                          {message.quote && (
                            <button
                              type="button"
                              className="message-quote-block"
                              onClick={(event) => {
                                event.stopPropagation();
                                const original = messagesRef.current.find(
                                  (item) => item.message_id === message.quote?.message_id,
                                );
                                if (!original) return;
                                const container = messagesContainerRef.current;
                                const node = container?.querySelector<HTMLElement>(
                                  `article[data-message-id="${CSS.escape(original.message_id)}"]`,
                                );
                                node?.scrollIntoView({ block: "center", behavior: "smooth" });
                              }}
                            >
                              <small className="message-quote-author">
                                {authorNameForPublicKey(message.quote.author_public_key)}
                              </small>
                              <span className="message-quote-text">{message.quote.excerpt}</span>
                            </button>
                          )}
                          {message.text && <p>{message.text}</p>}
                        </>
                      )}
                    </div>
                  )}
                  {!isSelfChat && isLastInGroup && (
                    <footer className="message-meta">
                      {message.edited_at && !message.deleted_at && (
                        <span className="message-edited-marker">
                          {t("messageMenu.editedMarker")}
                        </span>
                      )}
                      <MessageStatus
                        status={message.status}
                        direction={message.direction}
                        messageId={message.message_id}
                        transportLoadState={transportLoadState}
                        channelState={transportStatus?.channel_state}
                        deliveryDiagnostic={message.delivery_diagnostic}
                        onRetry={retryMessage}
                        attachmentUploading={
                          !message.message_id.startsWith("optimistic-") &&
                          !!message.attachment &&
                          (message.attachment.sent_bytes ?? 0) > 0 &&
                          (message.attachment.sent_bytes ?? 0) < message.attachment.size_bytes
                        }
                      />
                    </footer>
                  )}
                </div>
              </article>
            </Fragment>
          );
        })}
      </div>
      {error && <div className="error inline">{error}</div>}
      <MessageInput
        onSend={send}
        onSendAttachment={sendAttachment}
        onAttach={openUploadPlaceholder}
        onAttachmentTooLarge={(limitBytes) =>
          showNotice(t("attachments.tooLarge", { size: formatFileSize(limitBytes) }))
        }
        onComposerFocus={scrollToLatestMessage}
        quotePreview={quotePreview}
        onClearQuote={() => setQuoteTarget(null)}
      />
      {mediaViewer && (
        <div
          className="media-viewer-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label={mediaViewer.attachment.file_name}
          onClick={() => setMediaViewer(null)}
        >
          <button
            type="button"
            className="media-viewer-close"
            onClick={(event) => {
              event.stopPropagation();
              setMediaViewer(null);
            }}
            aria-label={t("common.close")}
            title={t("common.close")}
          >
            <X size={22} />
          </button>
          <div className="media-viewer" onClick={(event) => event.stopPropagation()}>
            {mediaViewer.attachment.media_kind === "video" && mediaViewer.playing ? (
              <video
                className="media-viewer-media"
                src={mediaViewer.url}
                controls
                autoPlay
                muted={prefs.videoAutoplayMuted}
                playsInline
              />
            ) : mediaViewer.attachment.media_kind === "video" ? (
              <button
                type="button"
                className="media-viewer-video-poster"
                onClick={() => {
                  setMediaViewer((current) =>
                    current ? { ...current, playing: true } : current,
                  );
                }}
                aria-label={mediaViewer.attachment.file_name}
              >
                {mediaViewer.posterUrl ? (
                  <img
                    className="media-viewer-media"
                    src={mediaViewer.posterUrl}
                    alt={mediaViewer.attachment.file_name}
                  />
                ) : (
                  <span className="media-viewer-video-fallback">
                    <Video size={42} />
                    <span>{mediaViewer.attachment.file_name}</span>
                    <small>{formatAttachmentSize(mediaViewer.attachment.size_bytes)}</small>
                  </span>
                )}
                <span className="media-viewer-play-badge" aria-hidden="true">
                  <Play size={30} fill="currentColor" />
                </span>
              </button>
            ) : (
              <img
                className="media-viewer-media"
                src={mediaViewer.url}
                alt={mediaViewer.attachment.file_name}
              />
            )}
          </div>
        </div>
      )}
      {messageMenu && (() => {
        const target = messagesRef.current.find(
          (item) => item.message_id === messageMenu.messageId,
        );
        const hasText = !!target?.text.trim();
        const hasAttachment = !!target?.attachment && !target.deleted_at;
        // A live (non-tombstoned) attachment on the row means this is a file
        // message: it gets the file menu (incl. local file-delete), and the
        // whole-message delete is suppressed so the two deletes don't mix.
        const hasLiveAttachment =
          !!target?.attachment && target.attachment.status !== "deleted" && !target.deleted_at;
        const canEdit = !!target && (hasText || hasAttachment) && canEditOwnMessage(target);
        const editLocked = canEdit && !!target && isEditLockedByLaterInbound(target);
        const canDelete = !!target && !hasLiveAttachment && canDeleteOwnMessage(target);
        return (
          <MessageContextMenu
            messageId={messageMenu.messageId}
            x={messageMenu.x}
            y={messageMenu.y}
            canCopy={hasText}
            canQuote={hasText}
            canEdit={canEdit}
            editLocked={editLocked}
            canDelete={canDelete}
            canSaveAttachment={!!target && canSaveAttachment(target)}
            canForward={!!target && canForwardAttachment(target)}
            canShare={!!target && canShareAttachment(target)}
            canResendAttachment={!!target && canResendAttachment(target)}
            canDeleteAttachment={!!target && canDeleteAttachmentLocal(target)}
            onAction={handleMessageMenuAction}
            onClose={() => setMessageMenu(null)}
          />
        );
      })()}
      {editTarget && (
        <div
          className="upload-placeholder-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="message-edit-title"
          onClick={cancelEdit}
        >
          <div className="upload-placeholder" onClick={(event) => event.stopPropagation()}>
            <button
              type="button"
              className="modal-close"
              onClick={cancelEdit}
              aria-label={t("common.close")}
            >
              <X size={18} />
            </button>
            <h2 id="message-edit-title">{t("messageMenu.editTitle")}</h2>
            <textarea
              className="message-edit-textarea"
              value={editDraft}
              autoFocus
              onChange={(event) => setEditDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                  event.preventDefault();
                  void submitEdit();
                }
                if (event.key === "Escape") {
                  event.preventDefault();
                  cancelEdit();
                }
              }}
              rows={4}
            />
            <div className="modal-actions">
              <button type="button" onClick={cancelEdit} disabled={editSaving}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary"
                onClick={() => void submitEdit()}
                disabled={editSaving || !editDraft.trim()}
              >
                {editSaving ? t("messageMenu.editSaving") : t("messageMenu.editSave")}
              </button>
            </div>
          </div>
        </div>
      )}
      {deleteTarget && (
        <div
          className="upload-placeholder-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="message-delete-title"
          onClick={() => (deleteSaving ? undefined : setDeleteTarget(null))}
        >
          <div className="upload-placeholder" onClick={(event) => event.stopPropagation()}>
            <h2 id="message-delete-title">{t("messageMenu.deleteTitle")}</h2>
            <p>{t("messageMenu.deleteConfirm")}</p>
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                disabled={deleteSaving}
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary danger"
                onClick={() => void submitDelete()}
                disabled={deleteSaving}
              >
                {deleteSaving ? t("messageMenu.deleting") : t("messageMenu.deleteConfirmBtn")}
              </button>
            </div>
          </div>
        </div>
      )}
      {deleteFileTarget && (
        <div
          className="upload-placeholder-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="attachment-delete-title"
          onClick={() => (deleteFileSaving ? undefined : setDeleteFileTarget(null))}
        >
          <div className="upload-placeholder" onClick={(event) => event.stopPropagation()}>
            <h2 id="attachment-delete-title">{t("attachments.deleteTitle")}</h2>
            <p>{t("attachments.deleteConfirm")}</p>
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => setDeleteFileTarget(null)}
                disabled={deleteFileSaving}
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary danger"
                onClick={() => void submitDeleteFile()}
                disabled={deleteFileSaving}
              >
                {deleteFileSaving ? t("attachments.deleting") : t("attachments.deleteConfirmBtn")}
              </button>
            </div>
          </div>
        </div>
      )}
      {forwardTarget && (
        <div
          className="upload-placeholder-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="attachment-forward-title"
          onClick={() => setForwardTarget(null)}
        >
          <div className="upload-placeholder forward-dialog" onClick={(event) => event.stopPropagation()}>
            <button
              type="button"
              className="modal-close"
              onClick={() => setForwardTarget(null)}
              aria-label={t("common.close")}
            >
              <X size={18} />
            </button>
            <h2 id="attachment-forward-title">{t("attachments.forwardTitle")}</h2>
            <input
              type="text"
              className="forward-search"
              value={forwardSearch}
              onChange={(event) => setForwardSearch(event.target.value)}
              placeholder={t("attachments.forwardSearch")}
              autoFocus
            />
            <div className="forward-chat-list">
              {forwardOptions.length === 0 ? (
                <p className="hint forward-empty">{t("attachments.forwardNoMatches")}</p>
              ) : (
                forwardOptions.map((option) => (
                  <button
                    key={option.id}
                    type="button"
                    className="forward-chat-item"
                    onClick={() => submitForward(option.id)}
                  >
                    <UserAvatar
                      displayName={option.name}
                      avatarJpegBase64={option.avatar}
                      className="forward-chat-avatar"
                    />
                    <span>{option.name}</span>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      )}
      {profileDialogLiveContact && (
        <ContactProfileDialog
          contact={profileDialogLiveContact}
          profileExtensions={profileDialogLiveContact.peer_profile_extensions}
          onClose={() => setProfileDialogContact(null)}
        />
      )}
      {statsDialogChat && (
        <ChatStatisticsDialog
          chat={statsDialogChat}
          onClose={() => setStatsDialogChat(null)}
        />
      )}
      {clearChatTarget && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="chat-clear-title"
          onClick={() => (clearChatSaving ? undefined : setClearChatTarget(null))}
        >
          <section className="modal chat-clear-dialog" onClick={(event) => event.stopPropagation()}>
            <h2 id="chat-clear-title">{t("chatHeaderMenu.clearTitle")}</h2>
            <p>{t("chatHeaderMenu.clearConfirm")}</p>
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => setClearChatTarget(null)}
                disabled={clearChatSaving}
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary danger"
                onClick={() => void submitClearChat()}
                disabled={clearChatSaving}
              >
                {clearChatSaving ? t("chatHeaderMenu.clearing") : t("chatHeaderMenu.clearConfirmButton")}
              </button>
            </div>
          </section>
        </div>
      )}
      {notice && <div className="toast feature-toast">{notice}</div>}
    </section>
  );
}
