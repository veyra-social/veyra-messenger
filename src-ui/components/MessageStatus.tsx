import { AlertCircle, Check, CheckCheck, Clock, Loader2, RotateCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { outboundDeliveryStage } from "../lib/format";
import { isDebugUi } from "../uiMode";
import type { ChannelState, DeliveryDiagnostic, MessageStatus as Status } from "../lib/types";

type Props = {
  status: Status | string;
  direction?: "inbound" | "outbound" | string;
  messageId?: string;
  transportLoadState?: "loading" | "ready" | "error";
  channelState?: ChannelState | null;
  deliveryDiagnostic?: DeliveryDiagnostic | null;
  onRetry?: (messageId: string) => void;
  // The message envelope may already be delivered/read while the attachment
  // chunks are still streaming; while true, the transfer label overrides the
  // envelope statuses so the sender does not see "delivered" mid-transfer.
  attachmentUploading?: boolean;
};

function deliveryDetailKey(
  stage: ReturnType<typeof outboundDeliveryStage>,
  transportLoadState: Props["transportLoadState"],
  channelState?: ChannelState | null,
): string {
  if (stage !== "searchingTransport") return `messageStatus.detail.${stage}`;
  if (transportLoadState === "loading") return "messageStatus.detail.searchingRoutes";
  if (channelState === "none" || channelState === "unavailable") {
    return "messageStatus.detail.noRoute";
  }
  if (channelState === "unknown") return "messageStatus.detail.routeUnknown";
  return "messageStatus.detail.searchingRoutes";
}

export function MessageStatus({
  status,
  direction,
  messageId,
  transportLoadState = "ready",
  channelState,
  deliveryDiagnostic,
  onRetry,
  attachmentUploading = false,
}: Props) {
  const { t } = useTranslation();

  const retryEta = (() => {
    if (!deliveryDiagnostic?.next_retry_at) return null;
    const retryAt = Date.parse(deliveryDiagnostic.next_retry_at);
    if (!Number.isFinite(retryAt)) return null;
    const seconds = Math.ceil((retryAt - Date.now()) / 1000);
    if (seconds <= 0) return null;
    if (seconds < 60) return t("messageStatus.retryEta.seconds", { count: seconds });
    return t("messageStatus.retryEta.minutes", { count: Math.ceil(seconds / 60) });
  })();

  if (direction === "outbound" && messageId) {
    if (attachmentUploading && status !== "failed") {
      const title = t("messageStatus.detail.sendingFile");
      return (
        <span className="msg-status-row" title={title} aria-label={title}>
          {isDebugUi && (
            <span className="msg-status-label">{t("messageStatus.sendingFile")}</span>
          )}
          <span className="msg-status msg-status-pending spin" aria-hidden="true">
            <Loader2 size={12} />
          </span>
        </span>
      );
    }

    if (status === "read") {
      return (
        <span className="msg-status msg-status-read" title={t("messageStatus.detail.read")}>
          <CheckCheck size={12} />
        </span>
      );
    }

    if (status === "failed") {
      const title = t("messageStatus.detail.failed");
      return (
        <span className="msg-status-row" title={title} aria-label={title}>
          <span className="msg-status-label">{t("messageStatus.failed")}</span>
          <span className="msg-status msg-status-failed" aria-hidden="true">
            <AlertCircle size={12} />
          </span>
          {onRetry && (
            <button
              type="button"
              className="msg-status-retry"
              onClick={() => onRetry(messageId)}
              title={t("messageStatus.retry")}
              aria-label={t("messageStatus.retry")}
            >
              <RotateCw size={12} />
            </button>
          )}
        </span>
      );
    }

    if (deliveryDiagnostic?.state === "deferred") {
      // Every still-undelivered recipient has been unreachable for >24h and
      // the row is parked (wake-only). Calm clock, not an alarm: the message
      // is not failed - it delivers when the peer appears, and the retry
      // button re-activates it manually.
      const title = t("messageStatus.detail.deferred");
      return (
        <span className="msg-status-row" title={title} aria-label={title}>
          {isDebugUi && (
            <span className="msg-status-label">{t("messageStatus.deferred")}</span>
          )}
          <span className="msg-status msg-status-pending" aria-hidden="true">
            <Clock size={12} />
          </span>
          {onRetry && (
            <button
              type="button"
              className="msg-status-retry"
              onClick={() => onRetry(messageId)}
              title={t("messageStatus.retry")}
              aria-label={t("messageStatus.retry")}
            >
              <RotateCw size={12} />
            </button>
          )}
        </span>
      );
    }

    const baseStage = outboundDeliveryStage(status, messageId, transportLoadState, channelState);
    const stage: ReturnType<typeof outboundDeliveryStage> =
      deliveryDiagnostic?.state === "no_route"
        ? "searchingTransport"
        : deliveryDiagnostic?.next_retry_at
          ? "queued"
          : baseStage;
    if (stage === "hidden" || stage === "failed") return null;

    const label = t(`messageStatus.${stage}`);
    const showSpinner =
      stage === "preparing" ||
      stage === "queued" ||
      stage === "searchingTransport" ||
      stage === "sending";
    let title = t(deliveryDetailKey(stage, transportLoadState, channelState));
    if (deliveryDiagnostic?.state === "no_route") {
      title = retryEta
        ? t("messageStatus.detail.noRouteWithEta", { eta: retryEta })
        : t("messageStatus.detail.noRoute");
    } else if (deliveryDiagnostic?.state === "retrying") {
      title = retryEta
        ? t("messageStatus.detail.retryingWithEta", { eta: retryEta })
        : t("messageStatus.detail.retrying");
    }

    return (
      <span className="msg-status-row" title={title} aria-label={title}>
        {isDebugUi && <span className="msg-status-label">{label}</span>}
        {showSpinner ? (
          // A spinner, not a clock: every one of these phases means work is
          // happening right now (route hunt, dispatch, retry ladder). The
          // release UI used a static clock here and it read as "stuck" —
          // indistinguishable from the parked 'deferred' state above, which is
          // the only state that genuinely is waiting. The debug UI adds the
          // phase label next to it; the icon is the same.
          <span className="msg-status msg-status-pending spin" aria-hidden="true">
            <Loader2 size={12} />
          </span>
        ) : stage === "sent" ? (
          <span className="msg-status msg-status-sent" aria-hidden="true">
            <Check size={12} />
          </span>
        ) : (
          <span className="msg-status msg-status-delivered" aria-hidden="true">
            <CheckCheck size={12} />
          </span>
        )}
      </span>
    );
  }

  switch (status) {
    case "pending":
      return (
        <span className="msg-status msg-status-pending spin" title={t("messageStatus.pending")}>
          <Loader2 size={12} />
        </span>
      );
    case "sent":
      return (
        <span className="msg-status msg-status-sent" title={t("messageStatus.sent")}>
          <Check size={12} />
        </span>
      );
    case "delivered":
      return (
        <span className="msg-status msg-status-delivered" title={t("messageStatus.delivered")}>
          <CheckCheck size={12} />
        </span>
      );
    case "read":
      return (
        <span className="msg-status msg-status-read" title={t("messageStatus.read")}>
          <CheckCheck size={12} />
        </span>
      );
    case "failed":
      return (
        <span className="msg-status msg-status-failed" title={t("messageStatus.failed")}>
          <AlertCircle size={12} />
        </span>
      );
    default:
      return null;
  }
}
