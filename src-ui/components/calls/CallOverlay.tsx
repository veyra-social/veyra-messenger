import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Check, Mic, MicOff, PhoneCall, PhoneOff, Volume2, VolumeX } from "lucide-react";
import { useTranslation } from "react-i18next";
import { callMediaController, type CallSetupPhase, type LocalMicrophoneInputState } from "../../lib/callMedia";
import { api } from "../../lib/tauriApi";
import type { CallLogEntry, Chat, Contact, CurrentCallSnapshot } from "../../lib/types";
import {
  detectMicrophoneAvailability,
  ensureMicrophoneAccess,
} from "../../lib/useMicrophoneAvailability";
import {
  isCallAudioRoutingAvailable,
  isNativeBridgeAvailable,
  openAppSettings,
} from "../../lib/nativeBridge";
import { silenceCallRingtone } from "../../lib/notificationSounds";
import {
  playCallProgressTone,
  stopCallProgressTone,
  type CallProgressTone,
} from "../../lib/callProgressSounds";
import { UserAvatar } from "../UserAvatar";

const CALL_TIMEOUT_MS = 90_000;
const ENDED_FLASH_MS = 1_500;

type Props = {
  currentCall: CurrentCallSnapshot | null;
  lastEndedCall: CallLogEntry | null;
  contacts: Contact[];
  chats: Chat[];
  onRefresh: () => Promise<void>;
};

type CallAction = "answer" | "reject" | "hangup" | "noMic" | "timeout";
type CallOverlayPhase = CallSetupPhase | "incoming";

function formatElapsed(seconds: number): string {
  const safeSeconds = Math.max(0, seconds);
  const h = Math.floor(safeSeconds / 3600);
  const m = Math.floor((safeSeconds % 3600) / 60);
  const s = safeSeconds % 60;
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  }
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function useElapsedSeconds(startedAt?: string | null): number {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!startedAt) {
      setElapsed(0);
      return;
    }
    const tick = () => {
      const start = Date.parse(startedAt);
      setElapsed(Number.isFinite(start) ? Math.floor((Date.now() - start) / 1000) : 0);
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [startedAt]);

  return elapsed;
}

function overlayPhaseForCall(
  call: CurrentCallSnapshot,
  setupPhase: CallSetupPhase,
  busyAction: CallAction | null,
): CallOverlayPhase {
  if (busyAction === "answer") return "answering";
  if (call.direction === "inbound" && call.state === "ringing") return "incoming";
  if (call.state === "connected") {
    if (setupPhase === "connected" || setupPhase === "connection_lost" || setupPhase === "connect_failed") {
      return setupPhase;
    }
    return "connecting_media";
  }
  return setupPhase === "idle" ? "finding_route" : setupPhase;
}

function phaseClassName(phase: CallOverlayPhase): string {
  switch (phase) {
    case "checking_microphone":
    case "preparing_audio":
      return "phase-low";
    case "finding_route":
    case "sending_invite":
      return "phase-mid";
    case "ringing_peer":
    case "answering":
    case "connecting_media":
    case "incoming":
      return "phase-high";
    case "connected":
      return "phase-done";
    case "connect_failed":
    case "connection_lost":
      return "phase-lost";
    default:
      return "phase-low";
  }
}

export function CallOverlay({ currentCall, lastEndedCall, contacts, chats, onRefresh }: Props) {
  const { t } = useTranslation();
  const [busyAction, setBusyAction] = useState<CallAction | null>(null);
  const [error, setError] = useState("");
  const [muted, setMuted] = useState(false);
  const [speakerOn, setSpeakerOn] = useState(false);
  const [localInputState, setLocalInputState] = useState<LocalMicrophoneInputState>("unknown");
  const [setupPhase, setSetupPhase] = useState<CallSetupPhase>("idle");
  const [endedFlash, setEndedFlash] = useState<CallLogEntry | null>(null);
  const endedFlashShownRef = useRef<string | null>(null);
  const speakerRoutingAvailable = isCallAudioRoutingAvailable();
  const autoNoMicCalls = useRef(new Set<string>());

  const activeOrEndedCall = currentCall ?? endedFlash;
  const peer = useMemo(
    () => contacts.find((contact) => contact.public_key === activeOrEndedCall?.peer_public_key) ?? null,
    [contacts, activeOrEndedCall?.peer_public_key],
  );
  const chat = useMemo(
    () => chats.find((entry) => entry.id === activeOrEndedCall?.chat_id) ?? null,
    [chats, activeOrEndedCall?.chat_id],
  );
  const displayName =
    peer?.display_name ||
    chat?.title ||
    (activeOrEndedCall ? t("calls.unknownPeer") : "");
  const elapsed = useElapsedSeconds(currentCall?.answered_at ?? currentCall?.started_at);

  // When the peer hangs up a live call, the backend ends the call and this
  // overlay would unmount mid-"connection lost" spinner. Show a short static
  // "call ended" state instead, then close without extra animation.
  useEffect(() => {
    if (currentCall) {
      setEndedFlash(null);
      return;
    }
    if (!lastEndedCall || lastEndedCall.end_reason !== "hangup_remote") return;
    if (endedFlashShownRef.current === lastEndedCall.call_id) return;
    endedFlashShownRef.current = lastEndedCall.call_id;
    setEndedFlash(lastEndedCall);
    const timer = window.setTimeout(() => setEndedFlash(null), ENDED_FLASH_MS);
    return () => window.clearTimeout(timer);
  }, [currentCall, lastEndedCall]);

  useEffect(() => {
    setError("");
    setBusyAction(null);
    setMuted(false);
    setSpeakerOn(false);
    setLocalInputState("unknown");
  }, [currentCall?.call_id]);

  // Setting up a call used to be silent, which reads as a dead line. The
  // phase — not `state === "calling"`, which exists before the microphone is
  // even checked — decides what is heard.
  const progressTone: CallProgressTone | null = useMemo(() => {
    if (!currentCall) return null;
    // Audio is flowing: from here the humans do the talking.
    if (
      setupPhase === "connected" ||
      setupPhase === "connection_lost" ||
      setupPhase === "connect_failed"
    ) {
      return null;
    }
    // The gap right after "Ответить" is the worst silence of the whole call:
    // the phone is already at the ear and the person is saying "алё" into a
    // line that is not up yet, with the "Соединяем звук" label somewhere
    // they cannot see. Both sides get the pulse here — the caller lands in
    // the same phase the moment the answer arrives.
    if (setupPhase === "answering" || setupPhase === "connecting_media") return "connecting";
    // An incoming call that is still ringing belongs to the ringtone.
    if (currentCall.direction !== "outbound") return null;
    if (currentCall.state === "connected") return null;
    if (setupPhase === "ringing_peer") return "ringback";
    // Everything between "the call exists" and "the peer is ringing" is
    // work in progress and gets the pulse. `idle` belongs here too: the
    // controller resets to it at the start of prepareOutboundOffer, and the
    // overlay's own label already treats that as route hunting — leaving it
    // silent punched a hole right before the first pulse.
    if (
      setupPhase === "idle" ||
      setupPhase === "preparing_audio" ||
      setupPhase === "finding_route" ||
      setupPhase === "sending_invite"
    ) {
      return "connecting";
    }
    // `checking_microphone` stays silent on purpose: a permission dialog may
    // be on screen and beeping under it is obnoxious.
    return null;
  }, [currentCall?.call_id, currentCall?.direction, currentCall?.state, setupPhase]);

  useEffect(() => {
    if (!currentCall || !progressTone) {
      stopCallProgressTone();
      return;
    }
    playCallProgressTone(currentCall.call_id, progressTone);
  }, [currentCall?.call_id, progressTone]);

  // Answered, ended, rejected, unmounted — every exit runs through here.
  useEffect(() => () => stopCallProgressTone(), []);

  // A call sheet has no text entry, so an open keyboard behind it is pure
  // damage: the layout reserves room for it and the sheet lands mid-screen
  // instead of on the bottom edge (field report from a Huawei phone). Drop
  // the focus that holds the keyboard open as soon as a call appears.
  useEffect(() => {
    if (!currentCall) return;
    const focused = document.activeElement;
    if (focused instanceof HTMLElement) focused.blur();
  }, [currentCall?.call_id]);

  useEffect(() => {
    return callMediaController.subscribeLocalMicrophoneInput((snapshot) => {
      setLocalInputState(snapshot.state);
    });
  }, []);

  useEffect(() => {
    return callMediaController.subscribeSetupPhase(setSetupPhase);
  }, []);

  useEffect(() => {
    if (!currentCall) return;
    if (
      currentCall.direction === "outbound" &&
      currentCall.state === "connected" &&
      currentCall.remote_sdp
    ) {
      void callMediaController
        .applyRemoteAnswer(currentCall.call_id, currentCall.remote_sdp)
        .catch((err) => {
          setError(err instanceof Error ? err.message : t("common.actionFailed"));
        });
    }
  }, [currentCall, t]);

  useEffect(() => {
    if (!currentCall) return;
    if (currentCall.state !== "calling" && currentCall.state !== "ringing") return;
    const callId = currentCall.call_id;
    const timer = window.setTimeout(() => {
      setBusyAction("timeout");
      api
        .timeoutCall(callId)
        .catch(() => undefined)
        .finally(() => {
          setBusyAction(null);
          void onRefresh().catch(() => undefined);
        });
    }, CALL_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [currentCall, onRefresh]);

  useEffect(() => {
    if (!currentCall || currentCall.direction !== "inbound" || currentCall.state !== "ringing") {
      return;
    }
    // Android can reliably report a permanently denied runtime permission and
    // offers a native Settings escape hatch. On macOS, a passive WebView check
    // can hide the first TCC prompt, so wait for an explicit Answer action.
    if (!isNativeBridgeAvailable()) return;
    if (autoNoMicCalls.current.has(currentCall.call_id)) return;
    let cancelled = false;
    detectMicrophoneAvailability().then((availability) => {
      if (cancelled || availability !== "unavailable") return;
      autoNoMicCalls.current.add(currentCall.call_id);
      setBusyAction("noMic");
      api
        .noMicrophoneCall(currentCall.call_id)
        .catch(() => undefined)
        .finally(() => {
          setBusyAction(null);
          void onRefresh().catch(() => undefined);
        });
    });
    return () => {
      cancelled = true;
    };
  }, [currentCall, onRefresh]);

  const runAction = useCallback(
    async (action: CallAction, fn: () => Promise<void>) => {
      if (!currentCall || busyAction) return;
      setBusyAction(action);
      setError("");
      try {
        await fn();
        await onRefresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : t("common.actionFailed"));
      } finally {
        setBusyAction(null);
      }
    },
    [busyAction, currentCall, onRefresh, t],
  );

  const answer = useCallback(() => {
    void runAction("answer", async () => {
      if (!currentCall) return;
      silenceCallRingtone(currentCall.call_id);
      const micResult = await ensureMicrophoneAccess();
      if (!micResult.ok) {
        // Notify peer first so the call ends cleanly on both sides, then
        // offer the user a path out of USER_FIXED RECORD_AUDIO state (system
        // dialog is suppressed; only the App-info deep-link works).
        await api.noMicrophoneCall(currentCall.call_id);
        if (micResult.denied && window.confirm(t("calls.openMicSettingsPrompt"))) {
          openAppSettings();
        }
        return;
      }
      if (!currentCall.remote_sdp) {
        throw new Error(t("common.actionFailed"));
      }
      if (!peer?.peer_id) {
        throw new Error(t("common.actionFailed"));
      }
      let answerSdp: string;
      try {
        answerSdp = await callMediaController.prepareInboundAnswer(
          peer.peer_id,
          currentCall.call_id,
          currentCall.remote_sdp,
        );
        await api.answerCall(currentCall.call_id, answerSdp);
        callMediaController.bindCall(currentCall.call_id);
      } catch (err) {
        callMediaController.cleanup(currentCall.call_id);
        throw err;
      }
    });
  }, [currentCall, peer?.peer_id, runAction, t]);

  const reject = useCallback(() => {
    void runAction("reject", async () => {
      if (currentCall) {
        callMediaController.cleanup(currentCall.call_id);
        await api.rejectCall(currentCall.call_id);
      }
    });
  }, [currentCall, runAction]);

  const hangup = useCallback(() => {
    void runAction("hangup", async () => {
      if (currentCall) {
        callMediaController.cleanup(currentCall.call_id);
        await api.hangupCall(currentCall.call_id);
      }
    });
  }, [currentCall, runAction]);

  const toggleMute = useCallback(() => {
    if (localInputState === "silent" && !muted) {
      callMediaController.setMuted(false);
      return;
    }
    const next = !muted;
    setMuted(next);
    callMediaController.setMuted(next);
  }, [localInputState, muted]);

  const toggleSpeaker = useCallback(() => {
    const next = !speakerOn;
    setSpeakerOn(next);
    callMediaController.setSpeakerphone(next);
  }, [speakerOn]);

  const setRemoteAudioElement = useCallback((element: HTMLAudioElement | null) => {
    callMediaController.setRemoteAudioElement(element);
  }, []);

  if (!currentCall) {
    if (!endedFlash) return null;
    return (
      <div className="call-overlay" role="dialog" aria-modal="true" aria-labelledby="call-overlay-title">
        <section className="call-panel">
          <div className="call-status-mark phase-done" aria-hidden="true">
            <Check size={24} />
          </div>
          <div className="call-avatar" aria-hidden="true">
            <UserAvatar displayName={displayName} avatarJpegBase64={peer?.peer_avatar_jpeg_base64} />
          </div>
          <div className="call-copy">
            <span className="call-state-label">{t("calls.result.ended")}</span>
            <h2 id="call-overlay-title">{displayName}</h2>
            <p>{formatElapsed(endedFlash.duration_seconds)}</p>
          </div>
        </section>
      </div>
    );
  }

  const isIncoming = currentCall.direction === "inbound" && currentCall.state === "ringing";
  const isConnected = currentCall.state === "connected";
  const overlayPhase = overlayPhaseForCall(currentCall, setupPhase, busyAction);
  const statusLabel = isIncoming
    ? t("calls.incoming")
    : isConnected
      ? t("calls.connected")
      : t("calls.outgoing");
  const phaseLabel = isConnected && overlayPhase === "connected"
    ? formatElapsed(elapsed)
    : t(`calls.phase.${overlayPhase}`);
  const primaryBusy = busyAction === "answer" || busyAction === "noMic";
  const secondaryBusy = busyAction === "reject" || busyAction === "hangup" || busyAction === "timeout";
  const localInputSilent = isConnected && localInputState === "silent" && !muted;
  const muteButtonLabel = muted
    ? t("calls.unmute")
    : localInputSilent
      ? t("calls.microphoneSilent")
      : t("calls.mute");
  const micButtonHealthy = !muted && !localInputSilent;
  const speakerButtonLabel = speakerOn ? t("calls.speakerOn") : t("calls.speakerOff");

  return (
    <div className="call-overlay" role="dialog" aria-modal="true" aria-labelledby="call-overlay-title">
      <section className="call-panel">
        <div
          className={`call-status-mark call-progress ${phaseClassName(overlayPhase)}`}
          aria-hidden="true"
        >
          {overlayPhase === "connected" ? (
            <Check size={24} />
          ) : isConnected ? (
            <Mic size={24} />
          ) : (
            <PhoneCall size={24} />
          )}
        </div>
        <div className="call-avatar" aria-hidden="true">
          <UserAvatar displayName={displayName} avatarJpegBase64={peer?.peer_avatar_jpeg_base64} />
        </div>
        <div className="call-copy">
          <span className="call-state-label">{statusLabel}</span>
          <h2 id="call-overlay-title">{displayName}</h2>
          <p>{phaseLabel}</p>
        </div>
        {error && <div className="error inline call-error">{error}</div>}
        <audio
          ref={setRemoteAudioElement}
          autoPlay
          playsInline
          className="call-remote-audio"
        />
        <div className="call-actions">
          {isIncoming ? (
            <>
              <button
                type="button"
                className="call-action call-action-danger"
                onClick={reject}
                disabled={!!busyAction}
              >
                <PhoneOff size={18} /> {secondaryBusy ? t("calls.ending") : t("calls.decline")}
              </button>
              <button
                type="button"
                className="call-action call-action-primary"
                onClick={answer}
                disabled={!!busyAction}
              >
                <PhoneCall size={18} /> {primaryBusy ? t("calls.connecting") : t("calls.answer")}
              </button>
            </>
          ) : (
            <>
              {isConnected && (
                <button
                  type="button"
                  className={`call-action call-action-icon call-action-toggle ${
                    micButtonHealthy ? "" : "is-alert"
                  }`}
                  onClick={toggleMute}
                  disabled={!!busyAction}
                  aria-label={muteButtonLabel}
                  aria-pressed={muted}
                  title={muteButtonLabel}
                >
                  {micButtonHealthy ? <Mic size={20} /> : <MicOff size={20} />}
                </button>
              )}
              {isConnected && speakerRoutingAvailable && (
                <button
                  type="button"
                  // Speaker off is a choice, not a fault: it used to wear the
                  // same amber "something is wrong" paint as a dead
                  // microphone. Now only "on" is coloured.
                  className={`call-action call-action-icon call-action-toggle ${
                    speakerOn ? "is-active" : ""
                  }`}
                  onClick={toggleSpeaker}
                  disabled={!!busyAction}
                  aria-label={speakerButtonLabel}
                  aria-pressed={speakerOn}
                  title={speakerButtonLabel}
                >
                  {speakerOn ? <Volume2 size={20} /> : <VolumeX size={20} />}
                </button>
              )}
              <button
                type="button"
                className="call-action call-action-danger"
                onClick={hangup}
                disabled={!!busyAction}
              >
                <PhoneOff size={18} /> {secondaryBusy ? t("calls.ending") : t("calls.end")}
              </button>
            </>
          )}
        </div>
        {localInputSilent && (
          <div className="call-local-mic-warning" role="status">
            <AlertTriangle size={16} aria-hidden="true" />
            <span>{t("calls.microphoneSilentHint")}</span>
          </div>
        )}
      </section>
    </div>
  );
}
