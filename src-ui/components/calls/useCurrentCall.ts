import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { callMediaController } from "../../lib/callMedia";
import { api } from "../../lib/tauriApi";
import type {
  CallIceCandidatePayload,
  CallLogEntry,
  CallStateChangedPayload,
  CurrentCallSnapshot,
} from "../../lib/types";

export function useCurrentCall() {
  const [currentCall, setCurrentCall] = useState<CurrentCallSnapshot | null>(null);
  const [lastEndedCall, setLastEndedCall] = useState<CallLogEntry | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getCurrentCall()
      .then((call) => {
        if (!cancelled) setCurrentCall(call);
      })
      .catch(() => {
        if (!cancelled) setCurrentCall(null);
      });

    let unlistenCallState: (() => void) | undefined;
    let unlistenIce: (() => void) | undefined;
    void listen<CallStateChangedPayload>("call-state-changed", (event) => {
      setCurrentCall(event.payload.current ?? null);
      if (!event.payload.current) {
        callMediaController.cleanup(event.payload.ended?.call_id);
      }
      if (event.payload.ended) {
        setLastEndedCall(event.payload.ended);
      }
    }).then((fn) => {
      unlistenCallState = fn;
    });
    void listen<CallIceCandidatePayload>("call-ice-candidate", (event) => {
      void callMediaController.addRemoteIceCandidate(event.payload).catch(() => undefined);
    }).then((fn) => {
      unlistenIce = fn;
    });

    return () => {
      cancelled = true;
      unlistenCallState?.();
      unlistenIce?.();
    };
  }, []);

  return { currentCall, lastEndedCall };
}
