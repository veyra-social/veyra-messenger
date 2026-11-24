import { api } from "./tauriApi";
import {
  setSpeakerphone as nativeSetSpeakerphone,
  startCallAudio as nativeStartCallAudio,
  stopCallAudio as nativeStopCallAudio,
} from "./nativeBridge";
import type { CallIceCandidatePayload, RtcIceServerConfig } from "./types";

const FALLBACK_ICE_CONFIG: RTCConfiguration = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
};

// How long "connection lost" may persist before the call is ended locally.
// A remote hangup can only arrive over slow mailbox paths on hostile
// networks, and Chromium may sit in ICE "disconnected" without ever
// reaching "failed" — without this bound the overlay hangs indefinitely.
// 2026-07-16 field finding (intercontinental call, lossy path): ICE
// "disconnected" is a routine transient there and the browser recovers on
// its own well past the old 12 s bound — the grace was killing calls whose
// media path was still alive. 45 s rides out those blips; a genuinely dead
// path reaches ICE "failed" (which reports the failure immediately) or the
// remote hangup lands meanwhile.
const CONNECTION_LOST_GRACE_MS = 45_000;

function callMediaLog(message: string, level: "info" | "warn" = "info") {
  const line = `[veyra-call] ${message}`;
  if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
  void api.logCallMediaDiagnostic(level, line).catch(() => undefined);
}

const FORCE_RELAY_STORAGE_KEY = "veyra.callForceRelayDiagnostic";

// Field-diagnostic switch (Network -> Technical details): restrict call ICE
// to TURN relay pairs only, to answer whether relay pairs connect at all on
// the current network. Never enable by default - it removes the srflx
// hole-punch path that carries normal calls.
export function callForceRelayDiagnosticEnabled(): boolean {
  try {
    return localStorage.getItem(FORCE_RELAY_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

export function setCallForceRelayDiagnostic(enabled: boolean): void {
  try {
    if (enabled) {
      localStorage.setItem(FORCE_RELAY_STORAGE_KEY, "1");
    } else {
      localStorage.removeItem(FORCE_RELAY_STORAGE_KEY);
    }
  } catch {
    // Storage unavailable: the diagnostic simply stays off.
  }
}

async function callIceConfig(peerId: string): Promise<RTCConfiguration> {
  const forceRelay = callForceRelayDiagnosticEnabled();
  try {
    const iceServers = await api.getCallIceServers(peerId);
    if (iceServers.length > 0) {
      const kinds = iceServers.map((server) => iceServerKind(server)).join(",");
      const turnUrlCount = iceServers.reduce(
        (count, server) => count + server.urls.filter((url) => url.startsWith("turn:") || url.startsWith("turns:")).length,
        0,
      );
      callMediaLog(`ICE config prepared servers=${iceServers.length} kinds=${kinds} turnUrls=${turnUrlCount}`);
      if (forceRelay && turnUrlCount > 0) {
        callMediaLog("FORCE-RELAY diagnostic active: iceTransportPolicy=relay", "warn");
        return { iceServers: iceServers.map(toRtcIceServer), iceTransportPolicy: "relay" };
      }
      if (forceRelay) {
        callMediaLog("FORCE-RELAY requested but no TURN urls; using default policy", "warn");
      }
      return { iceServers: iceServers.map(toRtcIceServer) };
    }
  } catch {
    // Calls must still work on LAN/STUN-only paths if TURN discovery fails.
  }
  if (forceRelay) {
    callMediaLog("FORCE-RELAY requested but ICE config fell back to stun-only; using default policy", "warn");
  }
  callMediaLog("ICE config fallback=stun-only");
  return FALLBACK_ICE_CONFIG;
}

function iceServerKind(server: RtcIceServerConfig): string {
  if (server.urls.some((url) => url.startsWith("turn:") || url.startsWith("turns:"))) {
    return "turn";
  }
  if (server.urls.some((url) => url.startsWith("stun:") || url.startsWith("stuns:"))) {
    return "stun";
  }
  return "unknown";
}

function toRtcIceServer(server: RtcIceServerConfig): RTCIceServer {
  const rtcServer: RTCIceServer = { urls: server.urls };
  if (server.username != null) rtcServer.username = server.username;
  if (server.credential != null) rtcServer.credential = server.credential;
  return rtcServer;
}

function candidateType(candidate: string): string {
  return candidate.match(/ typ ([a-z]+)/)?.[1] ?? "unknown";
}

function iceUrlKind(url?: string | null): string {
  if (!url) return "unknown";
  if (url.startsWith("turns:")) return "turns";
  if (url.startsWith("turn:")) return "turn";
  if (url.startsWith("stuns:")) return "stuns";
  if (url.startsWith("stun:")) return "stun";
  return "unknown";
}

function statsNumber(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? String(Math.round(value)) : "-";
}

function statsDecimal(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(3) : "-";
}

function candidateStatsSummary(candidate?: RTCStats): string {
  if (!candidate) return "none";
  const stat = candidate as RTCStats & {
    candidateType?: string;
    protocol?: string;
    relayProtocol?: string;
    networkType?: string;
  };
  return [
    stat.candidateType ?? "unknown",
    stat.protocol ?? "",
    stat.relayProtocol ? `relay=${stat.relayProtocol}` : "",
    stat.networkType ? `net=${stat.networkType}` : "",
  ]
    .filter(Boolean)
    .join("/");
}

type LocalIceCandidate = {
  candidate: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
};

export type LocalMicrophoneInputState = "unknown" | "active" | "muted" | "silent";
export type CallSetupPhase =
  | "idle"
  | "checking_microphone"
  | "preparing_audio"
  | "finding_route"
  | "sending_invite"
  | "ringing_peer"
  | "answering"
  | "connecting_media"
  | "connected"
  | "connect_failed"
  | "connection_lost";

type LocalMicrophoneInputSnapshot = {
  state: LocalMicrophoneInputState;
};

type LocalMicrophoneInputListener = (snapshot: LocalMicrophoneInputSnapshot) => void;
type CallSetupPhaseListener = (phase: CallSetupPhase) => void;

class CallMediaController {
  private peerConnection: RTCPeerConnection | null = null;
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private remoteAudioElement: HTMLAudioElement | null = null;
  private callId: string | null = null;
  private peerId: string | null = null;
  private reportedIceOutcome = false;
  private localCandidateDispatchEnabled = false;
  private pendingLocalCandidates: LocalIceCandidate[] = [];
  private pendingRemoteCandidates: CallIceCandidatePayload[] = [];
  private mediaConnected = false;
  private reportedFailure = false;
  private statsTimer: number | null = null;
  private lostPhaseTimer: number | null = null;
  private muted = false;
  private speakerOn = false;
  private localMicrophoneInputState: LocalMicrophoneInputState = "unknown";
  private localMicrophoneInputListeners = new Set<LocalMicrophoneInputListener>();
  private setupPhase: CallSetupPhase = "idle";
  private setupPhaseListeners = new Set<CallSetupPhaseListener>();
  private silentInputStartedAt: number | null = null;

  setRemoteAudioElement(element: HTMLAudioElement | null) {
    this.remoteAudioElement = element;
    this.attachRemoteStream();
  }

  subscribeLocalMicrophoneInput(listener: LocalMicrophoneInputListener): () => void {
    this.localMicrophoneInputListeners.add(listener);
    listener({ state: this.localMicrophoneInputState });
    return () => {
      this.localMicrophoneInputListeners.delete(listener);
    };
  }

  subscribeSetupPhase(listener: CallSetupPhaseListener): () => void {
    this.setupPhaseListeners.add(listener);
    listener(this.setupPhase);
    return () => {
      this.setupPhaseListeners.delete(listener);
    };
  }

  setSetupPhase(phase: CallSetupPhase) {
    this.setSetupPhaseInternal(phase);
  }

  async prepareOutboundOffer(peerId: string): Promise<string> {
    this.reset();
    this.setSetupPhaseInternal("preparing_audio");
    this.localStream = await this.getLocalAudioStream();
    this.startNativeCallAudio();
    this.setSetupPhaseInternal("finding_route");
    this.peerConnection = await this.createPeerConnection(peerId);
    this.addLocalTracks();
    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);
    const sdp = this.peerConnection.localDescription?.sdp;
    if (!sdp) throw new Error("missing local offer SDP");
    this.setSetupPhaseInternal("sending_invite");
    return sdp;
  }

  async prepareInboundAnswer(peerId: string, callId: string, remoteOfferSdp: string): Promise<string> {
    const queuedRemoteCandidates = this.pendingRemoteCandidates.filter((candidate) => candidate.call_id === callId);
    this.reset();
    this.setSetupPhaseInternal("answering");
    this.callId = callId;
    this.pendingRemoteCandidates = queuedRemoteCandidates;
    this.localStream = await this.getLocalAudioStream();
    this.startNativeCallAudio();
    this.setSetupPhaseInternal("connecting_media");
    this.peerConnection = await this.createPeerConnection(peerId);
    await this.peerConnection.setRemoteDescription({
      type: "offer",
      sdp: remoteOfferSdp,
    });
    await this.flushRemoteCandidates();
    this.addLocalTracks();
    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);
    const sdp = this.peerConnection.localDescription?.sdp;
    if (!sdp) throw new Error("missing local answer SDP");
    return sdp;
  }

  bindCall(callId: string) {
    this.callId = callId;
    this.localCandidateDispatchEnabled = true;
    if (this.setupPhase !== "connected") {
      this.setSetupPhaseInternal("ringing_peer");
    }
    this.flushLocalCandidates();
  }

  async applyRemoteAnswer(callId: string, remoteAnswerSdp: string) {
    if (this.callId !== callId || !this.peerConnection) return;
    if (this.peerConnection.remoteDescription?.sdp === remoteAnswerSdp) return;
    this.setSetupPhaseInternal("connecting_media");
    await this.peerConnection.setRemoteDescription({
      type: "answer",
      sdp: remoteAnswerSdp,
    });
    await this.flushRemoteCandidates();
  }

  async addRemoteIceCandidate(payload: CallIceCandidatePayload) {
    if (this.callId && payload.call_id !== this.callId) return;
    if (!this.peerConnection || !this.peerConnection.remoteDescription) {
      callMediaLog(
        `remote ICE candidate queued type=${candidateType(payload.candidate)} hasPeerConnection=${!!this.peerConnection} hasRemoteDescription=${!!this.peerConnection?.remoteDescription}`,
      );
      this.pendingRemoteCandidates.push(payload);
      return;
    }
    await this.addRemoteCandidate(payload);
  }

  setMuted(muted: boolean) {
    this.muted = muted;
    this.localStream?.getAudioTracks().forEach((track) => {
      track.enabled = !muted;
    });
    this.silentInputStartedAt = null;
    this.setLocalMicrophoneInputState(muted ? "muted" : "unknown");
  }

  /** Whether the in-call route is currently the loudspeaker (Android only). */
  isSpeakerphoneOn(): boolean {
    return this.speakerOn;
  }

  /** Toggles the native in-call audio route between earpiece and loudspeaker. */
  setSpeakerphone(on: boolean): boolean {
    this.speakerOn = on;
    return nativeSetSpeakerphone(on);
  }

  // Hands the live call's audio to the native voice-call session (Android). The
  // route defaults to whatever the user last chose for this call (earpiece on a
  // fresh call). No-op on platforms without the native bridge.
  private startNativeCallAudio() {
    nativeStartCallAudio(this.speakerOn);
  }

  cleanup(callId?: string) {
    if (callId && this.callId && this.callId !== callId) return;
    this.reset();
  }

  private async getLocalAudioStream(): Promise<MediaStream> {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("media devices are not available");
    }
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  }

  private async createPeerConnection(peerId: string): Promise<RTCPeerConnection> {
    if (typeof RTCPeerConnection === "undefined") {
      throw new Error("WebRTC is not available");
    }
    this.peerId = peerId;
    const peerConnection = new RTCPeerConnection(await callIceConfig(peerId));
    peerConnection.onicecandidate = (event) => {
      if (!event.candidate) return;
      const candidate = event.candidate.toJSON();
      const rawCandidate = candidate.candidate ?? "";
      // Surface the candidate "type" (host/srflx/prflx/relay) into logcat so we
      // can confirm relay candidates were gathered when audio is missing.
      callMediaLog(`local ICE candidate type=${candidateType(rawCandidate)} sdpMid=${candidate.sdpMid ?? ""}`);
      this.queueOrSendLocalCandidate({
        candidate: rawCandidate,
        sdpMid: candidate.sdpMid ?? null,
        sdpMLineIndex: candidate.sdpMLineIndex ?? null,
      });
    };
    peerConnection.onicecandidateerror = (event) => {
      callMediaLog(
        `iceCandidateError server=${iceUrlKind(event.url)} code=${event.errorCode} text=${event.errorText ?? ""}`,
        "warn",
      );
    };
    peerConnection.oniceconnectionstatechange = () => {
      callMediaLog(`iceConnectionState=${peerConnection.iceConnectionState}`);
      if (peerConnection.iceConnectionState === "checking") {
        this.setSetupPhaseInternal("connecting_media");
      }
      if (peerConnection.iceConnectionState === "connected" || peerConnection.iceConnectionState === "completed") {
        this.setSetupPhaseInternal("connected");
        this.reportIceOutcome(true);
      }
      if (peerConnection.iceConnectionState === "disconnected" || peerConnection.iceConnectionState === "failed") {
        this.setLostPhase();
      }
      if (peerConnection.iceConnectionState === "failed") {
        this.reportIceOutcome(false);
      }
    };
    peerConnection.onicegatheringstatechange = () => {
      callMediaLog(`iceGatheringState=${peerConnection.iceGatheringState}`);
    };
    peerConnection.ontrack = (event) => {
      callMediaLog(`ontrack kind=${event.track.kind} streams=${event.streams.length}`);
      this.remoteStream = event.streams[0] ?? new MediaStream([event.track]);
      this.attachRemoteStream();
    };
    peerConnection.onconnectionstatechange = () => {
      const state = peerConnection.connectionState;
      callMediaLog(`connectionState=${state}`);
      if (state === "connected") {
        this.mediaConnected = true;
        this.setSetupPhaseInternal("connected");
        this.reportIceOutcome(true);
        return;
      }
      if (state === "connecting") {
        this.setSetupPhaseInternal("connecting_media");
      }
      if (state === "failed") {
        this.setLostPhase();
        this.reportIceOutcome(false);
        this.reportMediaFailure();
      }
    };
    this.startStatsPolling(peerConnection);
    return peerConnection;
  }

  private addLocalTracks() {
    if (!this.peerConnection || !this.localStream) return;
    this.localStream.getAudioTracks().forEach((track) => {
      this.peerConnection?.addTrack(track, this.localStream as MediaStream);
    });
  }

  private queueOrSendLocalCandidate(candidate: LocalIceCandidate) {
    if (!candidate.candidate.trim()) return;
    if (!this.callId || !this.localCandidateDispatchEnabled) {
      callMediaLog(`local ICE candidate queued type=${candidateType(candidate.candidate)}`);
      this.pendingLocalCandidates.push(candidate);
      return;
    }
    callMediaLog(`local ICE candidate dispatch type=${candidateType(candidate.candidate)}`);
    void api
      .sendCallIceCandidate(
        this.callId,
        candidate.candidate,
        candidate.sdpMid ?? null,
        candidate.sdpMLineIndex ?? null,
      )
      .catch(() => undefined);
  }

  private flushLocalCandidates() {
    const candidates = this.pendingLocalCandidates;
    this.pendingLocalCandidates = [];
    candidates.forEach((candidate) => this.queueOrSendLocalCandidate(candidate));
  }

  private async flushRemoteCandidates() {
    const candidates = this.pendingRemoteCandidates;
    this.pendingRemoteCandidates = [];
    for (const candidate of candidates) {
      await this.addRemoteCandidate(candidate);
    }
  }

  private async addRemoteCandidate(payload: CallIceCandidatePayload) {
    if (!this.peerConnection || !payload.candidate.trim()) return;
    const type = candidateType(payload.candidate);
    try {
      await this.peerConnection.addIceCandidate(
        new RTCIceCandidate({
          candidate: payload.candidate,
          sdpMid: payload.sdp_mid ?? null,
          sdpMLineIndex: payload.sdp_m_line_index ?? null,
        }),
      );
      callMediaLog(`remote ICE candidate added type=${type} sdpMid=${payload.sdp_mid ?? ""}`);
    } catch (err) {
      callMediaLog(
        `remote ICE candidate failed type=${type} error=${err instanceof Error ? err.message : String(err)}`,
        "warn",
      );
      throw err;
    }
  }

  private attachRemoteStream() {
    if (!this.remoteAudioElement) return;
    this.remoteAudioElement.srcObject = this.remoteStream;
    if (this.remoteStream) {
      void this.remoteAudioElement
        .play()
        .then(() => {
          callMediaLog("remote audio play started");
        })
        .catch((err) => {
          callMediaLog(
            `remote audio play failed error=${err instanceof Error ? err.message : String(err)}`,
            "warn",
          );
        });
    }
  }

  // Reports the first terminal ICE outcome of this peer connection to the
  // backend, so the Connection Manager's TURN health learns from real call
  // media results (Phase 7 slice 4). One report per connection: the setup
  // either reached a connected media path or it did not.
  private reportIceOutcome(connected: boolean) {
    if (this.reportedIceOutcome || !this.peerId || !this.callId) return;
    this.reportedIceOutcome = true;
    callMediaLog(`ice outcome reported connected=${connected}`);
    void api.reportCallMediaIceOutcome(this.peerId, this.callId, connected).catch(() => undefined);
  }

  // "Connection lost" is only honest after media actually connected once; a
  // setup that never connected reads as "could not connect audio" instead.
  private setLostPhase() {
    this.setSetupPhaseInternal(this.mediaConnected ? "connection_lost" : "connect_failed");
    this.armLostPhaseWatchdog();
  }

  private armLostPhaseWatchdog() {
    if (this.lostPhaseTimer !== null || !this.mediaConnected) return;
    this.lostPhaseTimer = window.setTimeout(() => {
      this.lostPhaseTimer = null;
      if (this.setupPhase !== "connection_lost" || !this.callId) return;
      callMediaLog("connection lost grace elapsed; ending call locally", "warn");
      this.reportMediaFailure();
    }, CONNECTION_LOST_GRACE_MS);
  }

  private clearLostPhaseWatchdog() {
    if (this.lostPhaseTimer !== null) {
      window.clearTimeout(this.lostPhaseTimer);
      this.lostPhaseTimer = null;
    }
  }

  private reportMediaFailure() {
    if (!this.callId || this.reportedFailure) return;
    this.reportedFailure = true;
    this.setLostPhase();
    const reason = this.mediaConnected ? "network_drop" : "dtls_timeout";
    void api.failCall(this.callId, reason).catch(() => undefined);
  }

  private startStatsPolling(peerConnection: RTCPeerConnection) {
    this.stopStatsPolling();
    this.statsTimer = window.setInterval(() => {
      void this.logStats(peerConnection).catch(() => undefined);
    }, 1000);
  }

  private stopStatsPolling() {
    if (this.statsTimer != null) {
      window.clearInterval(this.statsTimer);
      this.statsTimer = null;
    }
  }

  private async logStats(peerConnection: RTCPeerConnection) {
    if (this.peerConnection !== peerConnection) return;
    const report = await peerConnection.getStats();
    const stats = Array.from(report.values()) as Array<RTCStats & Record<string, unknown>>;
    const transport = stats.find((stat) => stat.type === "transport");
    const selectedPairId =
      typeof transport?.selectedCandidatePairId === "string"
        ? transport.selectedCandidatePairId
        : undefined;
    const selectedPair =
      (selectedPairId ? (report.get(selectedPairId) as (RTCStats & Record<string, unknown>) | undefined) : undefined) ??
      stats.find((stat) => stat.type === "candidate-pair" && stat.selected === true) ??
      stats.find((stat) => stat.type === "candidate-pair" && stat.nominated === true) ??
      stats.find((stat) => stat.type === "candidate-pair" && stat.state === "succeeded");
    const localCandidate =
      typeof selectedPair?.localCandidateId === "string"
        ? report.get(selectedPair.localCandidateId) as RTCStats | undefined
        : undefined;
    const remoteCandidate =
      typeof selectedPair?.remoteCandidateId === "string"
        ? report.get(selectedPair.remoteCandidateId) as RTCStats | undefined
        : undefined;
    const candidatePairs = stats.filter((stat) => stat.type === "candidate-pair");
    const pairStates = candidatePairs.reduce<Record<string, number>>((counts, pair) => {
      const state = typeof pair.state === "string" ? pair.state : "unknown";
      counts[state] = (counts[state] ?? 0) + 1;
      return counts;
    }, {});
    const pairStateSummary = Object.entries(pairStates)
      .map(([state, count]) => `${state}:${count}`)
      .join(",");
    const inboundAudio = stats.find((stat) => stat.type === "inbound-rtp" && stat.kind === "audio");
    const outboundAudio = stats.find((stat) => stat.type === "outbound-rtp" && stat.kind === "audio");
    const localAudioSource = stats.find((stat) => stat.type === "media-source" && stat.kind === "audio");
    this.updateLocalMicrophoneInputState(localAudioSource);
    callMediaLog(
      [
        "stats",
        `ice=${peerConnection.iceConnectionState}`,
        `conn=${peerConnection.connectionState}`,
        `dtls=${String(transport?.dtlsState ?? "-")}`,
        `pairState=${String(selectedPair?.state ?? "none")}`,
        `nominated=${String(selectedPair?.nominated ?? false)}`,
        `writable=${String(selectedPair?.writable ?? false)}`,
        `pairs=${pairStateSummary || "none"}`,
        `local=${candidateStatsSummary(localCandidate)}`,
        `remote=${candidateStatsSummary(remoteCandidate)}`,
        `rtt=${statsDecimal(selectedPair?.currentRoundTripTime)}`,
        `stunReqS=${statsNumber(selectedPair?.requestsSent)}`,
        `stunRespR=${statsNumber(selectedPair?.responsesReceived)}`,
        `stunReqR=${statsNumber(selectedPair?.requestsReceived)}`,
        `stunRespS=${statsNumber(selectedPair?.responsesSent)}`,
        `pairBytesS=${statsNumber(selectedPair?.bytesSent)}`,
        `pairBytesR=${statsNumber(selectedPair?.bytesReceived)}`,
        `rtpOutBytes=${statsNumber(outboundAudio?.bytesSent)}`,
        `rtpOutPackets=${statsNumber(outboundAudio?.packetsSent)}`,
        `rtpInBytes=${statsNumber(inboundAudio?.bytesReceived)}`,
        `rtpInPackets=${statsNumber(inboundAudio?.packetsReceived)}`,
        `rtpInLost=${statsNumber(inboundAudio?.packetsLost)}`,
        `rtpOutEnergy=${statsDecimal(outboundAudio?.totalAudioEnergy)}`,
        `rtpInEnergy=${statsDecimal(inboundAudio?.totalAudioEnergy)}`,
        `srcLevel=${statsDecimal(localAudioSource?.audioLevel)}`,
        `srcEnergy=${statsDecimal(localAudioSource?.totalAudioEnergy)}`,
        `srcDuration=${statsDecimal(localAudioSource?.totalSamplesDuration)}`,
      ].join(" "),
    );
  }

  private reset() {
    this.stopStatsPolling();
    this.clearLostPhaseWatchdog();
    nativeStopCallAudio();
    this.speakerOn = false;
    this.peerConnection?.close();
    this.localStream?.getTracks().forEach((track) => track.stop());
    if (this.remoteAudioElement) {
      this.remoteAudioElement.pause();
      this.remoteAudioElement.srcObject = null;
    }
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
    this.callId = null;
    this.peerId = null;
    this.reportedIceOutcome = false;
    this.localCandidateDispatchEnabled = false;
    this.pendingLocalCandidates = [];
    this.pendingRemoteCandidates = [];
    this.mediaConnected = false;
    this.reportedFailure = false;
    this.muted = false;
    this.silentInputStartedAt = null;
    this.setLocalMicrophoneInputState("unknown");
    this.setSetupPhaseInternal("idle");
  }

  private updateLocalMicrophoneInputState(localAudioSource?: RTCStats & Record<string, unknown>) {
    if (this.muted) {
      this.setLocalMicrophoneInputState("muted");
      return;
    }
    const audioLevel =
      typeof localAudioSource?.audioLevel === "number" && Number.isFinite(localAudioSource.audioLevel)
        ? localAudioSource.audioLevel
        : null;
    const totalAudioEnergy =
      typeof localAudioSource?.totalAudioEnergy === "number" && Number.isFinite(localAudioSource.totalAudioEnergy)
        ? localAudioSource.totalAudioEnergy
        : null;
    const totalSamplesDuration =
      typeof localAudioSource?.totalSamplesDuration === "number" && Number.isFinite(localAudioSource.totalSamplesDuration)
        ? localAudioSource.totalSamplesDuration
        : null;
    if (audioLevel == null && totalAudioEnergy == null) {
      this.silentInputStartedAt = null;
      this.setLocalMicrophoneInputState("unknown");
      return;
    }
    if ((audioLevel ?? 0) > 0 || (totalAudioEnergy ?? 0) > 0) {
      this.silentInputStartedAt = null;
      this.setLocalMicrophoneInputState("active");
      return;
    }
    if (totalSamplesDuration != null && totalSamplesDuration < 3) {
      this.setLocalMicrophoneInputState("unknown");
      return;
    }
    this.silentInputStartedAt ??= Date.now();
    if (Date.now() - this.silentInputStartedAt >= 5_000) {
      this.setLocalMicrophoneInputState("silent");
    }
  }

  private setLocalMicrophoneInputState(state: LocalMicrophoneInputState) {
    if (this.localMicrophoneInputState === state) return;
    this.localMicrophoneInputState = state;
    this.localMicrophoneInputListeners.forEach((listener) => listener({ state }));
  }

  private setSetupPhaseInternal(phase: CallSetupPhase) {
    // Media recovered (or the call moved on): the lost-phase deadline no
    // longer applies. `setLostPhase` re-arms it right after setting the
    // lost/failed phase.
    if (phase !== "connection_lost" && phase !== "connect_failed") {
      this.clearLostPhaseWatchdog();
    }
    if (this.setupPhase === phase) return;
    this.setupPhase = phase;
    this.setupPhaseListeners.forEach((listener) => listener(phase));
  }
}

export const callMediaController = new CallMediaController();
