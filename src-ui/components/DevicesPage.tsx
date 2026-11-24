import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  ArrowLeft,
  Check,
  Copy,
  Loader2,
  MonitorSmartphone,
  Pencil,
  Power,
  PowerOff,
  QrCode,
  RefreshCw,
  ScanLine,
  X,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import type { OwnDevice } from "../lib/types";
import { api } from "../lib/tauriApi";
import { copyTextToClipboard } from "../lib/clipboard";
import { InviteQrView } from "./InviteQrView";
import { QrScanner } from "./QrScanner";

type Props = {
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

type ActivePairing = {
  code: string;
  expiresAt: string;
};

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 12)}…` : value;
}

function formatSeen(value: string): string {
  if (!value) return "";
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "";
  return new Date(parsed).toLocaleString();
}

function formatExpiry(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "";
  return new Date(parsed).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// The backend refuses pairing with a machine reason; translate the ones the
// user can act on. The big one in the field: scanning a code shown by a
// DIFFERENT profile's device — pairing links devices of ONE profile only.
function pairErrorText(err: unknown, t: TFunction): string {
  const code =
    err && typeof err === "object" && "code" in err ? String((err as { code: unknown }).code) : "";
  const message =
    err && typeof err === "object" && "message" in err
      ? String((err as { message: unknown }).message)
      : "";
  if (code === "peer_not_reachable") return t("devices.errors.unreachable");
  if (code === "pairing_rejected") {
    if (message === "descriptor_rejected" || message === "descriptor_peer_mismatch") {
      return t("devices.errors.foreignProfile");
    }
    if (
      message === "no_active_pairing" ||
      message === "pairing_expired" ||
      message === "pairing_mismatch" ||
      message === "pairing_code_expired"
    ) {
      return t("devices.errors.staleCode");
    }
    if (message === "invalid_pairing_code") return t("devices.errors.notPairingCode");
    if (message === "self_pairing") return t("devices.errors.selfPair");
    return `${t("devices.pairFailed")} (${message})`;
  }
  return message ? `${t("devices.pairFailed")} (${message})` : t("devices.pairFailed");
}

export function DevicesPage({ showMobileBack, onMobileBack }: Props) {
  const { t } = useTranslation();
  const [devices, setDevices] = useState<OwnDevice[] | null>(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [pairing, setPairing] = useState<ActivePairing | null>(null);
  const [showQr, setShowQr] = useState(false);
  const [showJoin, setShowJoin] = useState(false);
  const [joinCode, setJoinCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [editingLabel, setEditingLabel] = useState<string | null>(null);
  const [savingLabel, setSavingLabel] = useState(false);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [syncMode, setSyncMode] = useState<string | null>(null);
  const [savingMode, setSavingMode] = useState(false);
  // Status of device-list actions (sync/toggle/rename). Rendered right under
  // the list: the shared error/success slot at the page bottom is off-screen
  // on the phone when the tapped button is at the top (field report).
  const [listNotice, setListNotice] = useState<{
    kind: "error" | "success";
    text: string;
  } | null>(null);

  const reload = useCallback(async () => {
    try {
      setDevices(await api.listOwnDevices());
      setSyncMode(await api.getDeviceSyncMode());
    } catch (err) {
      setListNotice({
        kind: "error",
        text: err instanceof Error ? err.message : t("devices.loadFailed"),
      });
    }
  }, [t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // The initiator side completes inside the backend when the other device
  // sends its pair request: close the QR and show the fresh list.
  useEffect(() => {
    const unlisten = listen("own-devices-changed", () => {
      setPairing(null);
      setShowQr(false);
      setSuccess(t("devices.paired"));
      void reload();
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, [reload, t]);

  const pairingLive = pairing !== null && Date.parse(pairing.expiresAt) > Date.now();

  // Slice 3.1: the code stops being accepted at its TTL anyway — fold the
  // UI at the same moment instead of showing a dead QR (the backend session
  // is also disarmed so the next "Show code" issues a fresh one).
  useEffect(() => {
    if (!pairing) return;
    const remaining = Date.parse(pairing.expiresAt) - Date.now();
    if (!Number.isFinite(remaining)) return;
    const timer = setTimeout(
      () => {
        setPairing(null);
        setShowQr(false);
        setSuccess(t("devices.codeExpired"));
        void api.cancelDevicePairing().catch(() => undefined);
      },
      Math.max(0, remaining) + 500,
    );
    return () => clearTimeout(timer);
  }, [pairing, t]);

  async function showPairingCode() {
    setError("");
    setSuccess("");
    try {
      if (pairingLive && pairing) {
        setShowQr(true);
        return;
      }
      const begin = await api.beginDevicePairing();
      setShowJoin(false);
      setPairing({ code: begin.code, expiresAt: begin.expires_at });
      setShowQr(true);
    } catch (err) {
      setError(pairErrorText(err, t));
    }
  }

  async function copyPairingCode() {
    if (!pairing) return;
    try {
      await copyTextToClipboard(pairing.code);
      setSuccess(t("devices.codeCopied"));
    } catch {
      setError(t("devices.pairFailed"));
    }
  }

  function cancelPairingCode() {
    setPairing(null);
    setShowQr(false);
    void api.cancelDevicePairing().catch(() => undefined);
  }

  async function submitJoinCode(code: string) {
    const trimmed = code.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    // Close the scanner right away: the camera must not keep re-scanning the
    // same code while the (up to ~25 s) pairing round-trip runs, and the busy
    // modal below is the visible state instead of a frozen-looking viewfinder.
    setShowJoin(false);
    setError("");
    setSuccess("");
    try {
      await api.completeDevicePairing(trimmed);
      setJoinCode("");
      setSuccess(t("devices.paired"));
      await reload();
    } catch (err) {
      setError(pairErrorText(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function toggleDevice(device: OwnDevice) {
    if (togglingId) return;
    setTogglingId(device.device_id);
    setListNotice(null);
    try {
      await api.setOwnDeviceEnabled(device.device_id, device.status !== "active");
      await reload();
    } catch (err) {
      setListNotice({
        kind: "error",
        text: err instanceof Error ? err.message : t("devices.loadFailed"),
      });
    } finally {
      setTogglingId(null);
    }
  }

  async function changeSyncMode(mode: string) {
    if (savingMode || mode === syncMode) return;
    setSavingMode(true);
    setListNotice(null);
    try {
      await api.setDeviceSyncMode(mode);
      setSyncMode(mode);
    } catch (err) {
      setListNotice({
        kind: "error",
        text: err instanceof Error ? err.message : t("devices.loadFailed"),
      });
    } finally {
      setSavingMode(false);
    }
  }

  async function syncDevice(device: OwnDevice) {
    if (syncingId) return;
    setSyncingId(device.device_id);
    setListNotice(null);
    try {
      const summary = await api.syncOwnDevice(device.device_id);
      const pulled = summary.pulled_applied;
      const pushed = summary.pushed_applied;
      if (pulled === 0 && pushed === 0) {
        setListNotice({ kind: "success", text: t("devices.syncNothing") });
      } else {
        setListNotice({ kind: "success", text: t("devices.syncDone", { pulled, pushed }) });
      }
      await reload();
    } catch (err) {
      const message =
        err && typeof err === "object" && "message" in err
          ? String((err as { message: unknown }).message)
          : "";
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "";
      if (code === "peer_not_reachable") {
        setListNotice({ kind: "error", text: t("devices.errors.syncUnreachable") });
      } else {
        setListNotice({
          kind: "error",
          text: message ? `${t("devices.syncFailed")} (${message})` : t("devices.syncFailed"),
        });
      }
    } finally {
      setSyncingId(null);
    }
  }

  async function saveLabel() {
    const trimmed = (editingLabel ?? "").trim();
    if (!trimmed || savingLabel) return;
    setSavingLabel(true);
    setListNotice(null);
    try {
      await api.renameOwnDevice(trimmed);
      setEditingLabel(null);
      await reload();
    } catch (err) {
      setListNotice({
        kind: "error",
        text: err instanceof Error ? err.message : t("devices.loadFailed"),
      });
    } finally {
      setSavingLabel(false);
    }
  }

  return (
    <div className="settings-view">
      <header className="settings-header">
        <div className="settings-header-row">
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
          <div className="settings-header-text">
            <h1>{t("devices.title")}</h1>
            <small className="hint">{t("devices.subtitle")}</small>
          </div>
        </div>
      </header>
      <div className="settings-content">
        <section className="settings-section">
          <h2>{t("devices.listTitle")}</h2>
          {!devices && !error && <small className="hint">{t("common.loading")}</small>}
          {devices?.map((device) => (
            <div key={device.device_id} className="device-row">
              <div className="device-row-main">
                <MonitorSmartphone size={18} />
                <div className="device-row-text">
                  {device.is_current && editingLabel !== null ? (
                    <div className="device-label-edit">
                      <input
                        type="text"
                        value={editingLabel}
                        maxLength={60}
                        autoFocus
                        onChange={(event) => setEditingLabel(event.target.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void saveLabel();
                          if (event.key === "Escape") setEditingLabel(null);
                        }}
                        aria-label={t("devices.renameLabel")}
                      />
                      <button
                        type="button"
                        disabled={savingLabel || !editingLabel.trim()}
                        onClick={() => void saveLabel()}
                        aria-label={t("common.save")}
                      >
                        {savingLabel ? <Loader2 size={14} className="spin" /> : <Check size={14} />}
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingLabel(null)}
                        aria-label={t("common.cancel")}
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ) : (
                    <strong>
                      {device.label || shortId(device.device_id)}
                      {device.is_current ? ` · ${t("devices.thisDevice")}` : ""}
                      {device.is_current && (
                        <button
                          type="button"
                          className="device-rename-btn"
                          onClick={() => setEditingLabel(device.label ?? "")}
                          aria-label={t("devices.renameLabel")}
                        >
                          <Pencil size={13} />
                        </button>
                      )}
                    </strong>
                  )}
                  <small className="hint">
                    {device.label ? `${shortId(device.device_id)} · ` : ""}
                    {shortId(device.device_peer_id)}
                    {device.app_version ? ` · Veyra ${device.app_version}` : ""}
                    {device.last_seen_at
                      ? ` · ${t("devices.lastSeen")}: ${formatSeen(device.last_seen_at)}`
                      : ""}
                  </small>
                  {device.status === "disabled_local" && (
                    <small className="hint">{t("devices.disabledBadge")}</small>
                  )}
                </div>
              </div>
              {!device.is_current && (
                <div className="button-row">
                  {device.status === "active" && (
                    <button
                      type="button"
                      disabled={syncingId !== null}
                      onClick={() => void syncDevice(device)}
                      aria-label={t("devices.syncNow")}
                      title={t("devices.syncNow")}
                    >
                      {syncingId === device.device_id ? (
                        <Loader2 size={14} className="spin" />
                      ) : (
                        <RefreshCw size={14} aria-hidden="true" />
                      )}
                      <span className="mobile-hidden-label">{t("devices.syncNow")}</span>
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={togglingId === device.device_id}
                    onClick={() => void toggleDevice(device)}
                    aria-label={
                      device.status === "active" ? t("devices.disable") : t("devices.enable")
                    }
                    title={
                      device.status === "active" ? t("devices.disable") : t("devices.enable")
                    }
                  >
                    {togglingId === device.device_id ? (
                      <Loader2 size={14} className="spin" />
                    ) : device.status === "active" ? (
                      <PowerOff size={14} aria-hidden="true" />
                    ) : (
                      <Power size={14} aria-hidden="true" />
                    )}
                    <span className="mobile-hidden-label">
                      {device.status === "active" ? t("devices.disable") : t("devices.enable")}
                    </span>
                  </button>
                </div>
              )}
            </div>
          ))}
          {listNotice && (
            <p className={listNotice.kind === "error" ? "error" : "hint"}>{listNotice.text}</p>
          )}
          {devices && devices.length <= 1 && (
            <>
              <small className="hint">{t("devices.emptyTitle")}</small>
              <small className="hint">{t("devices.emptyHint")}</small>
            </>
          )}
          <small className="hint">{t("devices.disableHint")}</small>
        </section>
        <section className="settings-section">
          <h2>{t("devices.syncModeTitle")}</h2>
          {/* Two modes, one of which is simply "not the other" — a switch says
              that better than a radio pair. The hint below states what happens
              in the state you are actually in, so both explanations stay. */}
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={syncMode === "nearby"}
              disabled={savingMode || syncMode === null}
              onChange={(event) => void changeSyncMode(event.target.checked ? "nearby" : "manual")}
            />
            {t("devices.syncModeNearby")}
          </label>
          <small className="hint">
            {syncMode === "nearby"
              ? t("devices.syncModeNearbyHint")
              : t("devices.syncModeManualHint")}
          </small>
        </section>
        <section className="settings-section">
          <h2>{t("devices.pairTitle")}</h2>
          <small className="hint">{t("devices.pairHint")}</small>
          <small className="hint">{t("devices.pairHintNote")}</small>
          <div className="button-row">
            <button type="button" onClick={() => void showPairingCode()}>
              <QrCode size={16} /> {t("devices.showCode")}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowJoin((prev) => !prev);
                setError("");
                setSuccess("");
              }}
            >
              <ScanLine size={16} /> {t("devices.scanCode")}
            </button>
          </div>
          {pairingLive && pairing && (
            <>
              <small className="hint">
                {t("devices.validUntil", { time: formatExpiry(pairing.expiresAt) })}
              </small>
              <div className="button-row">
                <button type="button" onClick={() => void copyPairingCode()}>
                  <Copy size={16} /> {t("devices.copyCode")}
                </button>
                <button type="button" onClick={cancelPairingCode}>
                  <X size={16} /> {t("devices.cancelCode")}
                </button>
              </div>
            </>
          )}
          {showJoin && (
            <>
              <QrScanner onScan={(text) => void submitJoinCode(text)} />
              <textarea
                value={joinCode}
                onChange={(event) => setJoinCode(event.target.value)}
                placeholder={t("devices.codePlaceholder")}
                rows={3}
              />
              <button
                type="button"
                disabled={busy || !joinCode.trim()}
                onClick={() => void submitJoinCode(joinCode)}
              >
                {busy ? <Loader2 size={14} className="spin" /> : t("devices.linkNow")}
              </button>
            </>
          )}
          {error && <p className="error">{error}</p>}
          {success && <p className="hint">{success}</p>}
        </section>
      </div>
      {showQr && pairing && (
        <InviteQrView
          value={pairing.code}
          onClose={() => setShowQr(false)}
          title={t("devices.qrTitle")}
          subtitle={t("devices.qrSubtitle")}
          hint={t("devices.qrHint")}
        />
      )}
      {busy && (
        <div className="modal-backdrop">
          <section
            className="modal"
            role="alertdialog"
            aria-busy="true"
            aria-label={t("devices.pairingInProgress")}
          >
            <h1>{t("devices.pairingInProgress")}</h1>
            <p className="pairing-progress-row">
              <Loader2 size={20} className="spin" aria-hidden="true" />
              {t("devices.pairingWait")}
            </p>
          </section>
        </div>
      )}
    </div>
  );
}
