import { type ReactNode, useEffect, useRef, useState } from "react";
import { ArrowLeft, Check, Trash2, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import type {
  AppStatus,
  FileLoggingStatus,
  MyProfile,
  NetworkRoutesStatus,
} from "../lib/types";
import { isDebugUi } from "../uiMode";
import { api } from "../lib/tauriApi";
import {
  callForceRelayDiagnosticEnabled,
  setCallForceRelayDiagnostic,
} from "../lib/callMedia";
import { BootstrapNodesView, visibleBootstrapRowCount } from "./BootstrapNodesView";
import { ProxySettingsView } from "./ProxyView";
import { PeerStatus } from "./PeerStatus";
import { useInputContextMenu } from "../lib/useInputContextMenu";
import { InputContextMenu } from "./InputContextMenu";
import { readSectionOpenFromStorage, writeSectionOpenToStorage } from "../lib/uiPrefs";

type Props = {
  profile: MyProfile;
  status: AppStatus;
  onRefresh: () => Promise<void>;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

type NetworkDisclosureProps = {
  /// Stable storage id — the open/closed state is remembered under it.
  sectionId: string;
  title: string;
  /// Rows inside the block; shown as a small badge next to the title when > 0,
  /// so a collapsed block still says whether there is anything in it.
  count?: number;
  children: ReactNode;
};

// Every block starts collapsed and then follows the remembered state: the page
// opens short, and whatever the user unfolded stays unfolded next time.
function NetworkDisclosure({ sectionId, title, count, children }: NetworkDisclosureProps) {
  const [open, setOpen] = useState(() => readSectionOpenFromStorage(sectionId));

  function toggle() {
    setOpen((current) => {
      writeSectionOpenToStorage(sectionId, !current);
      return !current;
    });
  }

  return (
    <section className={`settings-disclosure settings-accordion${open ? " open" : ""}`}>
      <button
        type="button"
        className="settings-disclosure-summary"
        aria-expanded={open}
        onClick={toggle}
      >
        <span>{title}</span>
        {count != null && count > 0 && (
          <span className="badge settings-disclosure-count">{count}</span>
        )}
        <span aria-hidden="true">{open ? "-" : "+"}</span>
      </button>
      {open && <div className="settings-disclosure-body">{children}</div>}
    </section>
  );
}

export function NetworkView({
  profile,
  status,
  onRefresh,
  showMobileBack,
  onMobileBack,
}: Props) {
  const { t } = useTranslation();
  const [multiaddr, setMultiaddr] = useState("");
  const [lanOnly, setLanOnly] = useState<boolean | null>(null);
  const [forceRelay, setForceRelay] = useState(callForceRelayDiagnosticEnabled());
  const [fileLog, setFileLog] = useState<FileLoggingStatus | null>(null);
  const [routes, setRoutes] = useState<NetworkRoutesStatus | null>(null);
  const [clearOutboxOpen, setClearOutboxOpen] = useState(false);
  const [clearingOutbox, setClearingOutbox] = useState(false);
  const [clearOutboxError, setClearOutboxError] = useState("");
  // Row counts for the collapsed-block badges; the blocks themselves own the
  // data and report how many rows they render.
  const [proxyCount, setProxyCount] = useState(0);
  const [nodeCount, setNodeCount] = useState(0);

  const multiaddrRef = useRef<HTMLInputElement>(null);
  const multiaddrMenu = useInputContextMenu();
  // One human-readable connection line for the release UI; the tile grid,
  // route chips and outbox counter below are debug-only diagnostics.
  const connectionSummary = (() => {
    if (status.p2p_node_status !== "running") return t("network.connOffline");
    if (lanOnly) return t("network.connLanOnly");
    if (status.reachability_status === "public") return t("network.connDirect");
    if (status.active_relay_reservations > 0) return t("network.connRelay");
    return t("network.connConnecting");
  })();
  const reachability =
    status.reachability_status === "public"
      ? t("peerStatus.reachabilityPublic")
      : status.reachability_status === "private"
        ? t("peerStatus.reachabilityPrivate")
        : t("peerStatus.reachabilityUnknown");

  useEffect(() => {
    api
      .getConnectPolicy()
      .then((policy) => setLanOnly(policy === "lan_only"))
      .catch(() => setLanOnly(false));
    api
      .getFileLoggingStatus()
      .then(setFileLog)
      .catch(() => setFileLog(null));
  }, []);

  // Route availability + live connection ids; refreshed while the page is
  // open so the checklist and node online dots track reality. The badge counts
  // ride along: a collapsed block must still show how many rows it holds, and
  // nodes can arrive on their own (learned from a contact, catalog exchange)
  // with no UI action to hang a refresh on.
  useEffect(() => {
    let alive = true;
    const refresh = () => {
      api
        .getNetworkRoutesStatus()
        .then((next) => {
          if (alive) setRoutes(next);
        })
        .catch(() => undefined);
      api
        .listProxies()
        .then((proxies) => {
          if (alive) setProxyCount(proxies.length);
        })
        .catch(() => undefined);
      api
        .listBootstrapNodes()
        .then((nodes) => {
          if (alive) setNodeCount(visibleBootstrapRowCount(nodes));
        })
        .catch(() => undefined);
    };
    refresh();
    const timer = window.setInterval(refresh, 10_000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  async function toggleFileLog(next: boolean) {
    try {
      await api.setFileLoggingEnabled(next);
      setFileLog(await api.getFileLoggingStatus());
    } catch {
      // keep the previous state on failure
    }
  }

  async function toggleLanOnly(next: boolean) {
    setLanOnly(next);
    try {
      await api.setConnectPolicy(next ? "lan_only" : "standard");
      await onRefresh();
    } catch {
      setLanOnly(!next);
    }
  }

  async function connect() {
    await api.connectPeer(multiaddr.trim());
    setMultiaddr("");
    await onRefresh();
  }

  async function clearOutbox() {
    setClearOutboxError("");
    setClearingOutbox(true);
    try {
      await api.clearOutbox();
      setClearOutboxOpen(false);
      await onRefresh();
    } catch (error) {
      setClearOutboxError(
        error instanceof Error ? error.message : t("network.clearOutboxFailed"),
      );
    } finally {
      setClearingOutbox(false);
    }
  }

  return (
    <div className="settings-view network-view">
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
            <h1>{t("network.title")}</h1>
            <small className="hint">{t("network.subtitle")}</small>
          </div>
        </div>
      </header>
      <div className="settings-content">
        <section className="settings-section network-overview">
          <h2>{t("network.overview")}</h2>
          <p className="network-connection-line">
            {t("network.connectionLabel")}: <strong>{connectionSummary}</strong>
          </p>
          <label className="checkbox-row">
            <input
              type="checkbox"
              role="switch"
              checked={lanOnly ?? false}
              onChange={(event) => toggleLanOnly(event.target.checked)}
              disabled={lanOnly === null}
            />
            {t("network.preferLanOnly")}
          </label>
          <p className="hint">{t("network.lanOnlyHint")}</p>
          {/* The stuck-queue escape hatch, in the release UI since 1.26.51.
              It only appears when something is actually parked: with an empty
              outbox there is nothing to explain and nothing to clear. */}
          {!isDebugUi && status.pending_outbox_count > 0 && (
            <>
              <p className="hint">
                {t("network.stuckOutboxLine", { count: status.pending_outbox_count })}
              </p>
              <div className="button-row">
                <button
                  type="button"
                  onClick={() => {
                    setClearOutboxError("");
                    setClearOutboxOpen(true);
                  }}
                >
                  <Trash2 size={14} aria-hidden="true" />
                  {t("network.clearStuck")}
                </button>
              </div>
            </>
          )}
          {isDebugUi && (
            <>
              <div className="network-summary">
                <div>
                  <span>{t("peerStatus.p2pNode")}</span>
                  <strong>{status.p2p_node_status === "running" ? "OK" : "STOP"}</strong>
                </div>
                <div>
                  <span>{t("peerStatus.reachability")}</span>
                  <strong>{reachability}</strong>
                </div>
                <div>
                  <span>{t("peerStatus.relayReservations")}</span>
                  <strong>{status.active_relay_reservations}</strong>
                </div>
                <div>
                  <span>{t("peerStatus.connectedPeers")}</span>
                  <strong>{status.connected_peers}</strong>
                </div>
                <div className="network-summary-outbox">
                  <span>{t("peerStatus.pendingOutbox")}</span>
                  <span className="network-summary-outbox-value">
                    <strong>{status.pending_outbox_count}</strong>
                    <button
                      type="button"
                      className="network-outbox-clear-btn"
                      onClick={() => {
                        setClearOutboxError("");
                        setClearOutboxOpen(true);
                      }}
                      disabled={status.pending_outbox_count === 0}
                      aria-label={t("network.clearOutbox")}
                      title={t("network.clearOutbox")}
                    >
                      <Trash2 size={18} strokeWidth={2} />
                    </button>
                  </span>
                </div>
              </div>
              <h3>{t("network.routesTitle")}</h3>
              <div className="network-routes">
                {(
                  [
                    ["LAN", routes?.lan ?? false],
                    [t("network.routeInternet"), routes?.internet ?? false],
                    ["TCP", routes?.direct_tcp ?? false],
                    ["QUIC", routes?.direct_quic ?? false],
                    ["WSS", routes?.direct_wss ?? false],
                    ["R-QUIC", routes?.relay_quic ?? false],
                    ["R-WSS", (routes?.relay_wss || routes?.relay_other) ?? false],
                    ["WebRTC", routes?.webrtc ?? false],
                  ] as Array<[string, boolean]>
                ).map(([label, up]) => (
                  <div key={label} className={`network-route${up ? " up" : ""}`}>
                    {up ? (
                      <Check size={14} aria-hidden="true" />
                    ) : (
                      <X size={14} aria-hidden="true" />
                    )}
                    <span>{label}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>

        {isDebugUi && (
          <NetworkDisclosure sectionId="network.manual" title={t("network.manualConnection")}>
            <section className="settings-section">
              <label>
                {t("network.peerMultiaddr")}
                <input
                  ref={multiaddrRef}
                  value={multiaddr}
                  onChange={(event) => setMultiaddr(event.target.value)}
                  {...multiaddrMenu.bind}
                />
                <InputContextMenu
                  position={multiaddrMenu.menuPosition}
                  onClose={multiaddrMenu.closeMenu}
                  inputRef={multiaddrRef}
                />
              </label>
              <button onClick={connect} disabled={!multiaddr.trim()}>
                {t("network.connectPeer")}
              </button>
            </section>
          </NetworkDisclosure>
        )}

        {isDebugUi && (
        <NetworkDisclosure sectionId="network.technical" title={t("network.technical")}>
          <section className="settings-section">
            <div className="profile-field">
              <label>{t("network.peerId")}</label>
              <code>{profile.peer_id}</code>
            </div>
            {isDebugUi && (
              <>
                <div className="profile-field">
                  <label>{t("network.listenAddresses")}</label>
                  <div className="addr-list">
                    {status.listen_addresses.length === 0 ? (
                      <small className="hint">{t("network.noListenAddresses")}</small>
                    ) : (
                      status.listen_addresses.map((addr) => <code key={addr}>{addr}</code>)
                    )}
                  </div>
                </div>
                <PeerStatus status={status} />
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={forceRelay}
                    onChange={(event) => {
                      setCallForceRelayDiagnostic(event.target.checked);
                      setForceRelay(event.target.checked);
                    }}
                  />
                  {t("network.forceRelayDiagnostic")}
                </label>
                <p className="hint">{t("network.forceRelayDiagnosticHint")}</p>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    role="switch"
                    checked={fileLog?.enabled ?? false}
                    disabled={fileLog === null}
                    onChange={(event) => void toggleFileLog(event.target.checked)}
                  />
                  {t("network.fileLog")}
                </label>
                <p className="hint">{t("network.fileLogHint")}</p>
                {fileLog?.enabled && fileLog.path && (
                  <p className="hint">
                    <code>{fileLog.path}</code>
                    {" · "}
                    {t("network.fileLogSize", {
                      size: (fileLog.total_bytes / (1024 * 1024)).toFixed(1),
                    })}
                  </p>
                )}
              </>
            )}
          </section>
        </NetworkDisclosure>
        )}

        {/* In the release UI since 1.26.19: a packet capture on 2026-07-26
            confirmed the fail-closed promise — with the proxy on, the only
            outbound connections were to the tunnel itself, including to a
            host that also runs a node the client knew the direct address of. */}
        <NetworkDisclosure sectionId="network.proxy" title={t("proxy.title")} count={proxyCount}>
          <ProxySettingsView status={status} onRefresh={onRefresh} />
        </NetworkDisclosure>

        <NetworkDisclosure
          sectionId="network.nodes"
          title={t("network.bootstrapAndBridges")}
          count={nodeCount}
        >
          <BootstrapNodesView
            onRefresh={onRefresh}
            status={status}
            connectedPeerIds={routes?.connected_peer_ids ?? []}
          />
        </NetworkDisclosure>
      </div>
      {clearOutboxOpen && (
        <div
          className="modal-backdrop"
          onClick={() => !clearingOutbox && setClearOutboxOpen(false)}
        >
          <section className="modal" onClick={(event) => event.stopPropagation()}>
            <h1>{t("network.clearOutboxTitle")}</h1>
            <p>{t("network.clearOutboxConfirm")}</p>
            {clearOutboxError && <div className="error">{clearOutboxError}</div>}
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => setClearOutboxOpen(false)}
                disabled={clearingOutbox}
              >
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="btn-destructive"
                onClick={clearOutbox}
                disabled={clearingOutbox}
              >
                {t("network.clearOutbox")}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
