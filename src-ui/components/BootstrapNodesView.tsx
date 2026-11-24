import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Ban, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useInputContextMenu } from "../lib/useInputContextMenu";
import { InputContextMenu } from "./InputContextMenu";
import type {
  AccessBundleImportResult,
  AccessBundleImportRow,
  AccessBundlePreview,
  AppStatus,
  BootstrapNetworkSummary,
  BootstrapNode,
  BootstrapNodeProbe,
  BootstrapNodeTestResult,
  CatalogIngestStats,
  NodePassportView,
  PeerCatalogIngest,
} from "../lib/types";
import { isDebugUi } from "../uiMode";
import { api } from "../lib/tauriApi";
import { dateTime, shortId } from "../lib/format";

type Props = {
  onRefresh: () => Promise<void>;
  status?: AppStatus | null;
  connectedPeerIds?: string[];
};

// "added" merges the former user-added and learned groups: to the user both
// are simply "ноды, добавленные вами вручную или полученные от контактов".
type GroupId = "official" | "added" | "privateBridge" | "blocked";

const GROUP_DEFS: Array<{ id: GroupId; match: (node: BootstrapNode) => boolean }> = [
  {
    id: "official",
    match: (n) => n.trust_level === "official" || n.trust_level === "official_seed",
  },
  {
    id: "added",
    match: (n) =>
      n.trust_level === "user_added" ||
      n.trust_level === "learned_from_verified_contact" ||
      n.trust_level === "learned_from_unverified_peer" ||
      n.trust_level === "local_mdns_learned",
  },
  {
    id: "privateBridge",
    match: (n) => n.trust_level === "private_bridge",
  },
  {
    id: "blocked",
    match: (n) => n.trust_level === "blocked" || !!n.blocked_at,
  },
];

// How many node rows this view actually renders for the current UI mode — the
// release UI hides the official group, and a blocked user-added node shows up
// in two groups, so this counts rendered rows, not distinct nodes. Used by the
// collapsed-block badge in NetworkView, which cannot ask the unmounted view.
export function visibleBootstrapRowCount(nodes: BootstrapNode[]): number {
  return GROUP_DEFS.reduce(
    (sum, def) =>
      !isDebugUi && def.id === "official" ? sum : sum + nodes.filter(def.match).length,
    0,
  );
}

// "/ip4/1.2.3.4/tcp/443/…" -> "1.2.3.4:443"; "/dns4/host/tcp/443/…" -> "host:443".
function nodeEndpoint(node: BootstrapNode): string {
  for (const addr of node.multiaddrs) {
    const parts = addr.split("/").filter(Boolean);
    let host = "";
    let port = "";
    for (let i = 0; i + 1 < parts.length; i += 2) {
      const key = parts[i];
      const value = parts[i + 1];
      if (key === "ip4" || key === "ip6" || key === "dns4" || key === "dns6" || key === "dns") {
        host = value;
      } else if (key === "tcp" || key === "udp") {
        port = value;
      }
    }
    if (host) return port ? `${host}:${port}` : host;
  }
  return shortId(node.peer_id, 10, 8);
}

type NodeTestState = {
  node: BootstrapNode;
  phase: "running" | "done";
  result?: BootstrapNodeTestResult;
  error?: string;
  passport?: NodePassportView;
};

export function BootstrapNodesView({ onRefresh, status, connectedPeerIds }: Props) {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<BootstrapNode[]>([]);
  const [multiaddr, setMultiaddr] = useState("");
  const [probe, setProbe] = useState<BootstrapNodeProbe | null>(null);
  const [probing, setProbing] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [catalogPath, setCatalogPath] = useState("");
  const [bundlePath, setBundlePath] = useState("");
  const [bundleText, setBundleText] = useState("");
  const [bundleComment, setBundleComment] = useState("");
  const [bundleImports, setBundleImports] = useState<AccessBundleImportRow[]>([]);
  const [networkSummary, setNetworkSummary] = useState<BootstrapNetworkSummary | null>(null);
  const [showRawAddresses, setShowRawAddresses] = useState(false);
  // Node passport: opened per node on explicit action only — the panel first
  // shows where the request would go, the fetch happens on a second click.
  const [passportNodeId, setPassportNodeId] = useState<string | null>(null);
  const [passport, setPassport] = useState<NodePassportView | null>(null);
  const [passportLoading, setPassportLoading] = useState(false);
  const [passportError, setPassportError] = useState("");
  // One action at a time: node tests / catalog requests wait out real network
  // timeouts, so the pressed button must show progress and repeat clicks must
  // not stack.
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const busyRef = useRef(false);
  const noticeRef = useRef<HTMLDivElement>(null);
  // Node reachability test runs inside its own modal: the old inline flow
  // scrolled the page around and gave no feedback until the timeout passed.
  const [nodeTest, setNodeTest] = useState<NodeTestState | null>(null);

  const multiaddrRef = useRef<HTMLInputElement>(null);
  const multiaddrMenu = useInputContextMenu();

  const bundleTextRef = useRef<HTMLTextAreaElement>(null);
  const bundleTextMenu = useInputContextMenu();

  function formatStats(stats: CatalogIngestStats): string {
    return t("bootstrap.stats", {
      accepted: stats.accepted,
      rejected: stats.rejected,
      inserted: stats.inserted,
      merged: stats.merged,
    });
  }

  function formatBundlePreview(preview: AccessBundlePreview): string {
    const parts = [
      t("bootstrap.bundlePreviewNetwork", { network: preview.network_id }),
      t("bootstrap.bundlePreviewExpires", { time: dateTime(preview.bundle_expires_at) }),
    ];
    if (preview.issuer_fingerprint) {
      parts.push(t("bootstrap.bundlePreviewIssuer", { fingerprint: preview.issuer_fingerprint }));
    }
    parts.push(
      t("bootstrap.bundlePreviewBridges", { count: preview.private_bridge_count }),
    );
    if (preview.expired) {
      parts.push(t("bootstrap.bundlePreviewExpired"));
    }
    return parts.join(" · ");
  }

  function formatBundleResult(result: AccessBundleImportResult): string {
    const parts: string[] = [];
    if (result.expired) {
      parts.push(t("bootstrap.bundleExpiredStored"));
    }
    if (result.issuer_fingerprint) {
      parts.push(t("bootstrap.bundlePreviewIssuer", { fingerprint: result.issuer_fingerprint }));
    }
    if (result.catalog_stats) {
      parts.push(t("bootstrap.bundleCatalog", { stats: formatStats(result.catalog_stats) }));
    }
    parts.push(
      t("bootstrap.bundleBridges", {
        accepted: result.bridges_accepted,
        rejected: result.bridges_rejected,
      }),
    );
    if (result.bridge_reasons.length > 0) {
      parts.push(result.bridge_reasons.slice(0, 6).join(", "));
    }
    return parts.join(" · ");
  }

  function describePeerResults(results: PeerCatalogIngest[]): string {
    if (results.length === 0) return t("bootstrap.noConnectedPeers");
    return results
      .map((r) =>
        r.error
          ? `${shortId(r.peer_id, 6, 6)}: ${r.error}`
          : `${shortId(r.peer_id, 6, 6)}: ${r.stats ? formatStats(r.stats) : t("common.noData")}`,
      )
      .join(" | ");
  }

  function nodeDisplayName(node: BootstrapNode): string {
    return node.public_meta?.name || node.node_name || shortId(node.peer_id, 10, 8);
  }

  function passportHost(node: BootstrapNode): string {
    try {
      return new URL(node.passport_reference?.url ?? "").host;
    } catch {
      return node.passport_reference?.url ?? "";
    }
  }

  function togglePassport(node: BootstrapNode) {
    setPassport(null);
    setPassportError("");
    setPassportNodeId((current) => (current === node.id ? null : node.id));
  }

  async function loadPassport(node: BootstrapNode) {
    setPassportError("");
    setPassportLoading(true);
    try {
      setPassport(await api.fetchNodePassport(node.id));
    } catch (err) {
      setPassportError(err instanceof Error ? err.message : t("bootstrap.actionFailed"));
    } finally {
      setPassportLoading(false);
    }
  }

  const publicBootstrapCount = useMemo(
    () =>
      nodes.filter(
        (n) =>
          !n.blocked_at &&
          (n.trust_level === "official" ||
            n.trust_level === "official_seed" ||
            n.trust_level === "official_updated" ||
            n.trust_level === "user_added"),
      ).length,
    [nodes],
  );

  const privateBridgeCount = useMemo(
    () => nodes.filter((n) => !n.blocked_at && n.trust_level === "private_bridge").length,
    [nodes],
  );

  const groups = useMemo(
    () =>
      GROUP_DEFS.map((def) => ({
        ...def,
        title:
          def.id === "official"
            ? t("bootstrap.groupOfficial")
            : def.id === "added"
              ? t("bootstrap.groupLearned")
              : def.id === "privateBridge"
                ? t("bootstrap.groupPrivateBridge")
                : t("bootstrap.groupBlocked"),
        description:
          def.id === "official"
            ? t("bootstrap.groupOfficialHint")
            : def.id === "added"
              ? t("bootstrap.groupLearnedHint")
              : def.id === "privateBridge"
                ? t("bootstrap.groupPrivateBridgeHint")
                : t("bootstrap.groupBlockedHint"),
      })),
    [t],
  );

  // Release-UI availability gauge: share of the nodes this client actually
  // dials that have a live connection right now. The set is the same one
  // `publicBootstrapCount` reports — official nodes AND the ones the user added
  // by hand, which used to be left out of the gauge entirely, so a user whose
  // own node was the only one online still saw an empty bar. Nodes learned from
  // peers stay out (the user did not choose them, and a pile of stale learned
  // addresses would drag the bar down for no reason), as do private bridges and
  // blocked nodes.
  const nodeAvailability = useMemo(() => {
    const dialed = nodes.filter(
      (n) =>
        !n.blocked_at &&
        (n.trust_level === "official" ||
          n.trust_level === "official_seed" ||
          n.trust_level === "official_updated" ||
          n.trust_level === "user_added"),
    );
    const connected = dialed.filter((n) => connectedPeerIds?.includes(n.peer_id)).length;
    const total = dialed.length;
    return {
      total,
      percent: total === 0 ? 0 : Math.round((connected / total) * 100),
    };
  }, [nodes, connectedPeerIds]);

  const isNodeOnline = (node: BootstrapNode) =>
    connectedPeerIds?.includes(node.peer_id) ?? false;

  async function load() {
    setNodes(await api.listBootstrapNodes());
    setBundleImports(await api.listAccessBundleImports());
    setNetworkSummary(await api.getBootstrapNetworkSummary());
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  async function run(action: () => Promise<unknown>, success?: string, key = "action") {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusyKey(key);
    setError("");
    setInfo("");
    try {
      const result = await action();
      if (success) setInfo(success);
      else if (typeof result === "string") setInfo(result);
      await load();
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("bootstrap.actionFailed"));
    } finally {
      busyRef.current = false;
      setBusyKey(null);
    }
  }

  // The status/error strip lives above the node groups; after an action on a
  // card far below it would land outside the viewport — bring it into view.
  useEffect(() => {
    if ((info || error) && noticeRef.current) {
      noticeRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [info, error]);

  async function runNodeTest(node: BootstrapNode) {
    if (nodeTest?.phase === "running") return;
    setNodeTest({ node, phase: "running" });
    try {
      const result = await api.testBootstrapNode(node.id);
      let passport: NodePassportView | undefined;
      if (isDebugUi && result.reachable && node.passport_reference) {
        try {
          passport = await api.fetchNodePassport(node.id);
        } catch {
          /* passport is best-effort debug info */
        }
      }
      setNodeTest({ node, phase: "done", result, passport });
    } catch (err) {
      setNodeTest({
        node,
        phase: "done",
        error: err instanceof Error ? err.message : t("bootstrap.actionFailed"),
      });
    }
    load().catch(() => undefined);
  }

  // "Check" step: dial the typed ip:port, learn the peer id + capabilities, and
  // show a preview the user confirms before the node is actually added.
  async function checkNode() {
    setError("");
    setInfo("");
    setProbe(null);
    setProbing(true);
    try {
      setProbe(await api.probeBootstrapNode(multiaddr.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("bootstrap.probeFailed"));
    } finally {
      setProbing(false);
    }
  }

  return (
    <section className="settings-section">
      <h2>{isDebugUi ? t("bootstrap.title") : t("bootstrap.connectNodeTitle")}</h2>
      {isDebugUi && <p className="hint">{t("bootstrap.hint")}</p>}

      {isDebugUi && networkSummary != null && (
        <p className="hint">
          {t("bootstrap.networkSummary", {
            public: networkSummary.public_bootstrap_count,
            private: networkSummary.private_bridge_count,
            peers: networkSummary.connected_peers,
          })}
          {networkSummary.last_successful_route
            ? ` · ${t("bootstrap.lastSuccessfulRoute", { route: networkSummary.last_successful_route })}`
            : ""}
          {` · ${networkSummary.connected ? t("bootstrap.networkConnected") : t("bootstrap.networkDisconnected")}`}
        </p>
      )}

      {isDebugUi && status != null && networkSummary == null && (
        <p className="hint">
          {t("bootstrap.networkSummary", {
            public: publicBootstrapCount,
            private: privateBridgeCount,
            peers: status.connected_peers,
          })}
        </p>
      )}

      {isDebugUi && (
        <p className="button-row" style={{ alignItems: "center", flexWrap: "wrap" }}>
          <button type="button" onClick={() => setShowRawAddresses(!showRawAddresses)}>
            {showRawAddresses ? t("bootstrap.hideRawAddresses") : t("bootstrap.showRawAddresses")}
          </button>
        </p>
      )}

      <label>
        {t("bootstrap.nodeAddress")}
        <input
          ref={multiaddrRef}
          value={multiaddr}
          onChange={(event) => {
            setMultiaddr(event.target.value);
            setProbe(null);
          }}
          placeholder={t("bootstrap.nodeAddressPlaceholder")}
          autoComplete="off"
          {...multiaddrMenu.bind}
        />
        <InputContextMenu
          position={multiaddrMenu.menuPosition}
          onClose={multiaddrMenu.closeMenu}
          inputRef={multiaddrRef}
        />
      </label>
      <p className="hint">{t("bootstrap.addByAddressHint")}</p>
      <div className="button-row">
        <button onClick={checkNode} disabled={!multiaddr.trim() || probing}>
          {probing ? t("bootstrap.checking") : t("bootstrap.checkNode")}
        </button>
        <button
          onClick={() => run(api.connectBootstrapNodes, t("bootstrap.connectAttempted"), "connectNodes")}
          disabled={nodes.length === 0 || busyKey !== null}
        >
          {busyKey === "connectNodes" ? t("common.loading") : t("bootstrap.connectNodes")}
        </button>
        {multiaddr.trim().startsWith("/") && (
          <button
            type="button"
            onClick={() =>
              run(async () => {
                await api.addBootstrapNode(multiaddr.trim(), "user_added");
                setMultiaddr("");
                setProbe(null);
              }, t("bootstrap.nodeAdded"))
            }
            disabled={busyKey !== null}
          >
            {t("bootstrap.addRawMultiaddr")}
          </button>
        )}
      </div>

      {probe && (
        <div className="bootstrap-node bootstrap-probe-preview">
          <div>
            <strong>{probe.agent_version || shortId(probe.peer_id, 10, 8)}</strong>
            <span>
              {probe.is_veyra_bootstrap
                ? t("bootstrap.probeIsVeyra")
                : t("bootstrap.probeNotVeyra")}
              {probe.supports_relay ? ` · ${t("bootstrap.probeRelay")}` : ""}
              {` · ${t("bootstrap.probeReachable")}`}
            </span>
          </div>
          <code>{shortId(probe.peer_id, 14, 10)}</code>
          {!probe.is_veyra_bootstrap && (
            <p className="warning">{t("bootstrap.probeNotVeyraWarning")}</p>
          )}
          <div className="button-row">
            <button
              onClick={() =>
                run(async () => {
                  await api.addProbedBootstrapNode(probe.multiaddr_with_peer);
                  setMultiaddr("");
                  setProbe(null);
                }, t("bootstrap.nodeAdded"))
              }
              disabled={busyKey !== null}
            >
              {t("bootstrap.addCheckedNode")}
            </button>
            <button type="button" onClick={() => setProbe(null)}>
              {t("common.cancel")}
            </button>
          </div>
        </div>
      )}

      {/* Percent and the bar only: the raw "2/5" underneath said nothing to a
          user who never learns what the five are. */}
      {!isDebugUi && nodeAvailability.total > 0 && (
        <div className="node-availability">
          <div className="node-availability-header">
            <span>{t("bootstrap.availability")}</span>
            <strong>{nodeAvailability.percent}%</strong>
          </div>
          <div className="node-availability-gauge" aria-hidden="true">
            <span style={{ width: `${nodeAvailability.percent}%` }} />
          </div>
        </div>
      )}

      {isDebugUi && (
        <>
      <h3>{t("bootstrap.catalogTitle")}</h3>
      <label>
        {t("bootstrap.catalogPath")}
        <input
          value={catalogPath}
          onChange={(event) => setCatalogPath(event.target.value)}
          placeholder={t("bootstrap.catalogPathPlaceholder")}
          autoComplete="off"
        />
      </label>
      <div className="button-row">
        <button
          onClick={() =>
            run(async () => {
              const count = await api.exportBootstrapCatalog(catalogPath.trim());
              return t("bootstrap.exportedRecords", { count });
            })
          }
          disabled={!catalogPath.trim() || busyKey !== null}
        >
          {t("bootstrap.exportCatalog")}
        </button>
        <button
          onClick={() =>
            run(async () => {
              const stats = await api.importBootstrapCatalog(catalogPath.trim());
              return t("bootstrap.importedStats", { stats: formatStats(stats) });
            })
          }
          disabled={!catalogPath.trim() || busyKey !== null}
        >
          {t("bootstrap.importCatalog")}
        </button>
        <button
          onClick={() =>
            run(async () => {
              const results = await api.requestBootstrapCatalogFromConnectedPeers();
              return t("bootstrap.peersSummary", { summary: describePeerResults(results) });
            }, undefined, "requestPeers")
          }
          disabled={busyKey !== null}
        >
          {busyKey === "requestPeers" ? t("common.loading") : t("bootstrap.requestFromPeers")}
        </button>
      </div>

      <h3>{t("bootstrap.bundleTitle")}</h3>
      <p className="hint">{t("bootstrap.bundleHint")}</p>
      <label>
        {t("bootstrap.bundleComment")}
        <input
          value={bundleComment}
          onChange={(event) => setBundleComment(event.target.value)}
          placeholder={t("bootstrap.bundleCommentPlaceholder")}
          autoComplete="off"
        />
      </label>
      <label>
        {t("bootstrap.bundlePath")}
        <input
          value={bundlePath}
          onChange={(event) => setBundlePath(event.target.value)}
          placeholder={t("bootstrap.bundlePathPlaceholder")}
          autoComplete="off"
        />
      </label>
      <label>
        {t("bootstrap.bundleText")}
        <textarea
          ref={bundleTextRef}
          value={bundleText}
          onChange={(event) => setBundleText(event.target.value)}
          placeholder={t("bootstrap.bundleTextPlaceholder")}
          rows={4}
          {...bundleTextMenu.bind}
        />
        <InputContextMenu
          position={bundleTextMenu.menuPosition}
          onClose={bundleTextMenu.closeMenu}
          inputRef={bundleTextRef}
        />
      </label>
      <div className="button-row">
        <button
          type="button"
          onClick={() =>
            run(async () => {
              const preview = await api.previewAccessBundle(bundlePath.trim());
              return formatBundlePreview(preview);
            })
          }
          disabled={!bundlePath.trim() || busyKey !== null}
        >
          {t("bootstrap.previewBundle")}
        </button>
        <button
          type="button"
          onClick={() =>
            run(async () => {
              const result = await api.importAccessBundle(
                bundlePath.trim(),
                bundleComment.trim() || null,
              );
              return t("bootstrap.bundleImported", { summary: formatBundleResult(result) });
            })
          }
          disabled={!bundlePath.trim() || busyKey !== null}
        >
          {t("bootstrap.importBundle")}
        </button>
        <button
          type="button"
          onClick={() =>
            run(async () => {
              const result = await api.importAccessBundleText(
                bundleText.trim(),
                bundleComment.trim() || null,
              );
              setBundleText("");
              return t("bootstrap.bundleImported", { summary: formatBundleResult(result) });
            })
          }
          disabled={!bundleText.trim() || busyKey !== null}
        >
          {t("bootstrap.importBundleText")}
        </button>
        <button
          type="button"
          onClick={() =>
            run(async () => {
              const count = await api.exportAccessBundle(bundlePath.trim());
              return t("bootstrap.bundleExported", { count });
            })
          }
          disabled={!bundlePath.trim() || busyKey !== null}
        >
          {t("bootstrap.exportBundle")}
        </button>
      </div>

      {bundleImports.length > 0 && (
        <div className="bootstrap-group">
          <h3>{t("bootstrap.bundleHistoryTitle")}</h3>
          <div className="bootstrap-node-list">
            {bundleImports.map((row) => (
              <div className="bootstrap-node" key={row.id}>
                <div>
                  <strong>{row.local_comment || shortId(row.id, 8, 6)}</strong>
                  <span>
                    {row.status}
                    {row.issuer_fingerprint ? ` · ${row.issuer_fingerprint}` : ""}
                  </span>
                </div>
                <small>
                  {t("bootstrap.bundleHistoryImported", { time: dateTime(row.imported_at) })}
                  {` · ${t("bootstrap.bundlePreviewExpires", { time: dateTime(row.bundle_expires_at) })}`}
                  {row.status === "expired" ? ` · ${t("bootstrap.bundlePreviewExpired")}` : ""}
                </small>
                <div className="button-row">
                  <button
                    type="button"
                    onClick={() => run(() => api.removeAccessBundleImport(row.id))}
                    disabled={busyKey !== null}
                  >
                    {t("bootstrap.removeBundleImport")}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
        </>
      )}

      <div ref={noticeRef}>
        {info && <p className="hint">{info}</p>}
        {error && <p className="error">{error}</p>}
      </div>

      {groups.map((group) => {
        // Release UI replaces the official-node list with the availability
        // gauge above; the nodes themselves stay debug-only inventory.
        if (!isDebugUi && group.id === "official") return null;
        const groupNodes = nodes.filter(group.match);
        if (groupNodes.length === 0) return null;
        return (
          <div key={group.id} className="bootstrap-group">
            <h3>
              {group.title} <span className="badge">{groupNodes.length}</span>
            </h3>
            <p className="hint">{group.description}</p>
            <div className="bootstrap-node-list">
              {groupNodes.map((node) => (
                <div className="bootstrap-node" key={node.id}>
                  <div>
                    <strong>{isDebugUi ? nodeDisplayName(node) : nodeEndpoint(node)}</strong>
                    <span
                      className={`node-online-dot${isNodeOnline(node) ? " online" : ""}`}
                      title={
                        isNodeOnline(node)
                          ? t("bootstrap.nodeOnline")
                          : t("bootstrap.nodeOffline")
                      }
                      aria-label={
                        isNodeOnline(node)
                          ? t("bootstrap.nodeOnline")
                          : t("bootstrap.nodeOffline")
                      }
                    />
                    {isDebugUi && (
                      <span>
                        {node.trust_level}
                        {node.source ? ` · ${node.source}` : ""}
                      </span>
                    )}
                  </div>
                  {isDebugUi && node.public_meta && (
                    <small>
                      {node.public_meta.title}
                      {node.public_meta.info ? ` · ${node.public_meta.info}` : ""}
                      {node.public_meta.url ? ` · ${node.public_meta.url}` : ""}
                    </small>
                  )}
                  {isDebugUi && showRawAddresses ? (
                    node.multiaddrs.map((address) => <code key={address}>{address}</code>)
                  ) : (
                    <code className="node-peer-id">{shortId(node.peer_id, 14, 10)}</code>
                  )}
                  {isDebugUi && (
                    <small>
                      {t("bootstrap.okFailed", { ok: node.success_count, failed: node.failure_count })}
                      {node.last_seen_at
                        ? ` · ${t("bootstrap.lastSeen", { time: dateTime(node.last_seen_at) })}`
                        : ""}
                      {node.expires_at
                        ? ` · ${t("bootstrap.expires", { time: dateTime(node.expires_at) })}`
                        : ""}
                    </small>
                  )}
                  {isDebugUi &&
                    (node.trust_level === "learned_from_verified_contact" ||
                      node.trust_level === "learned_from_unverified_peer" ||
                      node.trust_level === "local_mdns_learned") && (
                      <p className="warning">{t("bootstrap.learnedWarning")}</p>
                    )}
                  {isDebugUi && node.trust_level === "private_bridge" && (
                    <p className="warning">{t("bootstrap.privateBridgeWarning")}</p>
                  )}
                  {isDebugUi && node.passport_reference && passportNodeId === node.id && (
                    <div className="bootstrap-passport">
                      <p className="hint">
                        {t("bootstrap.passportFetchWarning", { host: passportHost(node) })}
                      </p>
                      {!passport && (
                        <div className="button-row">
                          <button
                            type="button"
                            disabled={passportLoading}
                            onClick={() => void loadPassport(node)}
                          >
                            {passportLoading ? t("common.loading") : t("bootstrap.passportLoad")}
                          </button>
                        </div>
                      )}
                      {passportError && <p className="error">{passportError}</p>}
                      {passport && (
                        <>
                          <strong>{passport.display_name}</strong>
                          {passport.description && <small>{passport.description}</small>}
                          <small>
                            {t("bootstrap.passportOperator")}: {passport.operator_kind}
                            {` · ${passport.visibility}`}
                            {passport.region
                              ? ` · ${t("bootstrap.passportRegion")}: ${passport.region}`
                              : ""}
                            {` · ${t("bootstrap.passportCapacity")}: ${passport.capacity_tier}`}
                          </small>
                          {passport.capabilities.length > 0 && (
                            <small>
                              {t("bootstrap.passportCapabilities")}: {passport.capabilities.join(", ")}
                            </small>
                          )}
                          <small>
                            {t("bootstrap.passportValidUntil", {
                              time: dateTime(passport.expires_at),
                            })}
                          </small>
                          <p className="hint">{t("bootstrap.passportSelfDeclared")}</p>
                        </>
                      )}
                    </div>
                  )}
                  <div className="button-row">
                    <button
                      onClick={() => void runNodeTest(node)}
                      disabled={nodeTest?.phase === "running"}
                    >
                      <Activity size={14} aria-hidden="true" />
                      {t("bootstrap.test")}
                    </button>
                    {isDebugUi && node.passport_reference && (
                      <button type="button" onClick={() => togglePassport(node)}>
                        {passportNodeId === node.id
                          ? t("bootstrap.passportHide")
                          : t("bootstrap.passportShow")}
                      </button>
                    )}
                    {group.id !== "blocked" && (
                      <button
                        className="btn-blue"
                        onClick={() =>
                          run(() => api.blockBootstrapNode(node.id), t("bootstrap.blocked"))
                        }
                        disabled={busyKey !== null}
                      >
                        <Ban size={14} aria-hidden="true" />
                        {t("bootstrap.block")}
                      </button>
                    )}
                    <button
                      className="danger"
                      onClick={() => run(() => api.removeBootstrapNode(node.id))}
                      disabled={busyKey !== null}
                    >
                      <Trash2 size={14} aria-hidden="true" />
                      {t("bootstrap.remove")}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {nodeTest && (
        <div
          className="modal-backdrop"
          onClick={() => nodeTest.phase === "done" && setNodeTest(null)}
        >
          <section
            className="modal node-test-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <h1>
              {nodeTest.phase === "running"
                ? t("bootstrap.testingTitle")
                : nodeTest.result?.reachable
                  ? t("bootstrap.testOkTitle")
                  : t("bootstrap.testOfflineTitle")}
            </h1>
            <p className="hint">
              {isDebugUi ? nodeDisplayName(nodeTest.node) : nodeEndpoint(nodeTest.node)}
            </p>
            {nodeTest.phase === "running" ? (
              <p>{t("bootstrap.testingBody")}</p>
            ) : nodeTest.result?.reachable ? (
              <p>
                {nodeTest.result.rtt_ms != null
                  ? t("bootstrap.testPing", { ms: nodeTest.result.rtt_ms })
                  : t("bootstrap.testOkTitle")}
              </p>
            ) : (
              <p>{t("bootstrap.testOfflineBody")}</p>
            )}
            {isDebugUi && nodeTest.phase === "done" && nodeTest.error && (
              <p className="error">{nodeTest.error}</p>
            )}
            {isDebugUi && nodeTest.passport && (
              <div className="node-test-passport">
                <strong>{nodeTest.passport.display_name}</strong>
                {nodeTest.passport.description && (
                  <small>{nodeTest.passport.description}</small>
                )}
                <small>
                  {t("bootstrap.passportOperator")}: {nodeTest.passport.operator_kind}
                  {` · ${nodeTest.passport.visibility}`}
                  {nodeTest.passport.region
                    ? ` · ${t("bootstrap.passportRegion")}: ${nodeTest.passport.region}`
                    : ""}
                  {` · ${t("bootstrap.passportCapacity")}: ${nodeTest.passport.capacity_tier}`}
                </small>
              </div>
            )}
            {nodeTest.phase === "done" && (
              <div className="modal-actions">
                <button type="button" onClick={() => setNodeTest(null)}>
                  {t("common.close")}
                </button>
              </div>
            )}
          </section>
        </div>
      )}
    </section>
  );
}
