import { useTranslation } from "react-i18next";
import type { AppStatus, ReachabilityStatus } from "../lib/types";

const REACHABILITY_GLYPH: Record<ReachabilityStatus, string> = {
  public: "●",
  private: "◐",
  unknown: "○",
};

function reachabilityLabel(status: ReachabilityStatus, t: (key: string) => string) {
  switch (status) {
    case "public":
      return t("peerStatus.reachabilityPublic");
    case "private":
      return t("peerStatus.reachabilityPrivate");
    default:
      return t("peerStatus.reachabilityUnknown");
  }
}

function connectPolicyLabel(policy: AppStatus["connect_policy"], t: (key: string) => string) {
  switch (policy) {
    case "standard":
      return t("peerStatus.policyStandard");
    case "lan_only":
      return t("peerStatus.policyLanOnly");
    default:
      return t("peerStatus.policyDegraded");
  }
}

export function PeerStatus({ status }: { status: AppStatus }) {
  const { t } = useTranslation();
  const reach = reachabilityLabel(status.reachability_status, t);
  return (
    <div className="peer-status">
      <div>
        <span>{t("peerStatus.p2pNode")}</span>
        <strong>{status.p2p_node_status}</strong>
      </div>
      <div>
        <span>{t("peerStatus.reachability")}</span>
        <strong title={reach}>
          <span aria-hidden>{REACHABILITY_GLYPH[status.reachability_status]} </span>
          {reach}
        </strong>
      </div>
      <div>
        <span>{t("peerStatus.connectPolicy")}</span>
        <strong>{connectPolicyLabel(status.connect_policy, t)}</strong>
      </div>
      <div>
        <span>{t("peerStatus.knownRoutes")}</span>
        <strong>{status.known_contact_routes}</strong>
      </div>
      <div>
        <span>{t("peerStatus.relayReservations")}</span>
        <strong>{status.active_relay_reservations}</strong>
      </div>
      <div>
        <span>{t("peerStatus.transports")}</span>
        <strong>{status.transport_protocols.join(", ") || t("common.noData")}</strong>
      </div>
      <div>
        <span>{t("peerStatus.connectedPeers")}</span>
        <strong>{status.connected_peers}</strong>
      </div>
      <div>
        <span>{t("peerStatus.pendingOutbox")}</span>
        <strong>{status.pending_outbox_count}</strong>
      </div>
    </div>
  );
}
