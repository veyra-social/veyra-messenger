import {
  BatteryWarning,
  Menu,
  MessageSquare,
  Plus,
  Search,
  ShieldAlert,
  Waypoints,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { listen } from "@tauri-apps/api/event";
import iconLogo from "../assets/logos/Icon.png";
import type { AppStatus, Chat, Contact, MyProfile } from "../lib/types";
import { api } from "../lib/tauriApi";
import { UserAvatar } from "./UserAvatar";
import { ChatList } from "./ChatList";
import type { ChatMenuAction } from "./ChatContextMenu";
import { ContactRequests } from "./ContactRequests";
import { shortId } from "../lib/format";
import { useSteadyOnline } from "../lib/useSteadyOnline";

type Props = {
  profile: MyProfile;
  status: AppStatus;
  contacts: Contact[];
  chats: Chat[];
  selectedChatId: string | null;
  onSelectChat: (id: string) => void;
  onOpenMenu: () => void;
  onOpenProfile: () => void;
  onOpenAbout: () => void;
  onAddContact: () => void;
  onRefresh: () => Promise<void>;
  onChatMenuAction?: (chat: Chat, action: ChatMenuAction) => void;
  onOpenChat: (contactId: string) => Promise<void>;
};

type SelfPresence = "online" | "connecting" | "offline";

function selfPresence(status: AppStatus, steadyOnline: boolean): SelfPresence {
  if (steadyOnline) return "online";
  if (status.p2p_node_status === "running") return "connecting";
  return "offline";
}

export function Sidebar(props: Props) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [searchVisible, setSearchVisible] = useState(false);
  // "Device restricts background work" notice (vendor-parked round alarms).
  // Raised/cleared by the Rust detector; the close button hides it for this
  // session only — the flag itself clears when alarms turn healthy again.
  const [backgroundRestricted, setBackgroundRestricted] = useState(false);
  const [restrictionDismissed, setRestrictionDismissed] = useState(false);
  /// Tap-to-reveal tooltip for the proxy indicator (phones have no hover).
  const [proxyTip, setProxyTip] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    void api
      .getBackgroundRestrictionStatus()
      .then((restricted) => {
        if (!cancelled) setBackgroundRestricted(restricted);
      })
      .catch(() => {});
    const unlisten = listen<boolean>("background-restriction-changed", (event) => {
      setBackgroundRestricted(event.payload);
      if (event.payload) setRestrictionDismissed(false);
    });
    return () => {
      cancelled = true;
      void unlisten.then((fn) => fn());
    };
  }, []);

  const toggleSearch = () => {
    setSearchVisible((prev) => {
      const next = !prev;
      if (next) {
        setTimeout(() => {
          if (!window.matchMedia("(max-width: 800px)").matches) {
            searchInputRef.current?.focus();
          }
        }, 150);
      } else {
        setQuery("");
      }
      return next;
    });
  };

  useEffect(() => {
    if (!searchVisible) return;
    window.requestAnimationFrame(() => {
      sidebarRef.current
        ?.querySelector<HTMLElement>(".list")
        ?.scrollTo({ top: 0, behavior: "auto" });
    });
  }, [searchVisible, query]);

  const steadyOnline = useSteadyOnline(
    props.status.connected_peers > 0 || props.status.active_relay_reservations > 0,
  );
  const presence = selfPresence(props.status, steadyOnline);
  const presenceLabel =
    presence === "online"
      ? t("presence.online")
      : presence === "connecting"
        ? t("presence.connecting")
        : t("presence.offline");
  // Proxy mode replaces the presence lamp with an icon and nothing else: the
  // header line has no room for extra words, so "через прокси" lives in the
  // tooltip (hover on desktop, tap on the icon on phones).
  const proxyEnabled = props.status.proxy?.enabled ?? false;
  const proxyHealth = props.status.proxy?.health ?? "off";
  const proxyTipText =
    proxyHealth === "down" ? t("proxy.tipDown") : t("proxy.tipOn");
  useEffect(() => {
    if (!proxyTip) return;
    const timer = window.setTimeout(() => setProxyTip(false), 2500);
    return () => window.clearTimeout(timer);
  }, [proxyTip]);
  return (
    <aside className="sidebar" ref={sidebarRef}>
      <div className="sidebar-top">
        {/* Veyra-icon brand button. Tapping/clicking opens the About dialog,
            mirroring the burger-menu "About" entry. Used on both mobile and
            desktop — the full `veyra.social` wordmark moved into the About
            dialog itself (per Brandbook, full logo belongs on a "presentation"
            surface, not a tight chrome row). */}
        <button
          type="button"
          className="sidebar-brand-btn"
          onClick={props.onOpenAbout}
          title={t("menu.about")}
          aria-label={t("menu.about")}
        >
          <img src={iconLogo} alt="" aria-hidden="true" />
        </button>
        <button
          className="profile-tile"
          onClick={props.onOpenProfile}
          title={t("sidebar.openProfile")}
        >
          <UserAvatar
            className="avatar"
            displayName={props.profile.display_name}
            avatarJpegBase64={props.profile.avatar_jpeg_base64}
          />
          <span className="profile-meta">
            <strong className="profile-name">{props.profile.display_name}</strong>
            <span className={`profile-presence ${presence}`}>
              {proxyEnabled ? (
                <span
                  className={`proxy-indicator ${proxyHealth}`}
                  title={proxyTipText}
                  aria-label={proxyTipText}
                  onClick={(event) => {
                    // The whole tile opens the profile — the icon only shows
                    // its tooltip.
                    event.stopPropagation();
                    event.preventDefault();
                    setProxyTip((current) => !current);
                  }}
                >
                  <Waypoints size={13} strokeWidth={2.5} aria-hidden="true" />
                  {proxyTip && <span className="proxy-tip">{proxyTipText}</span>}
                </span>
              ) : (
                <span className={`presence-dot ${presence}`} aria-hidden="true" />
              )}
              {presenceLabel}
            </span>
          </span>
        </button>
        <button className="hamburger" onClick={props.onOpenMenu} title={t("sidebar.menu")}>
          <Menu size={20} />
        </button>
      </div>
      {(() => {
        const pendingRequests = props.contacts.filter(
          (contact) => contact.trust_status === "pending"
        );
        if (!pendingRequests.length) return null;
        return (
          <div className="compact-requests-list">
            <h3>
              <ShieldAlert size={14} aria-hidden="true" />
              {t("contactRequests.title")} ({pendingRequests.length})
            </h3>
            <div className="compact-requests-items">
              {pendingRequests.map((request) => {
                const isOnline = request.presence_status === "online";
                return (
                  <button
                    key={request.local_id}
                    className="compact-request-item"
                    type="button"
                    onClick={() => props.onOpenChat(request.local_id)}
                    title={t("contactRequests.incoming")}
                  >
                    <span className="request-avatar-wrap">
                      <UserAvatar
                        className="avatar-mini"
                        displayName={request.display_name}
                        avatarJpegBase64={request.peer_avatar_jpeg_base64}
                      />
                      <span className={`presence-dot ${isOnline ? "online" : "offline"}`} />
                    </span>
                    <span className="request-info">
                      <strong className="request-name">{request.display_name}</strong>
                      <small className="request-id">
                        {shortId(request.fingerprint, 12, 8)}
                      </small>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })()}
      {backgroundRestricted && !restrictionDismissed && (
        <div className="background-restricted-banner" role="status">
          <BatteryWarning size={16} aria-hidden="true" />
          <span className="background-restricted-text">
            <strong>{t("backgroundRestricted.title")}</strong>
            <small>{t("backgroundRestricted.body")}</small>
          </span>
          <button
            type="button"
            className="background-restricted-dismiss"
            onClick={() => setRestrictionDismissed(true)}
            aria-label={t("common.close")}
          >
            <X size={14} />
          </button>
        </div>
      )}
      <section>
        <div className="sidebar-section-title">
          <h2>
            <MessageSquare size={15} />
            {t("sidebar.chats")}
          </h2>
          <div className="sidebar-section-actions">
            <button
              type="button"
              className={`sidebar-search-toggle ${searchVisible ? "active" : ""}`}
              onClick={toggleSearch}
              title={t("sidebar.search")}
              aria-label={t("sidebar.search")}
            >
              <Search size={16} />
            </button>
            <button
              type="button"
              onClick={props.onAddContact}
              title={t("menu.addContact")}
              aria-label={t("menu.addContact")}
            >
              <Plus size={17} />
            </button>
          </div>
        </div>
        <label className={`chat-search ${searchVisible ? "visible" : ""}`}>
          <Search size={16} aria-hidden="true" />
          <input
            ref={searchInputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("sidebar.search")}
            autoComplete="off"
          />
        </label>
        <ChatList
          chats={props.chats}
          contacts={props.contacts}
          onAddContact={props.onAddContact}
          selectedChatId={props.selectedChatId}
          query={query}
          myDisplayName={props.profile.display_name}
          myAvatarJpegBase64={props.profile.avatar_jpeg_base64}
          onSelect={props.onSelectChat}
          onChatMenuAction={props.onChatMenuAction}
        />
      </section>
    </aside>
  );
}
