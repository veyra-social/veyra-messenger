import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { listen } from "@tauri-apps/api/event";
import type { AppStatus, Chat, Contact, MyProfile, NotificationPrefs } from "../lib/types";
import { useNarrowLayout } from "../lib/useNarrowLayout";
import { api } from "../lib/tauriApi";
import { Sidebar } from "./Sidebar";
import { ChatView } from "./ChatView";
import { SecurityView } from "./SecurityView";
import { ProfilePage } from "./ProfilePage";
import { ContactsPage } from "./ContactsPage";
import { AddContactPage } from "./AddContactPage";
import { HamburgerMenu } from "./HamburgerMenu";
import { ContactRequests } from "./ContactRequests";
import { InterfaceView } from "./InterfaceView";
import { NetworkView } from "./NetworkView";
import { DevicesPage } from "./DevicesPage";
import { NotificationsView } from "./NotificationsView";
import { AboutDialog } from "./AboutDialog";
import type { ChatMenuAction } from "./ChatContextMenu";
import { RenameChatDialog } from "./RenameChatDialog";
import { ConfirmDeleteChatDialog } from "./ConfirmDeleteChatDialog";
import { CallOverlay } from "./calls/CallOverlay";
import { useCurrentCall } from "./calls/useCurrentCall";
import { startCallRingtone, stopCallRingtone } from "../lib/notificationSounds";
import { playCallEndCue } from "../lib/callProgressSounds";
import { startCallHaptic, stopCallHaptic } from "../lib/haptics";

type Props = {
  profile: MyProfile;
  status: AppStatus;
  contacts: Contact[];
  chats: Chat[];
  selectedChat: Chat | null;
  selectedChatId: string | null;
  onSelectChat: (id: string | null) => void;
  onAdoptChat: (chat: Chat) => void;
  onRefresh: (options?: { includeProfile?: boolean }) => Promise<void>;
  onRefreshProfile: () => Promise<void>;
  onBackupImported: () => Promise<void>;
  onNotificationPrefsChanged: (prefs: NotificationPrefs) => void;
  onChatRead: (chatId: string) => void;
  onLocked: () => void;
};

type View =
  | "chat"
  | "security"
  | "profile"
  | "contacts"
  | "interface"
  | "network"
  | "notifications"
  | "devices"
  | "addContact";

type MobileSurface = "list" | "main";

// A genuinely ringing call is at most ~30s old (the CallOverlay no-answer
// timeout). On macOS the backend process outlives its window, so a stale
// ringing call can resurface from `getCurrentCall()` when a window reopens —
// the backend now expires those, but we never auto-play the ringtone for an
// old ringing snapshot here either, as a fail-closed last line of defense
// against the "music on startup" bug. The margin sits above the 30s frontend
// timeout but below the 60s backend deadline.
const RINGTONE_MAX_AGE_MS = 45_000;

function isFreshRingingCall(startedAt: string): boolean {
  const started = Date.parse(startedAt);
  // Fail closed: if we cannot prove the call is fresh, do not ring.
  if (!Number.isFinite(started)) return false;
  return Date.now() - started < RINGTONE_MAX_AGE_MS;
}

export function Layout(props: Props) {
  const { t } = useTranslation();
  const narrow = useNarrowLayout();
  const mobileShell = narrow;
  const [view, setView] = useState<View>("chat");
  const [mobileSurface, setMobileSurface] = useState<MobileSurface>("list");
  const [showMenu, setShowMenu] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  // One honest dialog per proxy outage: the id changes only when a working
  // proxy breaks, so a dead proxy never turns into a stream of pop-ups.
  const [shownProxyOutage, setShownProxyOutage] = useState<number | null>(null);
  const [renameChat, setRenameChatTarget] = useState<Chat | null>(null);
  const [deleteChat, setDeleteChatTarget] = useState<Chat | null>(null);
  const [callNotice, setCallNotice] = useState("");
  const [clockSkewNotice, setClockSkewNotice] = useState("");
  const { currentCall, lastEndedCall } = useCurrentCall();
  const shownEndedCallRef = useRef<string | null>(null);
  const playedEndCueCallRef = useRef<string | null>(null);

  // Backend-detected clock skew against the node median (see p2p::clock_skew):
  // the toast is the user-actionable half — signed protocol windows break
  // silently otherwise and everything just reads as "rejected".
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let hideTimeout: number | undefined;
    void listen<number>("clock-skew-warning", (event) => {
      const seconds = Math.abs(Math.round(event.payload));
      if (!Number.isFinite(seconds) || seconds <= 0) return;
      setClockSkewNotice(t("clockSkew.toast", { seconds }));
      if (hideTimeout !== undefined) window.clearTimeout(hideTimeout);
      hideTimeout = window.setTimeout(() => setClockSkewNotice(""), 15000);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
      if (hideTimeout !== undefined) window.clearTimeout(hideTimeout);
    };
  }, [t]);

  const goMain = useCallback(() => {
    if (mobileShell) setMobileSurface("main");
  }, [mobileShell]);

  useEffect(() => {
    if (mobileShell) {
      setMobileSurface("list");
    }
  }, [mobileShell]);

  useEffect(() => {
    if (
      currentCall?.direction === "inbound" &&
      currentCall.state === "ringing" &&
      isFreshRingingCall(currentCall.started_at)
    ) {
      startCallRingtone(currentCall.call_id);
      startCallHaptic(currentCall.call_id);
      return () => {
        stopCallRingtone(currentCall.call_id);
        stopCallHaptic(currentCall.call_id);
      };
    }
    stopCallRingtone();
    stopCallHaptic();
  }, [
    currentCall?.call_id,
    currentCall?.direction,
    currentCall?.state,
    currentCall?.started_at,
  ]);

  // The short beeps every phone plays when a call is over. They live here,
  // not in the call screen: that screen unmounts the moment the call ends,
  // and a cue owned by it would be cut off before it was heard.
  //
  // Silence for the endings you caused yourself — hanging up, declining, a
  // locked profile: on a real phone, putting the handset down makes no
  // sound, and the app already tells you what happened.
  useEffect(() => {
    if (!lastEndedCall || playedEndCueCallRef.current === lastEndedCall.call_id) return;
    playedEndCueCallRef.current = lastEndedCall.call_id;
    switch (lastEndedCall.end_reason) {
      // Nobody picked up, the line refused you: the classic "занято".
      case "busy_remote":
      case "reject_remote":
      case "no_answer":
      case "peer_offline":
      case "no_microphone_remote":
        playCallEndCue("busy");
        break;
      // The call really was up (or was trying to be) and it is over now.
      case "hangup_remote":
      case "network_drop":
      case "dtls_timeout":
      case "identity_mismatch":
      case "error":
        playCallEndCue("ended");
        break;
      default:
        break;
    }
  }, [lastEndedCall?.call_id, lastEndedCall?.end_reason]);

  useEffect(() => {
    if (!lastEndedCall || shownEndedCallRef.current === lastEndedCall.call_id) return;
    shownEndedCallRef.current = lastEndedCall.call_id;

    let message = "";
    switch (lastEndedCall.end_reason) {
      case "busy_remote":
        message = t("calls.result.busy");
        break;
      case "no_answer":
        if (lastEndedCall.direction === "outbound") {
          message = t("calls.result.noAnswer");
        }
        break;
      case "no_microphone_remote":
        message = t("calls.result.remoteNoMicrophone");
        break;
      case "peer_offline":
        message = t("calls.result.unreachable");
        break;
      case "network_drop":
      case "dtls_timeout":
      case "identity_mismatch":
        message = t("calls.result.connectionLost");
        break;
    }
    if (!message) return;

    setCallNotice(message);
    const timeout = window.setTimeout(() => setCallNotice(""), 3500);
    return () => window.clearTimeout(timeout);
  }, [lastEndedCall, t]);

  useEffect(() => {
    if (
      mobileShell &&
      mobileSurface === "main" &&
      view === "chat" &&
      !props.selectedChat &&
      !props.selectedChatId
    ) {
      setMobileSurface("list");
    }
  }, [mobileShell, mobileSurface, view, props.selectedChat, props.selectedChatId]);

  const backToChatList = useCallback(() => {
    setView("chat");
    if (mobileShell) setMobileSurface("list");
  }, [mobileShell]);

  const uiRef = useRef({
    showMenu,
    showAbout,
    showRenameChat: !!renameChat,
    showDeleteChat: !!deleteChat,
    narrow: mobileShell,
    mobileSurface,
    view,
    hasSelectedChat: !!props.selectedChat,
  });
  uiRef.current = {
    showMenu,
    showAbout,
    showRenameChat: !!renameChat,
    showDeleteChat: !!deleteChat,
    narrow: mobileShell,
    mobileSurface,
    view,
    hasSelectedChat: !!props.selectedChat,
  };

  const settersRef = useRef({
    setShowMenu,
    setShowAbout,
    setRenameChatTarget,
    setDeleteChatTarget,
    setMobileSurface,
    setView,
  });
  settersRef.current = {
    setShowMenu,
    setShowAbout,
    setRenameChatTarget,
    setDeleteChatTarget,
    setMobileSurface,
    setView,
  };

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    import("@tauri-apps/api/app")
      .then(({ onBackButtonPress }) =>
        onBackButtonPress(() => {
          const u = uiRef.current;
          const s = settersRef.current;
          if (u.showDeleteChat) {
            s.setDeleteChatTarget(null);
            return;
          }
          if (u.showRenameChat) {
            s.setRenameChatTarget(null);
            return;
          }
          if (u.showAbout) {
            s.setShowAbout(false);
            return;
          }
          if (u.showMenu) {
            s.setShowMenu(false);
            return;
          }
          const ae = document.activeElement;
          if (ae instanceof HTMLInputElement || ae instanceof HTMLTextAreaElement) {
            ae.blur();
            return;
          }
          if (u.narrow && u.mobileSurface === "main" && u.view === "chat" && u.hasSelectedChat) {
            s.setMobileSurface("list");
            return;
          }
          if (u.narrow && u.mobileSurface === "main" && u.view !== "chat") {
            s.setView("chat");
            s.setMobileSurface("list");
            return;
          }
        }),
      )
      .then((listener) => {
        if (cancelled) {
          listener.unregister().catch(() => undefined);
          return;
        }
        unlisten = () => listener.unregister().catch(() => undefined);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (view !== "profile") return;
    props.onRefreshProfile().catch(() => undefined);
  }, [view, props.onRefreshProfile]);

  async function lock() {
    await api.lockProfile();
    props.onLocked();
  }

  async function openChatWithContact(contactId: string) {
    const chat = await api.createDirectChat(contactId);
    props.onAdoptChat(chat);
    props.onSelectChat(chat.id);
    setView("chat");
    goMain();
  }

  const openAddContact = useCallback(() => {
    setView("addContact");
    goMain();
  }, [goMain]);

  const handleSelectChat = useCallback(
    (id: string) => {
      props.onSelectChat(id);
      setView("chat");
      goMain();
    },
    [goMain, props.onSelectChat],
  );

  // Selecting a contact-level action from the chat list context menu. Rename
  // and Delete pop their own confirmation dialogs; Block is fire-and-forget
  // because it's reversible from the Contacts page.
  const handleChatMenuAction = useCallback(
    async (chat: Chat, action: ChatMenuAction) => {
      if (action === "rename") {
        setRenameChatTarget(chat);
        return;
      }
      if (action === "delete") {
        setDeleteChatTarget(chat);
        return;
      }
      if (action === "block") {
        if (chat.chat_type !== "direct" || chat.is_self_chat) return;
        const directContact = props.contacts.find((contact) =>
          chat.member_contact_ids.includes(contact.local_id),
        );
        if (!directContact) return;
        try {
          await api.blockContact(directContact.local_id);
          await props.onRefresh();
        } catch (err) {
          console.error("block contact failed", err);
        }
        return;
      }
      if (action === "togglePin") {
        // Self-chat (Notes) is always sorted on top regardless of pinned_at,
        // so the menu doesn't expose pinning for it — defensive guard here too.
        if (chat.is_self_chat) return;
        const nextPinned = !chat.pinned_at;
        try {
          await api.setChatPinned(chat.id, nextPinned);
          await props.onRefresh();
        } catch (err) {
          console.error("set chat pinned failed", err);
        }
      }
    },
    [props.contacts, props.onRefresh],
  );

  const submitRename = useCallback(
    async (newTitle: string) => {
      if (!renameChat) return;
      if (!renameChat.is_self_chat) {
        const directContact = props.contacts.find((contact) =>
          renameChat.member_contact_ids.includes(contact.local_id),
        );
        if (!directContact) return;
        await api.renameContact(directContact.local_id, newTitle);
      } else {
        return;
      }
      setRenameChatTarget(null);
      await props.onRefresh();
    },
    [renameChat, props.contacts, props.onRefresh],
  );

  const submitDelete = useCallback(async () => {
    if (!deleteChat) return;
    const wasSelected = props.selectedChatId === deleteChat.id;
    await api.deleteChat(deleteChat.id);
    setDeleteChatTarget(null);
    if (wasSelected) {
      props.onSelectChat(null);
      if (mobileShell) setMobileSurface("list");
    }
    await props.onRefresh();
  }, [deleteChat, mobileShell, props.onRefresh, props.onSelectChat, props.selectedChatId]);

  function renameInitialTitle(chat: Chat): string {
    const directContact = props.contacts.find((contact) =>
      chat.member_contact_ids.includes(contact.local_id),
    );
    return directContact?.display_name ?? "";
  }

  const pendingContactRequests = props.contacts.filter(
    (contact) => contact.trust_status === "pending",
  );

  const shellClass =
    mobileShell && mobileSurface === "main"
      ? "app-shell phone-shell mobile-main"
      : mobileShell
        ? "app-shell phone-shell mobile-list"
        : "app-shell desktop-shell";
  const renderChatView = !mobileShell || mobileSurface === "main";

  return (
    <div className={shellClass}>
      {showMenu ? (
        <HamburgerMenu
          onClose={() => setShowMenu(false)}
          contactRequests={pendingContactRequests}
          onRequestsChanged={props.onRefresh}
          onProfile={() => {
            setView("profile");
            goMain();
          }}
          onContacts={() => {
            setView("contacts");
            goMain();
          }}
          onSecurity={() => {
            setView("security");
            goMain();
          }}
          onNotifications={() => {
            setView("notifications");
            goMain();
          }}
          onDevices={() => {
            setView("devices");
            goMain();
          }}
          onNetwork={() => {
            setView("network");
            goMain();
          }}
          onInterface={() => {
            setView("interface");
            goMain();
          }}
          onAbout={() => setShowAbout(true)}
          onLock={lock}
        />
      ) : (
        <Sidebar
          profile={props.profile}
          status={props.status}
          contacts={props.contacts}
          chats={props.chats}
          selectedChatId={props.selectedChat?.id ?? null}
          onSelectChat={handleSelectChat}
          onOpenMenu={() => setShowMenu(true)}
          onOpenProfile={() => {
            setView("profile");
            goMain();
          }}
          onOpenAbout={() => setShowAbout(true)}
          onAddContact={openAddContact}
          onRefresh={props.onRefresh}
          onChatMenuAction={handleChatMenuAction}
          onOpenChat={openChatWithContact}
        />
      )}
      <main className="main-panel">
        {view === "interface" && (
          <InterfaceView
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "security" && (
          <SecurityView
            profile={props.profile}
            status={props.status}
            onBackupImported={props.onBackupImported}
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "network" && (
          <NetworkView
            profile={props.profile}
            status={props.status}
            onRefresh={props.onRefresh}
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "notifications" && (
          <NotificationsView
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
            onPrefsChanged={props.onNotificationPrefsChanged}
          />
        )}
        {view === "devices" && (
          <DevicesPage
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "profile" && (
          <ProfilePage
            profile={props.profile}
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
            onProfileChanged={props.onRefreshProfile}
          />
        )}
        {view === "contacts" && (
          <ContactsPage
            contacts={props.contacts.filter((c) => c.trust_status !== "pending")}
            pendingRequests={pendingContactRequests}
            onAddContact={openAddContact}
            onOpenChat={openChatWithContact}
            onRefresh={props.onRefresh}
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "addContact" && (
          <AddContactPage
            onAdded={(contact) => openChatWithContact(contact.local_id)}
            showMobileBack={mobileShell && mobileSurface === "main"}
            onMobileBack={backToChatList}
          />
        )}
        {view === "chat" && renderChatView && (
          <ChatView
            profile={props.profile}
            chat={props.selectedChat}
            contacts={props.contacts}
            currentCall={currentCall}
            onRefresh={props.onRefresh}
            onChatRead={props.onChatRead}
            markReadActive={!mobileShell || mobileSurface === "main"}
            showMobileBack={mobileShell && mobileSurface === "main" && !!props.selectedChat}
            onMobileBack={() => setMobileSurface("list")}
            proxyEnabled={props.status.proxy?.enabled ?? false}
          />
        )}
      </main>
      {showAbout && <AboutDialog onClose={() => setShowAbout(false)} />}
      {props.status.proxy?.health === "down" &&
        shownProxyOutage !== props.status.proxy.outage_id && (
          <div className="modal-backdrop">
            <section className="modal proxy-down-modal">
              <h1>{t("proxy.downTitle")}</h1>
              <p>{t("proxy.downBody")}</p>
              {/* Secondary first, primary last: `.phone-shell .modal-actions`
                  is column-reverse, so the last button is the one on top. */}
              <div className="modal-actions">
                <button
                  type="button"
                  onClick={() => setShownProxyOutage(props.status.proxy.outage_id)}
                >
                  {t("common.close")}
                </button>
                <button
                  type="button"
                  className="primary"
                  onClick={() => {
                    setShownProxyOutage(props.status.proxy.outage_id);
                    setView("network");
                    goMain();
                  }}
                >
                  {t("proxy.downOpenSettings")}
                </button>
              </div>
            </section>
          </div>
        )}
      {renameChat && (
        <RenameChatDialog
          initialTitle={renameInitialTitle(renameChat)}
          onCancel={() => setRenameChatTarget(null)}
          onSubmit={submitRename}
        />
      )}
      {deleteChat && (
        <ConfirmDeleteChatDialog
          chat={deleteChat}
          onCancel={() => setDeleteChatTarget(null)}
          onConfirm={submitDelete}
        />
      )}
      <CallOverlay
        currentCall={currentCall}
        lastEndedCall={lastEndedCall}
        contacts={props.contacts}
        chats={props.chats}
        onRefresh={props.onRefresh}
      />
      {callNotice && <div className="toast feature-toast">{callNotice}</div>}
      {!callNotice && clockSkewNotice && (
        <div className="toast feature-toast">{clockSkewNotice}</div>
      )}
    </div>
  );
}
