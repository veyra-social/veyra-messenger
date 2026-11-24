import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Check, Loader2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { LanguageSelect } from "./components/LanguageSelect";
import { open } from "@tauri-apps/plugin-dialog";
import {
  openBackupSource,
  inspectBackupSource,
  importBackupSource,
  releaseBackupSource,
  type BackupSource,
} from "./lib/backupSource";
import { Splash } from "./components/Splash";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { useInputContextMenu } from "./lib/useInputContextMenu";
import { InputContextMenu } from "./components/InputContextMenu";
import { useLocale } from "./i18n/LocaleProvider";
import { isDebugUi } from "./uiMode";
import { api } from "./lib/tauriApi";
import { setMediaServerInfo } from "./lib/attachmentMedia";
import {
  installNotificationSoundUnlock,
  playInviteSound,
  playMessageSound,
  setNotificationSoundPrefs,
} from "./lib/notificationSounds";
import { installCallProgressAudioUnlock } from "./lib/callProgressSounds";
import { armNotificationStartupSilence } from "./lib/notificationStartupSilence";
import {
  focusMainWindowFromNotification,
  installSystemNotificationActionHandler,
  setSystemNotificationPrefs,
  showSystemNotificationForEvent,
} from "./lib/systemNotifications";
import {
  setHapticPrefs,
  triggerInviteHaptic,
  triggerMessageHaptic,
} from "./lib/haptics";
import { STARTUP_NOTIFICATION_QUIET_MS } from "./lib/startupNotificationGate";
import {
  isBatteryExemptionSupported,
  isIgnoringBatteryOptimizations,
  requestBatteryExemption,
  setBackupKeepScreenOn,
} from "./lib/nativeBridge";
import { useNarrowLayout } from "./lib/useNarrowLayout";
import { useSteadyOnline } from "./lib/useSteadyOnline";
import { useIsAndroid } from "./lib/usePlatform";
import { useKeyboardViewportInset } from "./lib/useKeyboardViewportInset";
import type {
  AppNotificationEvent,
  AppStatus,
  BackupImportMode,
  CallStateChangedPayload,
  Chat,
  ChatRestoreConsentPrompt,
  Contact,
  LocalProfileSummary,
  MyProfile,
  NotificationPrefs,
  TrayState,
} from "./lib/types";
import logo from "./assets/logos/Full.png";

// Lazy-load Layout (and the heavy chat/settings/profile views it pulls in)
// so the initial JS chunk stays small. Auth screen and Splash don't need it.
const Layout = lazy(() =>
  import("./components/Layout").then((module) => ({ default: module.Layout })),
);

function chatsPollSignature(chats: Chat[]): string {
  return chats.map((c) => `${c.id}:${c.unread_count}:${c.title ?? ""}:${c.chat_type}`).join("\0");
}

type InboxChangedPayload = {
  chatId?: string;
  messageId?: string;
  chat_id?: string;
  message_id?: string;
};

type DesktopTrayInput = {
  profile: MyProfile | null;
  status: AppStatus | null;
  badgeCount: number;
  callBadgeAlert: boolean;
  notificationPrefs: NotificationPrefs | null;
  steadyOnline: boolean;
};

function computeDesktopTrayState({
  profile,
  status,
  badgeCount,
  callBadgeAlert,
  notificationPrefs,
  steadyOnline,
}: DesktopTrayInput): TrayState {
  if (!profile || !status || status.locked || status.p2p_node_status !== "running") {
    return "offline";
  }
  if (badgeCount > 0 || callBadgeAlert) {
    return "new_message";
  }
  if ((status.failed_outbox_count ?? 0) > 0) {
    return "warning_blocked";
  }
  if (notificationPrefs && !notificationPrefs.notificationsEnabled) {
    return "muted_dnd";
  }
  if (
    steadyOnline ||
    status.reachability_status === "public" ||
    status.reachability_status === "private"
  ) {
    return "connected_secure";
  }
  return "syncing";
}

function desktopTrayTooltip(
  t: (key: string, options?: Record<string, unknown>) => string,
  state: TrayState,
  badgeCount: number,
  callBadgeAlert: boolean,
): string {
  if (callBadgeAlert) {
    return `Veyra - ${t("tray.incomingCall")}`;
  }
  if (badgeCount > 0) {
    return `Veyra - ${t("tray.unread", { count: badgeCount })}`;
  }
  const keyByState: Record<TrayState, string> = {
    connected_secure: "tray.connected",
    new_message: "tray.unread",
    syncing: "tray.syncing",
    offline: "tray.offline",
    warning_blocked: "tray.warning",
    muted_dnd: "tray.muted",
  };
  const key = keyByState[state];
  return state === "new_message"
    ? "Veyra"
    : `Veyra - ${t(key)}`;
}

export default function App() {
  const { t } = useTranslation();
  const { locale, setLocale, syncFromBackend } = useLocale();
  const narrow = useNarrowLayout();
  useKeyboardViewportInset(narrow);
  const isAndroidWebView = useIsAndroid();
  const isIOSWebView = useMemo(
    () =>
      typeof navigator !== "undefined" &&
      /iPad|iPhone|iPod/i.test(navigator.userAgent),
    [],
  );
  const isMobileWebView = isAndroidWebView || isIOSWebView;
  const isWindowsDesktop = useMemo(
    () =>
      !isAndroidWebView &&
      typeof navigator !== "undefined" &&
      /Windows/i.test(navigator.userAgent),
    [isAndroidWebView],
  );
  const isMacOSDesktop = useMemo(
    () =>
      !isAndroidWebView &&
      !isIOSWebView &&
      typeof navigator !== "undefined" &&
      /Macintosh|Mac OS X/i.test(navigator.userAgent),
    [isAndroidWebView, isIOSWebView],
  );
  const refreshInFlight = useRef(false);
  const refreshChain = useRef(Promise.resolve());
  const chatsPollInFlight = useRef(false);
  const resumeInFlight = useRef(false);
  // True only after a genuine background/hide. Gates handleResume so a bare
  // window `focus` (cmd-tab back without the page being hidden) does not re-arm
  // the notification silence window or re-drain the backend — that was silencing
  // genuinely-new messages arriving shortly after the user clicked into Veyra.
  const wasBackgroundedRef = useRef(false);
  const peerAvatarDebounceRef = useRef<number | undefined>(undefined);
  const selectedChatIdRef = useRef<string | null>(null);
  const playedInboxMessageIdsRef = useRef<Set<string>>(new Set());
  const playedInviteContactIdsRef = useRef<Set<string>>(new Set());
  const pendingContactIdsRef = useRef<Set<string>>(new Set());
  const pendingContactsPrimedRef = useRef(false);
  const notificationQuietProfileRef = useRef<string | null>(null);
  const notificationStartupQuietUntilRef = useRef(
    Date.now() + STARTUP_NOTIFICATION_QUIET_MS,
  );
  const lastDesktopBadgeStateRef = useRef<string>("");
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [restoreConsentPrompt, setRestoreConsentPrompt] =
    useState<ChatRestoreConsentPrompt | null>(null);
  const steadyOnline = useSteadyOnline(
    !!status &&
      (status.connected_peers > 0 || status.active_relay_reservations > 0),
  );
  const [loadError, setLoadError] = useState("");
  const [profile, setProfile] = useState<MyProfile | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [chats, setChats] = useState<Chat[]>([]);
  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  // Multi-profile selector state. `localProfiles === null` means "not
  // loaded yet"; an empty list falls back to the classic single-profile
  // auth flow. `authView === "auto"` shows the selector when more than one
  // profile exists, the plain form otherwise.
  const [localProfiles, setLocalProfiles] = useState<LocalProfileSummary[] | null>(null);
  const [authView, setAuthView] = useState<"auto" | "selector" | "form">("auto");
  const [selectedLocalProfile, setSelectedLocalProfile] =
    useState<LocalProfileSummary | null>(null);
  const [createProfileMode, setCreateProfileMode] = useState(false);
  // Import started from the profile selector: the backup restores into a
  // freshly created isolated profile instead of the first-run empty one.
  const [importIntoNewProfile, setImportIntoNewProfile] = useState(false);
  const [importProfileSource, setImportProfileSource] = useState<BackupSource | null>(null);
  const [importProfilePreparing, setImportProfilePreparing] = useState<
    "read" | "inspect" | null
  >(null);
  const [importProfileName, setImportProfileName] = useState<string | null>(null);
  const [importBackupPassword, setImportBackupPassword] = useState("");
  const [importProfileMode, setImportProfileMode] = useState<BackupImportMode>("link");
  const [importRestarting, setImportRestarting] = useState(false);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [callBadgeAlert, setCallBadgeAlert] = useState(false);
  const [notificationPrefs, setNotificationPrefsState] = useState<NotificationPrefs | null>(null);

  const importBackupPasswordRef = useRef<HTMLInputElement>(null);
  const importBackupPasswordMenu = useInputContextMenu();
  const eventListsRefreshTimerRef = useRef<number | undefined>(undefined);
  const eventStatusRefreshTimerRef = useRef<number | undefined>(undefined);
  const statusRefreshInFlight = useRef(false);

  useEffect(() => {
    function suppressNativeContextMenu(event: MouseEvent) {
      event.preventDefault();
    }
    document.addEventListener("contextmenu", suppressNativeContextMenu);
    return () => {
      document.removeEventListener("contextmenu", suppressNativeContextMenu);
    };
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("android-webview", isAndroidWebView);
    return () => document.documentElement.classList.remove("android-webview");
  }, [isAndroidWebView]);

  // Android video path: load the loopback media-server coordinates once per
  // process (null on desktop/iOS → videos stay on the veyra-media protocol).
  useEffect(() => {
    api
      .getMediaServerInfo()
      .then(setMediaServerInfo)
      .catch(() => setMediaServerInfo(null));
  }, []);

  // Quiet update auto-check (update-checker plan): never at startup — a few
  // minutes after unlock, so the unlock path stays fast and clients do not
  // storm the site in sync. The command self-gates on the About checkbox and
  // the 72 h cadence; failures stay silent.
  const profileUnlocked = profile !== null;
  useEffect(() => {
    if (!profileUnlocked) return;
    const timer = window.setTimeout(() => {
      api.autoCheckAppUpdate().catch(() => {});
    }, 3 * 60 * 1000);
    return () => window.clearTimeout(timer);
  }, [profileUnlocked]);

  useEffect(() => {
    let cancelled = false;
    api
      .getVersionInfo()
      .then((info) => {
        if (!cancelled) {
          setAppVersion(info.app_version);
        }
      })
      .catch(() => {
        /* footer falls back to no-render */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const selectedChat = useMemo(
    () => chats.find((chat) => chat.id === selectedChatId) ?? null,
    [chats, selectedChatId],
  );

  const desktopBadgeCount = useMemo(() => {
    const unreadMessages = chats.reduce((sum, chat) => sum + Math.max(0, chat.unread_count), 0);
    const pendingRequests = contacts.filter((contact) => contact.trust_status === "pending").length;
    return unreadMessages + pendingRequests;
  }, [chats, contacts]);

  const systemNotificationLabels = useMemo(
    () => ({
      appTitle: "Veyra",
      newMessage: t("notifications.newMessage"),
      newInvite: t("notifications.newInvite"),
      incomingCall: t("notifications.incomingCall"),
      testBody: t("notifications.testBody"),
      sampleSender: t("notifications.sampleSender"),
      sampleMessage: t("notifications.sampleMessage"),
    }),
    [t],
  );

  const applyNotificationPrefs = useCallback((prefs: NotificationPrefs) => {
    setNotificationPrefsState(prefs);
    setNotificationSoundPrefs(prefs);
    setSystemNotificationPrefs(prefs);
    setHapticPrefs(prefs);
  }, []);

  useEffect(() => {
    // Audio-unlock primer: WebView autoplay policy (incl. macOS WKWebView) only
    // lets the cue <audio> elements play programmatically after they've played
    // once during a user gesture. Installed on mount (pre-unlock) so the
    // password-screen gestures already unlock audio — otherwise the post-unlock
    // backlog burst arrives before the first in-app gesture and its cue is
    // dropped by the autoplay policy. The prime is silent (a tiny silent WAV
    // played through the cue element, not the real cue), so it never makes the
    // startup "ding".
    installNotificationSoundUnlock();
    // Same idea for the WebAudio context behind the call tones: iOS keeps an
    // AudioContext born outside a gesture suspended forever, and the dialing
    // pulse starts from a call-phase event, never from the tap itself.
    installCallProgressAudioUnlock();
  }, []);

  useEffect(() => {
    if (isMacOSDesktop) {
      armNotificationStartupSilence({ macOSDesktop: true });
    }
  }, [isMacOSDesktop]);

  useEffect(() => {
    if (!profile) {
      setNotificationPrefsState(null);
      return;
    }
    api
      .getNotificationPrefs()
      .then((prefs) => {
        applyNotificationPrefs(prefs);
      })
      .catch(() => undefined);
  }, [applyNotificationPrefs, profile?.public_id]);

  useEffect(() => {
    selectedChatIdRef.current = selectedChatId;
  }, [selectedChatId]);

  useEffect(() => {
    const count = profile ? desktopBadgeCount : 0;
    const alert = profile ? callBadgeAlert : false;
    const trayState = computeDesktopTrayState({
      profile,
      status,
      badgeCount: count,
      callBadgeAlert: alert,
      notificationPrefs,
      steadyOnline,
    });
    const tooltip = desktopTrayTooltip(t, trayState, count, alert);
    const signature = `${count}:${alert ? 1 : 0}:${trayState}:${tooltip}`;
    if (lastDesktopBadgeStateRef.current === signature) return;
    lastDesktopBadgeStateRef.current = signature;
    void api.setDesktopBadgeState(count, alert, trayState, tooltip).catch(() => undefined);
  }, [callBadgeAlert, desktopBadgeCount, notificationPrefs, profile, status, steadyOnline, t]);

  const resetNotificationTracking = useCallback(() => {
    playedInboxMessageIdsRef.current.clear();
    playedInviteContactIdsRef.current.clear();
    pendingContactIdsRef.current.clear();
    pendingContactsPrimedRef.current = false;
    notificationQuietProfileRef.current = null;
    notificationStartupQuietUntilRef.current =
      Date.now() + STARTUP_NOTIFICATION_QUIET_MS;
    armNotificationStartupSilence({ macOSDesktop: isMacOSDesktop });
  }, [isMacOSDesktop]);

  const applyContactsUpdate = useCallback((nextContacts: Contact[]) => {
    const nextPendingIds = new Set(
      nextContacts
        .filter((contact) => contact.trust_status === "pending")
        .map((contact) => contact.local_id),
    );

    if (!pendingContactsPrimedRef.current) {
      pendingContactsPrimedRef.current = true;
      for (const id of nextPendingIds) {
        playedInviteContactIdsRef.current.add(id);
      }
    }

    pendingContactIdsRef.current = nextPendingIds;
    setContacts(nextContacts);
  }, []);

  const refresh = useCallback(async (options?: { includeProfile?: boolean }) => {
    const run = async () => {
      refreshInFlight.current = true;
      try {
        const nextStatus = await api.getAppStatus();
        setLoadError("");
        if (!nextStatus.initialized || nextStatus.locked) {
          resetNotificationTracking();
          setStatus(nextStatus);
          return;
        }
        const profileRequest = options?.includeProfile ? api.getMyProfile() : null;
        const [nextProfile, nextContacts, nextChats] = await Promise.all([
          profileRequest ?? Promise.resolve(null),
          api.listContacts(),
          api.listChats(),
        ]);
        if (nextProfile) {
          setProfile(nextProfile);
        }
        applyContactsUpdate(nextContacts);
        setChats(nextChats);
        setSelectedChatId((current) => current ?? nextChats[0]?.id ?? null);
        setStatus(nextStatus);
        await syncFromBackend();
      } finally {
        refreshInFlight.current = false;
      }
    };

    const next = refreshChain.current.then(run, run);
    refreshChain.current = next.catch(() => undefined);
    return next;
  }, [applyContactsUpdate, resetNotificationTracking, syncFromBackend]);

  const adoptChat = useCallback((chat: Chat) => {
    setChats((prev) => {
      const index = prev.findIndex((item) => item.id === chat.id);
      if (index === -1) {
        return [chat, ...prev];
      }
      const next = [...prev];
      next[index] = chat;
      return next;
    });
    setSelectedChatId(chat.id);
  }, []);

  const markChatReadLocally = useCallback((chatId: string) => {
    setChats((prev) => {
      let changed = false;
      const next = prev.map((chat) => {
        if (chat.id !== chatId || chat.unread_count === 0) return chat;
        changed = true;
        return { ...chat, unread_count: 0 };
      });
      return changed ? next : prev;
    });
  }, []);

  const refreshProfile = useCallback(async () => {
    const nextProfile = await api.getMyProfile();
    setProfile(nextProfile);
  }, []);

  const handleBackupImported = useCallback(async () => {
    setProfile(null);
    setContacts([]);
    setChats([]);
    setSelectedChatId(null);
    await refresh({ includeProfile: true });
  }, [refresh]);

  const refreshLists = useCallback(async () => {
    if (chatsPollInFlight.current || refreshInFlight.current) return;
    chatsPollInFlight.current = true;
    try {
      const [nextContacts, nextChats] = await Promise.all([api.listContacts(), api.listChats()]);
      applyContactsUpdate(nextContacts);
      setChats((prev) =>
        chatsPollSignature(prev) === chatsPollSignature(nextChats) ? prev : nextChats,
      );
      setSelectedChatId((current) => {
        if (current && nextChats.some((c) => c.id === current)) return current;
        return nextChats[0]?.id ?? null;
      });
    } catch {
      /* ignore transient poll errors */
    } finally {
      chatsPollInFlight.current = false;
    }
  }, [applyContactsUpdate]);

  const refreshStatus = useCallback(async () => {
    if (statusRefreshInFlight.current) return;
    statusRefreshInFlight.current = true;
    try {
      const nextStatus = await api.getAppStatus();
      setStatus(nextStatus);
    } catch {
      /* ignore transient status refresh errors */
    } finally {
      statusRefreshInFlight.current = false;
    }
  }, []);

  const scheduleEventListsRefresh = useCallback(() => {
    window.clearTimeout(eventListsRefreshTimerRef.current);
    eventListsRefreshTimerRef.current = window.setTimeout(() => {
      refreshLists().catch(() => undefined);
    }, 600);
  }, [refreshLists]);

  const scheduleEventStatusRefresh = useCallback(() => {
    window.clearTimeout(eventStatusRefreshTimerRef.current);
    eventStatusRefreshTimerRef.current = window.setTimeout(() => {
      refreshStatus().catch(() => undefined);
    }, 1500);
  }, [refreshStatus]);

  useEffect(() => {
    return () => {
      window.clearTimeout(eventListsRefreshTimerRef.current);
      window.clearTimeout(eventStatusRefreshTimerRef.current);
    };
  }, []);

  useEffect(() => {
    refresh({ includeProfile: true }).catch((err) => {
      setStatus(null);
      setLoadError(toErrorMessage(err, t("auth.startupFailed")));
    });
  }, [refresh, t]);

  useEffect(() => {
    if (!profile) return;
    // Sidebar (chat + contact lists) is event-driven now: outbox-changed,
    // peer-avatar/profile-card-changed and chat-transport-changed all push updates.
    // This poll exists only as a defensive fallback for cases where an
    // event was dropped (window backgrounded during the change, IPC race,
    // etc.). At 6–9 s it used to fan out two full decrypt-per-row commands
    // on every tick and starved every other IPC call behind the SQLite
    // mutex; 18–24 s keeps the fallback role without monopolising the lock.
    const intervalMs = narrow ? 18000 : 24000;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      refreshLists().catch(() => undefined);
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [profile?.public_id, narrow, refreshLists]);

  useEffect(() => {
    if (!profile) return;
    const onPeerProfileChanged = () => {
      // Coalesce bursts of avatar events (a peer connecting can trigger
      // push + query within the same swarm tick) into a single refresh.
      window.clearTimeout(peerAvatarDebounceRef.current);
      peerAvatarDebounceRef.current = window.setTimeout(() => {
        refreshLists().catch(() => undefined);
      }, 600);
    };
    let unlistenAvatar: (() => void) | undefined;
    let unlistenProfileCard: (() => void) | undefined;
    void listen("peer-avatar-changed", onPeerProfileChanged).then((fn) => {
      unlistenAvatar = fn;
    });
    void listen("peer-profile-card-changed", onPeerProfileChanged).then((fn) => {
      unlistenProfileCard = fn;
    });
    return () => {
      unlistenAvatar?.();
      unlistenProfileCard?.();
      window.clearTimeout(peerAvatarDebounceRef.current);
    };
  }, [profile?.public_id, refreshLists]);

  useEffect(() => {
    if (!profile) return;
    let listener: { unregister: () => Promise<void> } | null = null;
    void installSystemNotificationActionHandler((route) => {
      void focusMainWindowFromNotification();
      const chatId = typeof route.chatId === "string" ? route.chatId : null;
      if (chatId) {
        setSelectedChatId(chatId);
      }
      refreshLists().catch(() => undefined);
    }).then((next) => {
      listener = next;
    });
    return () => {
      void listener?.unregister();
    };
  }, [profile?.public_id, refreshLists]);

  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    const listenerStartedAt = Date.now();
    if (notificationQuietProfileRef.current !== profile.public_id) {
      notificationQuietProfileRef.current = profile.public_id;
      notificationStartupQuietUntilRef.current =
        listenerStartedAt + STARTUP_NOTIFICATION_QUIET_MS;
      // Arm the audio-module silence chokepoint on profile entry/unlock too, so a
      // long-idle lock screen (module-load silence already expired) can never let
      // the initial list-priming burst play a cue.
      armNotificationStartupSilence({ macOSDesktop: isMacOSDesktop });
    }
    void listen<AppNotificationEvent>("app-notification", (event) => {
      const payload = event.payload;
      // Cue suppression is now purely the burst coalescer in notificationSounds
      // (playOnce): every incoming message/invite sounds, a rapid backlog burst
      // collapses to one cue. We no longer gate on the backend `silent` flag or
      // the local startup-silence windows here — they muted genuinely-new live
      // messages for ~30s after every unlock/resume.
      if (payload.kind === "message") {
        const played = playedInboxMessageIdsRef.current;
        if (played.has(payload.messageId)) return;
        played.add(payload.messageId);
        if (played.size > 256) {
          const oldest = played.values().next().value;
          if (oldest) played.delete(oldest);
        }
        // Android keeps web-audio cues foreground-only to avoid doubling the
        // foreground-service/system notification sound. Windows AND macOS desktop
        // play the local cue even while hidden/unfocused (the web-audio element
        // keeps playing when minimized to tray — the call ringtone proves it),
        // so a minimized message still sounds. Skip only when the message's own
        // chat is open and focused.
        const appIsVisible = !document.hidden && document.hasFocus();
        const isOpenVisibleChat = appIsVisible && payload.chatId === selectedChatIdRef.current;
        if ((appIsVisible || isWindowsDesktop || isMacOSDesktop) && !isOpenVisibleChat) {
          playMessageSound();
          triggerMessageHaptic();
        }
      } else if (payload.kind === "invite") {
        const played = playedInviteContactIdsRef.current;
        if (played.has(payload.contactId)) return;
        played.add(payload.contactId);
        if (played.size > 256) {
          const oldest = played.values().next().value;
          if (oldest) played.delete(oldest);
        }
        // Same platform split as messages: foreground-only on Android, local
        // hidden/unfocused cue on Windows and macOS desktop.
        if ((!document.hidden && document.hasFocus()) || isWindowsDesktop || isMacOSDesktop) {
          playInviteSound();
          triggerInviteHaptic();
        }
      } else if (payload.kind === "call") {
        setCallBadgeAlert(true);
      }
      if (!isMobileWebView) {
        void showSystemNotificationForEvent(payload, {
          selectedChatId: selectedChatIdRef.current,
          labels: systemNotificationLabels,
        });
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [isMacOSDesktop, isMobileWebView, isWindowsDesktop, profile?.public_id, systemNotificationLabels]);

  useEffect(() => {
    if (!profile) return;
    // Phase B: on Android, ask once to exclude Veyra from battery optimization so
    // aggressive OEM power management does not kill the background connectivity
    // service (next-steps/android-background-foreground-service.md). We auto-prompt
    // a single time per install; the Notifications settings page offers a manual
    // re-request if the user declined.
    if (!isBatteryExemptionSupported()) return;
    if (isIgnoringBatteryOptimizations() !== false) return;
    if (localStorage.getItem("veyra.battery_exemption_prompted") === "1") return;
    localStorage.setItem("veyra.battery_exemption_prompted", "1");
    requestBatteryExemption();
  }, [profile?.public_id]);

  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    void listen<CallStateChangedPayload>("call-state-changed", (event) => {
      const call = event.payload.current;
      setCallBadgeAlert(
        !!call && call.direction === "inbound" && call.state === "ringing",
      );
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [profile?.public_id]);

  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    void listen<InboxChangedPayload>("inbox-changed", () => {
      scheduleEventListsRefresh();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [profile?.public_id, scheduleEventListsRefresh]);

  // Slice 5.2: a verified contact asks for its half of your shared history
  // back. Nothing leaves this device until the user explicitly allows it.
  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    void listen<ChatRestoreConsentPrompt>("chat-restore-consent", (event) => {
      setRestoreConsentPrompt(event.payload);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [profile?.public_id]);

  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    void listen("outbox-changed", () => {
      scheduleEventListsRefresh();
      scheduleEventStatusRefresh();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [profile?.public_id, scheduleEventListsRefresh, scheduleEventStatusRefresh]);

  useEffect(() => {
    if (!profile) return;
    let unlisten: (() => void) | undefined;
    void listen("chat-transport-changed", () => {
      scheduleEventListsRefresh();
      scheduleEventStatusRefresh();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [profile?.public_id, scheduleEventListsRefresh, scheduleEventStatusRefresh]);

  useEffect(() => {
    if (!profile) return;
    const fullIntervalMs = narrow ? 60000 : 75000;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      refresh().catch(() => undefined);
    }, fullIntervalMs);
    return () => window.clearInterval(timer);
  }, [profile?.public_id, refresh]);

  useEffect(() => {
    async function handleResume(trigger: string) {
      // Only a genuine return from background re-drains the backend; a bare
      // window `focus` (cmd-tab back without the page ever being hidden) must
      // not. We deliberately do NOT arm a frontend notification-silence window
      // on resume: the backend `silent` flag (arm_notification_quiet) already
      // marks the resume backlog burst silent with a tight sliding window while
      // letting genuinely-new messages/invites/calls through. The old blunt 30s
      // frontend window muted live notifications (and the tray banner, and the
      // call ringtone) for 30s after every minimize/restore — the macOS "sound
      // disappears after restore" / "no tray banner" / "call sometimes silent"
      // bugs.
      if (!wasBackgroundedRef.current) return;
      if (document.hidden || !profile || resumeInFlight.current) return;
      wasBackgroundedRef.current = false;
      resumeInFlight.current = true;
      console.info(`[lifecycle] resume start (${trigger})`);
      requestAnimationFrame(() => {
        console.info(`[lifecycle] first frame after resume (${trigger})`);
      });
      try {
        // Tell the backend the app just regained focus so it can reset
        // pending-outbox backoff, wake every peer with pending rows, and
        // reattempt the embedded bootstrap connection. Critical on Android
        // where a returning user otherwise waits out a full backoff window.
        await api.notifyAppResumed();
        console.info(`[lifecycle] notifyAppResumed finished (${trigger})`);
      } catch (err) {
        console.warn(`[lifecycle] notifyAppResumed failed (${trigger})`, err);
      } finally {
        refresh().catch(() => undefined);
        resumeInFlight.current = false;
      }
    }

    async function handleBackground(trigger: string) {
      // Record the genuine background transition so the next resume is treated as
      // a real resume (see handleResume); a bare focus never sets this.
      wasBackgroundedRef.current = true;
      if (!profile) return;
      console.info(`[lifecycle] background (${trigger})`);
      try {
        // Tell the backend the app went to the background so the swarm trims
        // presence probing to peers with pending outbox rows. Relay/bootstrap
        // upkeep stays on, so inbound messages and calls still arrive.
        await api.notifyAppBackgrounded();
      } catch (err) {
        console.warn(`[lifecycle] notifyAppBackgrounded failed (${trigger})`, err);
      }
    }

    function onVisibilityChange() {
      console.info(`[lifecycle] visibilitychange hidden=${document.hidden}`);
      if (document.hidden) {
        void handleBackground("visibilitychange");
      } else {
        void handleResume("visibilitychange");
      }
    }

    function onFocus() {
      console.info("[lifecycle] window focus");
      void handleResume("focus");
    }

    function onPageShow() {
      console.info("[lifecycle] pageshow");
      void handleResume("pageshow");
    }

    function onNativeResume() {
      console.info("[lifecycle] native resume event");
      void handleResume("native");
    }

    // Fallback for overlays that stop the Activity without flipping the
    // document's visibility (screensaver Dream on a dock): the native onStop
    // dispatches this so the app does not keep foreground network cadences
    // while idle. Idempotent with the visibilitychange path.
    function onNativeBackground() {
      console.info("[lifecycle] native background event");
      void handleBackground("native");
    }

    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("focus", onFocus);
    window.addEventListener("pageshow", onPageShow);
    window.addEventListener("veyra-native-resume", onNativeResume);
    window.addEventListener("veyra-native-background", onNativeBackground);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("pageshow", onPageShow);
      window.removeEventListener("veyra-native-resume", onNativeResume);
      window.removeEventListener("veyra-native-background", onNativeBackground);
    };
  }, [isMacOSDesktop, profile?.public_id, refresh]);

  const authScreenVisible = !!status && (!status.initialized || status.locked || !profile);

  // Load the local profile registry whenever the auth screen appears (and
  // after every lock — `localProfiles` resets to null then). Errors fall
  // back to the classic single-profile flow.
  useEffect(() => {
    if (!authScreenVisible || localProfiles !== null) return;
    let cancelled = false;
    api
      .listLocalProfiles()
      .then((profiles) => {
        if (!cancelled) setLocalProfiles(profiles);
      })
      .catch(() => {
        if (!cancelled) setLocalProfiles([]);
      });
    return () => {
      cancelled = true;
    };
  }, [authScreenVisible, localProfiles]);

  function resetAuthSelector() {
    setLocalProfiles(null);
    setAuthView("auto");
    setSelectedLocalProfile(null);
    setCreateProfileMode(false);
    setImportIntoNewProfile(false);
  }

  async function submitProfile(mode: "init" | "unlock") {
    setError("");
    setAuthLoading(true);
    try {
      const nextProfile =
        mode === "init"
          ? createProfileMode
            ? await api.createLocalProfile(displayName.trim(), password, locale)
            : await api.initProfile(displayName.trim(), password, locale)
          : selectedLocalProfile
            ? await api.unlockLocalProfile(selectedLocalProfile.id, password)
            : await api.unlockProfile(password);
      resetNotificationTracking();
      setProfile(nextProfile);
      setPassword("");
      resetAuthSelector();
      if (mode === "unlock") {
        setStatus((current) => current ? { ...current, initialized: true, locked: false } : current);
        setAuthLoading(false);
        try {
          await refresh({ includeProfile: false });
        } catch (refreshErr) {
          setLoadError(toErrorMessage(refreshErr, t("auth.startupFailed")));
        }
        return;
      }
      await refresh({ includeProfile: mode === "init" });
    } catch (err) {
      if (mode === "unlock" && errorCode(err) === "duress_password_triggered") {
        try {
          await delay(1000);
          const nextProfile = await api.transformToDecoyProfile(password);
          resetNotificationTracking();
          setProfile(nextProfile);
          setPassword("");
          resetAuthSelector();
          setContacts([]);
          setChats([]);
          setSelectedChatId(null);
          setStatus((current) => current ? { ...current, initialized: true, locked: false } : current);
          setAuthLoading(false);
          try {
            await refresh({ includeProfile: false });
          } catch (refreshErr) {
            setLoadError(toErrorMessage(refreshErr, t("auth.startupFailed")));
          }
          return;
        } catch {
          // Deliberately generic: the lock screen must not hint that a
          // duress unlock was attempted, let alone why it failed.
          setError(t("auth.unlockFailed"));
          return;
        }
      }
      if (mode === "unlock") {
        setError(
          errorCode(err) === "wrong_password" ? t("auth.wrongPassword") : t("auth.unlockFailed"),
        );
        return;
      }
      setError(err instanceof Error ? err.message : t("common.operationFailed"));
    } finally {
      setAuthLoading(false);
    }
  }

  async function retryStartup() {
    setLoadError("");
    try {
      await refresh({ includeProfile: true });
    } catch (err) {
      setStatus(null);
      setLoadError(toErrorMessage(err, t("auth.startupFailed")));
    }
  }

  async function chooseProfileBackup() {
    setError("");
    // See BackupRestoreView.chooseImportFile — on Android the only way to
    // let the user pick a .vmb is to omit `filters` entirely so the Intent
    // falls back to `*/*` (Tauri converts even `filters: []` into a no-match
    // MIME list). Desktop platforms keep the friendlier extension filter.
    const chosenPath = await open({
      title: t("backup.openDialogTitle"),
      multiple: false,
      directory: false,
      ...(isAndroidWebView
        ? {}
        : { filters: [{ name: t("backup.vmbFiles"), extensions: ["vmb"] }] }),
    });
    if (!chosenPath || Array.isArray(chosenPath)) {
      // Cancelled picker: drop the selector's import intent. A stale
      // `importIntoNewProfile` used to gate away the password field and
      // submit button of every later unlock (field report 2026-07-22:
      // tagline + "back to profiles" link and nothing else).
      setImportIntoNewProfile(false);
      return;
    }
    let source: BackupSource | null = null;
    // Immediate visible feedback: a large pick takes seconds to stream and
    // inspect, and without this the start screen looked like the file was
    // never selected.
    setImportProfilePreparing("read");
    setBackupKeepScreenOn(true);
    try {
      // Materialize the pick once while the dialog's URI grant is still
      // active (Android streams it into a backend temp file, desktop keeps
      // the path, iOS keeps bytes). The subsequent inspect + import calls
      // reuse that source — a second open against the same content URI
      // after the dialog flow ends fails with SecurityException / EBADF.
      source = await openBackupSource(chosenPath, isIOSWebView);
      setImportProfilePreparing("inspect");
      const metadata = await inspectBackupSource(source);
      setImportProfileSource(source);
      setImportProfileName(metadata.profile_display_name || t("backup.unnamedProfile"));
      setImportBackupPassword("");
    } catch (err) {
      releaseBackupSource(source);
      // Same stale-flag hazard as the cancelled picker above.
      setImportIntoNewProfile(false);
      setError(toErrorMessage(err, t("backup.importFailed")));
    } finally {
      setImportProfilePreparing(null);
      setBackupKeepScreenOn(false);
    }
  }

  async function importProfileBackup() {
    if (!importProfileSource || !importBackupPassword) return;
    setAuthLoading(true);
    setError("");
    setBackupKeepScreenOn(true);
    try {
      let newProfileId: string | null = null;
      if (importIntoNewProfile) {
        // Selector-initiated import: restore into a fresh isolated profile.
        // Created only now (after the file was picked and inspected) so a
        // cancelled picker never leaves empty profiles behind.
        newProfileId = await api.prepareLocalProfileForImport(importProfileName ?? "");
      }
      await importBackupSource(importProfileSource, importBackupPassword, importProfileMode);
      if (newProfileId) {
        // The app restarts before any unlock; move the registry marker so
        // the restart opens the imported profile, not the previous one.
        await api.markActiveLocalProfile(newProfileId);
      }
      releaseBackupSource(importProfileSource);
      setImportProfileSource(null);
      setImportProfileName(null);
      setImportBackupPassword("");
      // The libp2p node keeps its in-memory identity for the process
      // lifetime, so a restart is required before the swarm matches the
      // imported database (multi-device Round 0). Fallback: if programmatic
      // restart is unavailable on this platform, refresh into the unlock
      // screen after a short beat.
      setImportRestarting(true);
      void api.restartApp().catch(() => {});
      window.setTimeout(() => {
        setImportRestarting(false);
        void refresh({ includeProfile: true });
      }, 2500);
    } catch (err) {
      setError(toErrorMessage(err, t("backup.importFailed")));
    } finally {
      setBackupKeepScreenOn(false);
      setAuthLoading(false);
    }
  }

  // Version footer: the debug UI marks itself so a build's UI branch is
  // always identifiable from the auth screen alone.
  const versionLabel = appVersion ? (isDebugUi ? `${appVersion} · debug UI` : appVersion) : null;

  if (!status) {
    if (loadError) {
      return (
        <main className="auth-screen">
          <section className="auth-panel startup-error-panel">
            <img className="auth-logo" src={logo} alt="Veyra" />
            <p>{t("brand.tagline")}</p>
            <div className="error">{loadError}</div>
            <button onClick={retryStartup}>{t("auth.retry")}</button>
          </section>
          {versionLabel && (
            <footer className="auth-version">{t("auth.versionFooter", { version: versionLabel })}</footer>
          )}
        </main>
      );
    }
    return <Splash message={t("common.loadingVeyra")} />;
  }

  if (!status.initialized || status.locked || !profile) {
    const mode = createProfileMode ? "init" : status.initialized ? "unlock" : "init";
    const welcomeName =
      (selectedLocalProfile?.display_name || status.profile_display_name)?.trim();
    const profiles = localProfiles ?? [];
    const showSelector =
      (authView === "selector" || (authView === "auto" && profiles.length > 1)) &&
      profiles.length > 0 &&
      !importProfileSource &&
      !importProfilePreparing;
    const cameFromSelector = createProfileMode || selectedLocalProfile !== null;
    if (showSelector) {
      return (
        <main className="auth-screen">
          <section className="auth-panel">
            <img className="auth-logo" src={logo} alt="Veyra" />
            <div className="auth-welcome">
              <div className="auth-welcome-title">{t("auth.profilesTitle")}</div>
            </div>
            <div className="profile-selector-list">
              {profiles.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  className="profile-selector-row"
                  onClick={() => {
                    setSelectedLocalProfile(entry);
                    setCreateProfileMode(false);
                    setAuthView("form");
                    setError("");
                    setPassword("");
                  }}
                >
                  {/* Deliberately name-only: no fingerprint, no avatar, no
                      recency hints — under a duress unlock the login screen
                      must not advertise the real identities behind the other
                      profiles. */}
                  <span className="profile-selector-name">
                    {entry.display_name.trim() || t("auth.unnamedProfile")}
                  </span>
                  {entry.active && (
                    <Check
                      size={18}
                      className="profile-selector-check"
                      aria-label={t("auth.activeProfileBadge")}
                    />
                  )}
                </button>
              ))}
            </div>
            <button
              type="button"
              className="text-link-btn"
              onClick={() => {
                setCreateProfileMode(true);
                setSelectedLocalProfile(null);
                setAuthView("form");
                setError("");
                setPassword("");
                setDisplayName("");
              }}
            >
              {t("auth.createProfile")}
            </button>
            <button
              type="button"
              className="text-link-btn"
              onClick={() => {
                setImportIntoNewProfile(true);
                setCreateProfileMode(false);
                setSelectedLocalProfile(null);
                void chooseProfileBackup();
              }}
            >
              {t("auth.importProfile")}
            </button>
          </section>
          {versionLabel && (
            <footer className="auth-version">
              {t("auth.versionFooter", { version: versionLabel })}
            </footer>
          )}
        </main>
      );
    }
    return (
      <main className="auth-screen">
        <section className="auth-panel">
          <img className="auth-logo" src={logo} alt="Veyra" />
          {mode === "unlock" && !importIntoNewProfile ? (
            <div className="auth-welcome">
              <div className="auth-welcome-title">
                {welcomeName
                  ? t("auth.welcomeBack", { username: welcomeName })
                  : t("auth.welcomeBackGeneric")}
              </div>
              <div className="auth-login-error" role="alert" aria-live="polite">
                {error || "\u00a0"}
              </div>
            </div>
          ) : mode === "init" && !importProfileSource && !importIntoNewProfile ? (
            <p className="auth-create-title">{t("auth.createProfileTitle")}</p>
          ) : (
            <p className="auth-create-title">{t("auth.importProfileTitle")}</p>
          )}
          <form
            className="auth-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (importProfileSource) {
                return;
              }
              if (authLoading || !password || (mode === "init" && !displayName.trim())) {
                return;
              }
              void submitProfile(mode);
            }}
          >
            {mode === "init" && !importProfileSource && (
              <LanguageSelect
                value={locale}
                disabled={authLoading}
                onChange={(next) => {
                  void setLocale(next);
                }}
              />
            )}
            {mode === "init" && !importProfileSource && (
              <label>
                {t("auth.displayName")}
                <input
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                  disabled={authLoading}
                />
              </label>
            )}
            {!importProfileSource && !importIntoNewProfile && (
              <label>
                {t("auth.masterPassword")}
                <input
                  type="password"
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    if (mode === "unlock" && error) setError("");
                  }}
                  autoComplete="current-password"
                  disabled={authLoading}
                />
                {mode === "init" && (
                  <small className="hint">{t("auth.passwordHint")}</small>
                )}
              </label>
            )}
            {mode !== "unlock" && error && <div className="error">{error}</div>}
            {!importProfileSource && !importIntoNewProfile && (
              <button
                type="submit"
                disabled={authLoading || !password || (mode === "init" && !displayName.trim())}
              >
                {authLoading ? (
                  <span className="auth-loading">
                    <Loader2 size={14} className="spin" />
                    {mode === "init" ? t("auth.creatingProfile") : t("auth.unlocking")}
                  </span>
                ) : mode === "init" ? (
                  t("auth.createProfile")
                ) : (
                  t("auth.unlock")
                )}
              </button>
            )}
            {authLoading && (
              <div className="auth-progress" role="status" aria-live="polite">
                <div className="auth-progress-track" aria-hidden="true">
                  <span />
                </div>
                <p>{mode === "init" ? t("auth.creatingProfileProgress") : t("auth.unlockingProgress")}</p>
              </div>
            )}
            {mode === "init" && !createProfileMode && !importProfileSource && !importProfilePreparing && (
              <button type="button" className="text-link-btn" onClick={() => void chooseProfileBackup()}>
                {t("auth.importProfile")}
              </button>
            )}
            {importProfilePreparing && (
              <div className="auth-progress" role="status" aria-live="polite">
                <div className="auth-progress-track" aria-hidden="true">
                  <span />
                </div>
                <p>
                  {importProfilePreparing === "read"
                    ? t("backup.importStageRead")
                    : t("backup.importStageInspect")}
                </p>
              </div>
            )}
            {importRestarting && (
              <div className="auth-progress" role="status" aria-live="polite">
                <div className="auth-progress-track" aria-hidden="true">
                  <span />
                </div>
                <p>{t("backup.importRestarting")}</p>
              </div>
            )}
            {(mode === "init" || importIntoNewProfile) && importProfileSource && (
              <div className="auth-import-profile">
                <p className="hint">{t("auth.importProfileSelected", { name: importProfileName })}</p>
                <div
                  className="preview-mode-picker"
                  role="radiogroup"
                  aria-label={t("backup.importModeTitle")}
                >
                  {(["link", "restore"] as const).map((importMode) => (
                    <button
                      key={importMode}
                      type="button"
                      role="radio"
                      aria-checked={importProfileMode === importMode}
                      className={`preview-mode-option${
                        importProfileMode === importMode ? " selected" : ""
                      }`}
                      disabled={authLoading}
                      onClick={() => setImportProfileMode(importMode)}
                    >
                      <span className="preview-mode-label">
                        {t(
                          importMode === "link"
                            ? "backup.importModeLink"
                            : "backup.importModeRestore",
                        )}
                      </span>
                      <span className="preview-mode-desc">
                        {t(
                          importMode === "link"
                            ? "backup.importModeLinkHint"
                            : "backup.importModeRestoreHint",
                        )}
                      </span>
                    </button>
                  ))}
                </div>
                <label>
                  {t("backup.password")}
                  <input
                    ref={importBackupPasswordRef}
                    type="password"
                    value={importBackupPassword}
                    onChange={(event) => setImportBackupPassword(event.target.value)}
                    autoComplete="new-password"
                    disabled={authLoading}
                    {...importBackupPasswordMenu.bind}
                  />
                  <InputContextMenu
                    position={importBackupPasswordMenu.menuPosition}
                    onClose={importBackupPasswordMenu.closeMenu}
                    inputRef={importBackupPasswordRef}
                    isPassword={true}
                  />
                </label>
                <div className="button-row">
                  <button
                    type="button"
                    onClick={() => void importProfileBackup()}
                    disabled={authLoading || !importBackupPassword}
                  >
                    {t("auth.importProfile")}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      releaseBackupSource(importProfileSource);
                      setImportProfileSource(null);
                      setImportProfileName(null);
                      setImportBackupPassword("");
                      if (importIntoNewProfile) {
                        setImportIntoNewProfile(false);
                        setAuthView("selector");
                      }
                    }}
                    disabled={authLoading}
                  >
                    {t("auth.backToCreateProfile")}
                  </button>
                </div>
                <p className="hint auth-import-restart-note">
                  {t("backup.importRestartNote")}
                </p>
              </div>
            )}
          </form>
          {cameFromSelector && !authLoading && !importProfileSource && (
            <button
              type="button"
              className="text-link-btn"
              onClick={() => {
                setAuthView("selector");
                setSelectedLocalProfile(null);
                setCreateProfileMode(false);
                setError("");
                setPassword("");
              }}
            >
              {t("auth.backToProfiles")}
            </button>
          )}
          {mode === "unlock" && !cameFromSelector && profiles.length > 0 && !authLoading && (
            <button
              type="button"
              className="text-link-btn"
              onClick={() => {
                setAuthView("selector");
                setError("");
                setPassword("");
              }}
            >
              {t("auth.profilesTitle")}
            </button>
          )}
        </section>
        {versionLabel && (
          <footer className="auth-version">{t("auth.versionFooter", { version: versionLabel })}</footer>
        )}
      </main>
    );
  }

  return (
    <ErrorBoundary>
    <Suspense fallback={<Splash message={t("common.loadingVeyra")} />}>
      <Layout
        profile={profile}
        status={status}
        contacts={contacts}
        chats={chats}
        selectedChat={selectedChat}
        selectedChatId={selectedChatId}
        onSelectChat={setSelectedChatId}
        onAdoptChat={adoptChat}
        onRefresh={refresh}
        onRefreshProfile={refreshProfile}
        onBackupImported={handleBackupImported}
        onNotificationPrefsChanged={applyNotificationPrefs}
        onChatRead={markChatReadLocally}
        onLocked={() => {
          resetNotificationTracking();
          setProfile(null);
          setContacts([]);
          setChats([]);
          setSelectedChatId(null);
          resetAuthSelector();
          refresh();
        }}
      />
      {restoreConsentPrompt && (
        <div className="modal-backdrop">
          <section className="modal" role="alertdialog">
            <h1>{t("restoreConsent.title")}</h1>
            <p>
              {t("restoreConsent.body", {
                name:
                  restoreConsentPrompt.contact_name ||
                  t("restoreConsent.unknownContact"),
                events: restoreConsentPrompt.events,
                size: (restoreConsentPrompt.bytes / 1024).toFixed(0),
              })}
            </p>
            <p className="hint">{t("restoreConsent.hint")}</p>
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => {
                  void api.respondChatRestoreConsent(
                    restoreConsentPrompt.request_id,
                    false,
                  );
                  setRestoreConsentPrompt(null);
                }}
              >
                {t("restoreConsent.deny")}
              </button>
              <button
                type="button"
                className="primary"
                onClick={() => {
                  void api.respondChatRestoreConsent(
                    restoreConsentPrompt.request_id,
                    true,
                  );
                  setRestoreConsentPrompt(null);
                }}
              >
                {t("restoreConsent.allow")}
              </button>
            </div>
          </section>
        </div>
      )}
    </Suspense>
    </ErrorBoundary>
  );
}

function toErrorMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message) {
    return err.message;
  }
  if (typeof err === "string" && err) {
    return err;
  }
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message?: unknown }).message;
    if (typeof message === "string" && message) {
      return message;
    }
  }
  return fallback;
}

function errorCode(err: unknown): string | null {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === "string" ? code : null;
  }
  return null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
