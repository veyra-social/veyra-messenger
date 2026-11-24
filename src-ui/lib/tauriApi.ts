import { invoke } from "@tauri-apps/api/core";
import type { UiLocale } from "../i18n/locale";
import type {
  AppStatus,
  AttachmentReceiveSettings,
  BootstrapNode,
  BootstrapNodeProbe,
  BootstrapNodeTestResult,
  NetworkRoutesStatus,
  CatalogIngestStats,
  Chat,
  ChatMessage,
  ChatMessageState,
  ChatStatistics,
  ChatTransportStatus,
  Contact,
  LocalProfileSummary,
  MyProfile,
  ParsedInvite,
  PeerCatalogIngest,
  AccessBundleImportResult,
  AccessBundlePreview,
  AccessBundleImportRow,
  BootstrapNetworkSummary,
  ReachabilityStatus,
  RelayReservationView,
  ConnectPolicy,
  ProxyActivation,
  ProxyInput,
  ProxyStatus,
  ProxyTestResult,
  ProxyView,
  VersionInfo,
  BackupMetadata,
  BackupImportMode,
  CallLogEntry,
  ChatRestoreSummary,
  ContactRestoreSummary,
  CurrentCallSnapshot,
  RtcIceServerConfig,
  DesktopIntegrationPrefs,
  DevicePairingBegin,
  DeviceSyncSummary,
  FileLoggingStatus,
  NodePassportView,
  NotificationPrefs,
  OwnDevice,
  MediaServerInfo,
  ProfileExtensions,
  TrayState,
  UpdateCheckStatus,
} from "./types";

export type AttachmentBytes = {
  bytes_b64: string;
  mime_type: string;
  file_name: string;
};

export const api = {
  initProfile: (display_name: string, master_password: string, ui_locale: UiLocale) =>
    invoke<MyProfile>("init_profile", {
      displayName: display_name,
      masterPassword: master_password,
      uiLocale: ui_locale,
    }),
  unlockProfile: (master_password: string) =>
    invoke<MyProfile>("unlock_profile", { masterPassword: master_password }),
  listLocalProfiles: () => invoke<LocalProfileSummary[]>("list_local_profiles"),
  unlockLocalProfile: (profile_id: string, master_password: string) =>
    invoke<MyProfile>("unlock_local_profile", {
      profileId: profile_id,
      masterPassword: master_password,
    }),
  createLocalProfile: (display_name: string, master_password: string, ui_locale: UiLocale) =>
    invoke<MyProfile>("create_local_profile", {
      displayName: display_name,
      masterPassword: master_password,
      uiLocale: ui_locale,
    }),
  prepareLocalProfileForImport: (display_name: string) =>
    invoke<string>("prepare_local_profile_for_import", { displayName: display_name }),
  markActiveLocalProfile: (profile_id: string) =>
    invoke<void>("mark_active_local_profile", { profileId: profile_id }),
  deleteLocalProfile: (profile_id: string) =>
    invoke<void>("delete_local_profile", { profileId: profile_id }),
  getBackgroundRestrictionStatus: () =>
    invoke<boolean>("get_background_restriction_status"),
  getMediaServerInfo: () => invoke<MediaServerInfo | null>("get_media_server_info"),
  quitApp: () => invoke<void>("quit_app"),
  getUpdateCheckStatus: () => invoke<UpdateCheckStatus>("get_update_check_status"),
  setUpdateAutoCheck: (enabled: boolean) =>
    invoke<UpdateCheckStatus>("set_update_auto_check", { enabled }),
  checkAppUpdate: () => invoke<UpdateCheckStatus>("check_app_update"),
  autoCheckAppUpdate: () => invoke<UpdateCheckStatus>("auto_check_app_update"),
  exportLocalProfileBackup: (profile_id: string, master_password: string, path: string) =>
    invoke<void>("export_local_profile_backup", {
      profileId: profile_id,
      masterPassword: master_password,
      path,
    }),
  exportLocalProfileBackupTempFile: (profile_id: string, master_password: string) =>
    invoke<string>("export_local_profile_backup_temp_file", {
      profileId: profile_id,
      masterPassword: master_password,
    }),
  serializeLocalProfileBackup: (profile_id: string, master_password: string) =>
    invoke<string>("serialize_local_profile_backup", {
      profileId: profile_id,
      masterPassword: master_password,
    }),
  changeMasterPassword: (old_password: string, new_password: string) =>
    invoke<void>("change_master_password", {
      oldPassword: old_password,
      newPassword: new_password,
    }),
  setDuressPassword: (master_password: string, duress_password: string) =>
    invoke<void>("set_duress_password", {
      masterPassword: master_password,
      duressPassword: duress_password,
    }),
  clearDuressPassword: (master_password: string) =>
    invoke<void>("clear_duress_password", { masterPassword: master_password }),
  transformToDecoyProfile: (duress_password: string) =>
    invoke<MyProfile>("transform_to_decoy_profile", { duressPassword: duress_password }),
  lockProfile: () => invoke<void>("lock_profile"),
  getMyProfile: () => invoke<MyProfile>("get_my_profile"),
  renameProfile: (display_name: string) =>
    invoke<MyProfile>("rename_profile", { displayName: display_name }),
  setMyAvatarJpeg: (jpeg_base64: string) =>
    invoke<MyProfile>("set_my_avatar_jpeg", { jpegBase64: jpeg_base64 }),
  clearMyAvatar: () => invoke<MyProfile>("clear_my_avatar"),
  setMyProfileExtensions: (profile_extensions: ProfileExtensions) =>
    invoke<MyProfile>("set_my_profile_extensions", { profileExtensions: profile_extensions }),
  syncPeerAvatarForContact: (contact_id: string) =>
    invoke<void>("sync_peer_avatar_for_contact", { contactId: contact_id }),
  syncPeerProfileCardForContact: (contact_id: string) =>
    invoke<void>("sync_peer_profile_card_for_contact", { contactId: contact_id }),
  generateInviteString: () => invoke<string>("generate_invite_string"),
  generateInviteWithRouting: () => invoke<string>("generate_invite_with_routing"),
  getListenAddresses: () => invoke<string[]>("get_listen_addresses"),
  beginDevicePairing: () => invoke<DevicePairingBegin>("begin_device_pairing"),
  cancelDevicePairing: () => invoke<void>("cancel_device_pairing"),
  completeDevicePairing: (code: string) => invoke<void>("complete_device_pairing", { code }),
  listOwnDevices: () => invoke<OwnDevice[]>("list_own_devices"),
  setOwnDeviceEnabled: (device_id: string, enabled: boolean) =>
    invoke<boolean>("set_own_device_enabled", { deviceId: device_id, enabled }),
  renameOwnDevice: (label: string) => invoke<void>("rename_own_device", { label }),
  syncOwnDevice: (device_id: string) =>
    invoke<DeviceSyncSummary>("sync_own_device", { deviceId: device_id }),
  restoreChatHistory: (chat_id: string) =>
    invoke<ChatRestoreSummary>("restore_chat_history", { chatId: chat_id }),
  restoreChatHistoryFromContact: (chat_id: string) =>
    invoke<ContactRestoreSummary>("restore_chat_history_from_contact", { chatId: chat_id }),
  respondChatRestoreConsent: (request_id: string, allow: boolean) =>
    invoke<void>("respond_chat_restore_consent", { requestId: request_id, allow }),
  getAttachmentReceiveSettings: () =>
    invoke<AttachmentReceiveSettings>("get_attachment_receive_settings"),
  setAttachmentReceiveSettings: (media: boolean, other: boolean) =>
    invoke<void>("set_attachment_receive_settings", { media, other }),
  getContactAttachmentDeniedKinds: (contact_id: string) =>
    invoke<string[]>("get_contact_attachment_denied_kinds", { contactId: contact_id }),
  setContactAttachmentDeniedKinds: (contact_id: string, denied: string[]) =>
    invoke<void>("set_contact_attachment_denied_kinds", { contactId: contact_id, denied }),
  acceptAttachment: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("accept_attachment", { messageId: message_id, transferId: transfer_id }),
  declineAttachment: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("decline_attachment", { messageId: message_id, transferId: transfer_id }),
  pauseAttachmentTransfer: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("pause_attachment_transfer", {
      messageId: message_id,
      transferId: transfer_id,
    }),
  resumeAttachmentTransfer: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("resume_attachment_transfer", {
      messageId: message_id,
      transferId: transfer_id,
    }),
  cancelAttachmentTransfer: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("cancel_attachment_transfer", {
      messageId: message_id,
      transferId: transfer_id,
    }),
  requestAttachmentTransfer: (message_id: string, transfer_id: string) =>
    invoke<ChatMessage>("request_attachment_transfer", {
      messageId: message_id,
      transferId: transfer_id,
    }),
  resendAttachmentAsNew: (message_id: string) =>
    invoke<ChatMessage>("resend_attachment_as_new", { messageId: message_id }),
  getDeviceSyncMode: () => invoke<string>("get_device_sync_mode"),
  setDeviceSyncMode: (mode: string) => invoke<void>("set_device_sync_mode", { mode }),
  getFileLoggingStatus: () => invoke<FileLoggingStatus>("get_file_logging_status"),
  setFileLoggingEnabled: (enabled: boolean) =>
    invoke<void>("set_file_logging_enabled", { enabled }),
  addContact: (
    invite_string: string,
    display_name: string,
    source: "pasted" | "qr_scan" = "pasted",
  ) =>
    invoke<Contact>("add_contact", { inviteString: invite_string, displayName: display_name, source }),
  parseInviteString: (invite_string: string) =>
    invoke<ParsedInvite>("parse_invite_string", { inviteString: invite_string }),
  listContacts: () => invoke<Contact[]>("list_contacts"),
  refreshContactPresence: (contact_id: string) =>
    invoke<void>("refresh_contact_presence", { contactId: contact_id }),
  verifyContact: (contact_id: string) => invoke<void>("verify_contact", { contactId: contact_id }),
  acceptContactRequest: (contact_id: string) => invoke<void>("accept_contact_request", { contactId: contact_id }),
  rejectContactRequest: (contact_id: string) => invoke<void>("reject_contact_request", { contactId: contact_id }),
  blockContact: (contact_id: string) => invoke<void>("block_contact", { contactId: contact_id }),
  unblockContact: (contact_id: string) =>
    invoke<void>("unblock_contact", { contactId: contact_id }),
  renameContact: (contact_id: string, display_name: string) =>
    invoke<void>("rename_contact", { contactId: contact_id, displayName: display_name }),
  deleteContact: (contact_id: string) => invoke<void>("delete_contact", { contactId: contact_id }),
  deleteChat: (chat_id: string) => invoke<void>("delete_chat", { chatId: chat_id }),
  setChatPinned: (chat_id: string, pinned: boolean) =>
    invoke<void>("set_chat_pinned", { chatId: chat_id, pinned }),
  getChatStatistics: (chat_id: string, file_search: string | null, page: number, page_size: number) =>
    invoke<ChatStatistics>("get_chat_statistics", {
      chatId: chat_id,
      fileSearch: file_search,
      page,
      pageSize: page_size,
    }),
  clearChatHistory: (chat_id: string) =>
    invoke<void>("clear_chat_history", { chatId: chat_id }),
  createDirectChat: (contact_id: string) => invoke<Chat>("create_direct_chat", { contactId: contact_id }),
  listChats: () => invoke<Chat[]>("list_chats"),
  markChatOpened: (chat_id: string) => invoke<void>("mark_chat_opened", { chatId: chat_id }),
  listCallLog: (chat_id: string, limit = 50) =>
    invoke<CallLogEntry[]>("list_call_log", { chatId: chat_id, limit }),
  getCurrentCall: () => invoke<CurrentCallSnapshot | null>("get_current_call"),
  getCallIceServers: (peer_id: string) =>
    invoke<RtcIceServerConfig[]>("get_call_ice_servers", { peerId: peer_id }),
  reportCallMediaIceOutcome: (peer_id: string, call_id: string, connected: boolean) =>
    invoke<void>("report_call_media_ice_outcome", { peerId: peer_id, callId: call_id, connected }),
  requestSystemMicrophoneAccess: () => invoke<string>("request_system_microphone_access"),
  logCallMediaDiagnostic: (level: "info" | "warn", message: string) =>
    invoke<void>("log_call_media_diagnostic", { level, message }),
  beginCall: (chat_id: string, peer_public_key: string) =>
    invoke<string>("begin_call", {
      chatId: chat_id,
      peerPublicKey: peer_public_key,
    }),
  sendCallOffer: (call_id: string, offer_sdp: string) =>
    invoke<void>("send_call_offer", {
      callId: call_id,
      offerSdp: offer_sdp,
    }),
  startCall: (chat_id: string, peer_public_key: string, offer_sdp: string) =>
    invoke<string>("start_call", {
      chatId: chat_id,
      peerPublicKey: peer_public_key,
      offerSdp: offer_sdp,
    }),
  answerCall: (call_id: string, answer_sdp: string) =>
    invoke<void>("answer_call", { callId: call_id, answerSdp: answer_sdp }),
  sendCallIceCandidate: (
    call_id: string,
    candidate: string,
    sdp_mid?: string | null,
    sdp_m_line_index?: number | null,
  ) =>
    invoke<void>("send_call_ice_candidate", {
      callId: call_id,
      candidate,
      sdpMid: sdp_mid ?? null,
      sdpMLineIndex: sdp_m_line_index ?? null,
    }),
  failCall: (call_id: string, reason: "dtls_timeout" | "network_drop") =>
    invoke<void>("fail_call", { callId: call_id, reason }),
  hangupCall: (call_id: string) => invoke<void>("hangup_call", { callId: call_id }),
  rejectCall: (call_id: string) => invoke<void>("reject_call", { callId: call_id }),
  noMicrophoneCall: (call_id: string) => invoke<void>("no_microphone_call", { callId: call_id }),
  timeoutCall: (call_id: string) => invoke<void>("timeout_call", { callId: call_id }),
  getUiLocale: () => invoke<UiLocale>("get_ui_locale"),
  setUiLocale: (locale: UiLocale) => invoke<void>("set_ui_locale", { locale }),
  getUiPrefs: () =>
    invoke<{
      theme: string;
      ui_font_scale: string;
      chat_font_scale: string;
      skin: string;
      video_autoplay_muted: boolean;
      keep_screen_on: boolean;
    }>("get_ui_prefs"),
  setUiPrefs: (prefs: {
    theme: string;
    ui_font_scale: string;
    chat_font_scale: string;
    skin: string;
    video_autoplay_muted: boolean;
    keep_screen_on: boolean;
  }) => invoke<void>("set_ui_prefs", { prefs }),
  getDesktopIntegrationPrefs: () =>
    invoke<DesktopIntegrationPrefs>("get_desktop_integration_prefs"),
  getNotificationPrefs: () =>
    invoke<NotificationPrefs>("get_notification_prefs"),
  setNotificationPrefs: (prefs: NotificationPrefs) =>
    invoke<void>("set_notification_prefs", { prefs }),
  getOfflineDeliveryEnabled: () =>
    invoke<boolean>("get_offline_delivery_enabled"),
  setOfflineDeliveryEnabled: (enabled: boolean) =>
    invoke<void>("set_offline_delivery_enabled", { enabled }),
  triggerHaptic: (kind: "message" | "invite" | "call") =>
    invoke<string>("trigger_haptic", { kind }),
  setDesktopBadgeState: (
    unread_count: number,
    alert: boolean,
    tray_state: TrayState,
    tooltip?: string,
  ) =>
    invoke<void>("set_desktop_badge_state", {
      unreadCount: unread_count,
      alert,
      trayState: tray_state,
      tooltip: tooltip ?? null,
    }),
  setCloseToTrayEnabled: (enabled: boolean) =>
    invoke<void>("set_close_to_tray_enabled", { enabled }),
  setAutostartEnabled: (enabled: boolean) =>
    invoke<void>("set_autostart_enabled", { enabled }),
  shouldShowMainWindowOnStartup: () =>
    invoke<boolean>("should_show_main_window_on_startup"),
  getChatMessages: (chat_id: string) => invoke<ChatMessage[]>("get_chat_messages", { chatId: chat_id }),
  getChatMessagesPage: (chat_id: string, before_created_at: string | null, limit: number) =>
    invoke<ChatMessage[]>("get_chat_messages_page", {
      chatId: chat_id,
      beforeCreatedAt: before_created_at,
      limit,
    }),
  getChatMessageStates: (chat_id: string) =>
    invoke<ChatMessageState[]>("get_chat_message_states", { chatId: chat_id }),
  getChatMessagesDelta: (chat_id: string, after_created_at: string) =>
    invoke<ChatMessage[]>("get_chat_messages_delta", {
      chatId: chat_id,
      afterCreatedAt: after_created_at,
    }),
  getChatTransport: (chat_id: string) =>
    invoke<ChatTransportStatus>("get_chat_transport", { chatId: chat_id }),
  sendMessage: (chat_id: string, text: string, quoted_message_id?: string | null) =>
    invoke<ChatMessage>("send_message", {
      chatId: chat_id,
      text,
      quotedMessageId: quoted_message_id ?? null,
    }),
  sendAttachmentMessage: (
    chat_id: string,
    file_name: string,
    mime_type: string,
    bytes_b64: string,
    caption?: string | null,
    quoted_message_id?: string | null,
  ) =>
    invoke<ChatMessage>("send_attachment_message", {
      chatId: chat_id,
      fileName: file_name,
      mimeType: mime_type,
      bytesB64: bytes_b64,
      caption: caption ?? null,
      quotedMessageId: quoted_message_id ?? null,
    }),
  beginAttachmentUpload: () => invoke<string>("begin_attachment_upload"),
  appendAttachmentUpload: (upload_id: string, chunk_b64: string) =>
    invoke<void>("append_attachment_upload", { uploadId: upload_id, chunkB64: chunk_b64 }),
  abortAttachmentUpload: (upload_id: string) =>
    invoke<void>("abort_attachment_upload", { uploadId: upload_id }),
  finalizeAttachmentUpload: (
    upload_id: string,
    chat_id: string,
    file_name: string,
    mime_type: string,
    caption?: string | null,
    quoted_message_id?: string | null,
  ) =>
    invoke<ChatMessage>("finalize_attachment_upload", {
      uploadId: upload_id,
      chatId: chat_id,
      fileName: file_name,
      mimeType: mime_type,
      caption: caption ?? null,
      quotedMessageId: quoted_message_id ?? null,
    }),
  getAttachmentBytes: (attachment_id: string) =>
    invoke<AttachmentBytes>("get_attachment_bytes", { attachmentId: attachment_id }),
  getAttachmentPoster: (attachment_id: string) =>
    invoke<string | null>("get_attachment_poster", { attachmentId: attachment_id }),
  setAttachmentPoster: (attachment_id: string, poster_b64: string) =>
    invoke<void>("set_attachment_poster", {
      attachmentId: attachment_id,
      posterB64: poster_b64,
    }),
  saveAttachment: (attachment_id: string, destination_path: string) =>
    invoke<void>("save_attachment", {
      attachmentId: attachment_id,
      destinationPath: destination_path,
    }),
  exportAttachmentToTemp: (attachment_id: string) =>
    invoke<string>("export_attachment_to_temp", { attachmentId: attachment_id }),
  deleteAttachmentTempFile: (path: string) =>
    invoke<void>("delete_attachment_temp_file", { path }),
  shareAttachment: (attachment_id: string) =>
    invoke<void>("share_attachment", { attachmentId: attachment_id }),
  forwardAttachmentMessage: (source_message_id: string, target_chat_id: string) =>
    invoke<ChatMessage>("forward_attachment_message", {
      sourceMessageId: source_message_id,
      targetChatId: target_chat_id,
    }),
  retryMessage: (message_id: string) => invoke<void>("retry_message", { messageId: message_id }),
  deleteAttachmentLocal: (message_id: string) =>
    invoke<ChatMessage>("delete_attachment_local", { messageId: message_id }),
  resendAttachment: (message_id: string) =>
    invoke<ChatMessage>("resend_attachment", { messageId: message_id }),
  clearOutbox: () => invoke<number>("clear_outbox"),
  editMessage: (message_id: string, new_text: string) =>
    invoke<ChatMessage>("edit_message", {
      messageId: message_id,
      newText: new_text,
    }),
  deleteMessage: (message_id: string) =>
    invoke<ChatMessage>("delete_message", { messageId: message_id }),
  connectPeer: (multiaddr: string) => invoke<void>("connect_peer", { multiaddr }),
  listConnectedPeers: () => invoke<string[]>("list_connected_peers"),
  addBootstrapNode: (multiaddr: string, trust_level: string) =>
    invoke<BootstrapNode>("add_bootstrap_node", { multiaddr, trustLevel: trust_level }),
  probeBootstrapNode: (address: string) =>
    invoke<BootstrapNodeProbe>("probe_bootstrap_node", { address }),
  addProbedBootstrapNode: (multiaddr: string) =>
    invoke<BootstrapNode>("add_probed_bootstrap_node", { multiaddr }),
  listBootstrapNodes: () => invoke<BootstrapNode[]>("list_bootstrap_nodes"),
  removeBootstrapNode: (bootstrap_node_id: string) =>
    invoke<void>("remove_bootstrap_node", { bootstrapNodeId: bootstrap_node_id }),
  fetchNodePassport: (bootstrap_node_id: string) =>
    invoke<NodePassportView>("fetch_node_passport", { bootstrapNodeId: bootstrap_node_id }),
  testBootstrapNode: (bootstrap_node_id: string) =>
    invoke<BootstrapNodeTestResult>("test_bootstrap_node", {
      bootstrapNodeId: bootstrap_node_id,
    }),
  getNetworkRoutesStatus: () => invoke<NetworkRoutesStatus>("get_network_routes_status"),
  connectBootstrapNodes: () => invoke<number>("connect_bootstrap_nodes"),
  blockBootstrapNode: (bootstrap_node_id: string) =>
    invoke<void>("block_bootstrap_node", { bootstrapNodeId: bootstrap_node_id }),
  exportBootstrapCatalog: (path: string) => invoke<number>("export_bootstrap_catalog", { path }),
  importBootstrapCatalog: (path: string) =>
    invoke<CatalogIngestStats>("import_bootstrap_catalog", { path }),
  importAccessBundle: (path: string, local_comment?: string | null) =>
    invoke<AccessBundleImportResult>("import_access_bundle", { path, localComment: local_comment ?? null }),
  previewAccessBundle: (path: string) =>
    invoke<AccessBundlePreview>("preview_access_bundle", { path }),
  importAccessBundleText: (text: string, local_comment?: string | null) =>
    invoke<AccessBundleImportResult>("import_access_bundle_text", { text, localComment: local_comment ?? null }),
  exportAccessBundle: (path: string) => invoke<number>("export_access_bundle", { path }),
  listAccessBundleImports: () => invoke<AccessBundleImportRow[]>("list_access_bundle_imports"),
  removeAccessBundleImport: (import_id: string) =>
    invoke<void>("remove_access_bundle_import", { importId: import_id }),
  getBootstrapNetworkSummary: () =>
    invoke<BootstrapNetworkSummary>("get_bootstrap_network_summary"),
  requestBootstrapCatalogFromPeer: (peer_id: string) =>
    invoke<CatalogIngestStats>("request_bootstrap_catalog_from_peer", { peerId: peer_id }),
  requestBootstrapCatalogFromConnectedPeers: () =>
    invoke<PeerCatalogIngest[]>("request_bootstrap_catalog_from_connected_peers"),
  getReachabilityStatus: () => invoke<ReachabilityStatus>("get_reachability_status"),
  getConnectPolicy: () => invoke<ConnectPolicy>("get_connect_policy"),
  setConnectPolicy: (policy: ConnectPolicy) =>
    invoke<void>("set_connect_policy", { policy }),
  listProxies: () => invoke<ProxyView[]>("list_proxies"),
  addProxy: (input: ProxyInput) => invoke<ProxyView[]>("add_proxy", { input }),
  updateProxy: (proxy_id: string, input: ProxyInput) =>
    invoke<ProxyView[]>("update_proxy", { proxyId: proxy_id, input }),
  removeProxy: (proxy_id: string) => invoke<ProxyView[]>("remove_proxy", { proxyId: proxy_id }),
  parseProxyLine: (text: string) => invoke<ProxyInput>("parse_proxy_line", { text }),
  getProxyStatus: () => invoke<ProxyStatus>("get_proxy_status"),
  testProxy: (proxy_id: string | null, input: ProxyInput | null) =>
    invoke<ProxyTestResult>("test_proxy", { proxyId: proxy_id, input }),
  enableProxy: (proxy_id: string) => invoke<ProxyActivation>("enable_proxy", { proxyId: proxy_id }),
  disableProxy: () => invoke<ProxyStatus>("disable_proxy"),
  listRelayReservations: () => invoke<RelayReservationView[]>("list_relay_reservations"),
  forceRelayRefresh: () => invoke<number>("force_relay_refresh"),
  exportBackup: (path: string, backup_password: string, backup_kind: "full" | "identity" | "identity_contacts") =>
    invoke<void>("export_backup", { path, backupPassword: backup_password, backupKind: backup_kind }),
  inspectBackup: (path: string) => invoke<BackupMetadata>("inspect_backup", { path }),
  importBackup: (path: string, backup_password: string, confirm_overwrite: boolean, mode: BackupImportMode) =>
    invoke<void>("import_backup", { path, backupPassword: backup_password, confirmOverwrite: confirm_overwrite, mode }),
  serializeBackup: (backup_password: string, backup_kind: "full" | "identity" | "identity_contacts") =>
    invoke<string>("serialize_backup", { backupPassword: backup_password, backupKind: backup_kind }),
  exportBackupTempFile: (backup_password: string, backup_kind: "full" | "identity" | "identity_contacts") =>
    invoke<string>("export_backup_temp_file", { backupPassword: backup_password, backupKind: backup_kind }),
  createBackupImportTempFile: () => invoke<string>("create_backup_import_temp_file"),
  deleteBackupTempFile: (path: string) => invoke<void>("delete_backup_temp_file", { path }),
  inspectBackupBytes: (b64: string) => invoke<BackupMetadata>("inspect_backup_bytes", { b64 }),
  importBackupBytes: (b64: string, backup_password: string, confirm_overwrite: boolean, mode: BackupImportMode) =>
    invoke<void>("import_backup_bytes", { b64, backupPassword: backup_password, confirmOverwrite: confirm_overwrite, mode }),
  restartApp: () => invoke<void>("restart_app"),
  getAppStatus: () => invoke<AppStatus>("get_app_status"),
  notifyAppResumed: () => invoke<void>("notify_app_resumed"),
  notifyAppBackgrounded: () => invoke<void>("notify_app_backgrounded"),
  getVersionInfo: () => invoke<VersionInfo>("get_version_info"),
};
