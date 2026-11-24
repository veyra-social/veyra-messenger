export type AppError = {
  code: string;
  message: string;
};

export type ParsedInvite = {
  version?: string;
  legacy?: boolean;
  peer_id: string;
  public_key_base64: string;
  fingerprint: string;
  multiaddrs: string[];
  routing_hint_count?: number;
  suggested_display_name?: string | null;
};

export type OwnDevice = {
  device_id: string;
  device_peer_id: string;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  is_current: boolean;
  label?: string | null;
  app_version?: string | null;
};

export type DevicePairingBegin = {
  code: string;
  expires_at: string;
};

export type FileLoggingStatus = {
  enabled: boolean;
  path: string | null;
  total_bytes: number;
};

export type MediaServerInfo = {
  port: number;
  token: string;
};

export type UpdateCheckStatus = {
  current_version: string;
  latest_version: string | null;
  update_available: boolean;
  update_url: string | null;
  last_checked_at: number | null;
  auto_check_enabled: boolean;
};

export type AttachmentReceiveSettings = {
  media: boolean;
  other: boolean;
};

export type ContactRestoreSummary = {
  applied: number;
  duplicate: number;
  skipped: number;
};

export type ChatRestoreConsentPrompt = {
  request_id: string;
  contact_public_key: string;
  contact_name: string;
  events: number;
  bytes: number;
};

export type ChatRestoreSummary = {
  devices_tried: number;
  devices_reached: number;
  applied: number;
  duplicate: number;
  deferred: number;
};

export type DeviceSyncSummary = {
  pulled_applied: number;
  pulled_duplicate: number;
  pulled_deferred: number;
  pushed_applied: number;
  pushed_duplicate: number;
  pushed_deferred: number;
};

export type Contact = {
  local_id: string;
  display_name: string;
  peer_id: string;
  public_key: string;
  fingerprint: string;
  known_multiaddrs: string[];
  trust_status: "unverified" | "verified" | "blocked" | string;
  created_at: string;
  updated_at: string;
  last_seen_at?: string | null;
  presence_status: "online" | "offline" | string;
  presence_label: string;
  peer_avatar_jpeg_base64?: string | null;
  peer_avatar_content_version?: number | null;
  peer_profile_extensions?: ProfileExtensions | null;
  /** The account itself — the row behind the Notes chat. */
  is_self?: boolean;
};

export type Chat = {
  id: string;
  chat_type: "direct" | string;
  title?: string | null;
  group_id?: string | null;
  member_contact_ids: string[];
  created_at: string;
  updated_at: string;
  unread_count: number;
  failed_count?: number;
  last_message_text?: string | null;
  last_message_at?: string | null;
  last_message_direction?: "inbound" | "outbound" | string | null;
  last_message_status?: MessageStatus | string | null;
  is_self_chat?: boolean;
  pinned_at?: string | null;
};

export type TransportKind =
  | "none"
  | "relay"
  | "quic_relay"
  | "wss_relay"
  | "direct_wss"
  | "direct_tcp"
  | "direct_quic"
  | "direct_lan_tcp"
  | "direct_lan_quic"
  | "unknown";

export type ChatTransportMember = {
  peer_id: string;
  display_name: string;
  connected: boolean;
  kind: TransportKind;
  scope: "lan" | "internet" | "unknown";
};

export type ChannelState = "ready" | "none" | "unknown" | "unavailable";

export type ActiveDeliveryPath =
  | "lan"
  | "tcp"
  | "quic"
  | "wss"
  | "relay"
  | "relay_quic"
  | "relay_wss"
  | "web_rtc"
  | "https"
  | "crypto_http"
  | "transit";

export type ChatTransportStatus = {
  chat_type: "direct" | string;
  members: ChatTransportMember[];
  summary_label: string;
  channel_label: string;
  channel_state: ChannelState;
  active_delivery_path: ActiveDeliveryPath | null;
  pending_outbox_count: number;
};

export type MessageStatus =
  | "pending"
  | "sent"
  | "delivered"
  | "read"
  | "failed";

export type ChatMessageState = {
  message_id: string;
  status: MessageStatus | string;
  created_at: string;
  direction: "inbound" | "outbound" | string;
  delivery_diagnostic?: DeliveryDiagnostic | null;
};

export type QuotedMessageInfo = {
  message_id: string;
  excerpt: string;
  author_public_key: string;
};

export type MessageAttachment = {
  id: string;
  transfer_id: string;
  file_name: string;
  mime_type: string;
  media_kind: "image" | "video" | "audio" | "file" | string;
  size_bytes: number;
  sha256_b64: string;
  status: "pending" | "available" | "failed" | string;
  bytes_transferred: number;
  total_bytes: number;
  sent_bytes?: number;
  receiver_decision?: "awaiting" | "accepted" | "declined" | string;
  terminal_reason?: string | null;
  sender_paused?: boolean;
  receiver_paused?: boolean;
  /** Slice E: peer's AttachmentControl v1 support — null unknown, false legacy. */
  peer_transfer_control?: boolean | null;
};

export type ChatFileEntry = {
  attachment_id: string;
  message_id: string;
  file_name: string;
  mime_type: string;
  media_kind: "image" | "video" | "file" | string;
  size_bytes: number;
  local_bytes: number;
  status: "pending" | "available" | "failed" | string;
  direction: "inbound" | "outbound" | string;
  created_at: string;
};

export type ChatStatistics = {
  chat_id: string;
  created_at: string;
  message_count: number;
  file_count: number;
  storage_bytes: number;
  files_total: number;
  page: number;
  page_size: number;
  files: ChatFileEntry[];
};

export type DeliveryDiagnostic = {
  state: "queued" | "no_route" | "retrying" | string;
  retry_count: number;
  next_retry_at?: string | null;
  pending_recipient_count: number;
};

export type ChatMessage = {
  local_id: string;
  message_id: string;
  chat_id: string;
  sender_public_key: string;
  recipient_public_key?: string | null;
  direction: "inbound" | "outbound" | string;
  text: string;
  status: MessageStatus | string;
  protocol_version: string;
  envelope_version: number;
  crypto_suite_version: string;
  created_at: string;
  sent_at?: string | null;
  delivered_at?: string | null;
  received_at?: string | null;
  /** Stored timeline position; see `messageDisplayTimestamp`. */
  display_at: string;
  delivery_diagnostic?: DeliveryDiagnostic | null;
  quote?: QuotedMessageInfo | null;
  attachment?: MessageAttachment | null;
  edited_at?: string | null;
  deleted_at?: string | null;
};

export type CallLogEntry = {
  call_id: string;
  chat_id: string;
  peer_public_key: string;
  direction: "inbound" | "outbound" | string;
  started_at: string;
  answered_at?: string | null;
  ended_at: string;
  end_reason: string;
  duration_seconds: number;
};

export type CurrentCallSnapshot = {
  call_id: string;
  chat_id: string;
  peer_public_key: string;
  // Transport peer of the exact device this call session is bound to
  // (multi-device Round 1b).
  peer_device_peer_id: string;
  direction: "inbound" | "outbound" | string;
  state: string;
  started_at: string;
  answered_at?: string | null;
  remote_sdp?: string | null;
  error?: string | null;
};

export type CallStateChangedPayload = {
  current?: CurrentCallSnapshot | null;
  ended?: CallLogEntry | null;
};

export type CallIceCandidatePayload = {
  call_id: string;
  candidate: string;
  sdp_mid?: string | null;
  sdp_m_line_index?: number | null;
};

export type RtcIceServerConfig = {
  urls: string[];
  username?: string | null;
  credential?: string | null;
};

export type NotificationPrefs = {
  notificationsEnabled: boolean;
  notificationSoundsEnabled: boolean;
  messageSoundEnabled: boolean;
  inviteSoundEnabled: boolean;
  callRingtoneEnabled: boolean;
  vibrationEnabled: boolean;
  notificationPreviewMode: NotificationPreviewMode;
};

export type NotificationPreviewMode = "private" | "sender" | "message";

export type AppNotificationEvent =
  | {
      kind: "message";
      chatId: string;
      messageId: string;
      contactName?: string | null;
      preview?: string | null;
      createdAt: string;
      // Backend-decided: true when this belongs to the startup/resume catch-up
      // burst and must be delivered without a sound cue or banner. Authoritative
      // signal — the backend knows when it is draining backlog. See
      // `arm_notification_quiet` in the Rust node.
      silent?: boolean;
    }
  | {
      kind: "invite";
      contactId: string;
      contactName?: string | null;
      createdAt: string;
      silent?: boolean;
    }
  | {
      kind: "call";
      callId: string;
      chatId: string;
      contactName?: string | null;
      createdAt: string;
      silent?: boolean;
    };

export type LocalProfileSummary = {
  id: string;
  display_name: string;
  fingerprint?: string | null;
  last_used_at?: string | null;
  active: boolean;
};

export type MyProfile = {
  display_name: string;
  public_id: string;
  peer_id: string;
  public_key: string;
  fingerprint: string;
  invite_string: string;
  listen_addresses: string[];
  avatar_jpeg_base64?: string | null;
  profile_extensions: ProfileExtensions;
};

export type ProfileVisibility = "contacts" | "favorites_only";

export type ProfileField = {
  value: string;
  visibility: ProfileVisibility | string;
};

export type ProfileLinkType =
  | "website"
  | "telegram"
  | "whatsapp"
  | "vk"
  | "instagram"
  | "facebook"
  | "youtube"
  | "tiktok"
  | "other";

export type ProfileLink = {
  type: ProfileLinkType | string;
  label?: string | null;
  url: string;
  visibility: ProfileVisibility | string;
};

export type ProfileExtensions = {
  about: ProfileField;
  status: ProfileField;
  mood: ProfileField;
  email: ProfileField;
  phone: ProfileField;
  links: ProfileLink[];
};

export type BootstrapNodeProbe = {
  peer_id: string;
  agent_version: string;
  reachable: boolean;
  is_veyra_bootstrap: boolean;
  supports_relay: boolean;
  observed_multiaddr: string;
  multiaddr_with_peer: string;
};

export type PublicNodeMeta = {
  name: string;
  title: string;
  info: string;
  url?: string | null;
  order?: number | null;
  cluster?: string | null;
};

export type PassportReferenceV2 = {
  kind: string;
  url: string;
  sha256: string;
  cache_ttl_seconds: number;
  expires_at: string;
};

export type NodePassportView = {
  display_name: string;
  description: string;
  operator_kind: string;
  visibility: string;
  region: string;
  cluster: string;
  capacity_tier: string;
  capabilities: string[];
  stats_policy: string;
  created_at: string;
  expires_at: string;
  from_cache: boolean;
};

export type BootstrapNode = {
  id: string;
  peer_id: string;
  node_name?: string | null;
  public_meta?: PublicNodeMeta | null;
  passport_reference?: PassportReferenceV2 | null;
  multiaddrs: string[];
  turn_endpoints?: { urls: string[]; priority?: number | null }[];
  trust_level: string;
  source: string;
  last_seen_at?: string | null;
  expires_at?: string | null;
  success_count: number;
  failure_count: number;
  blocked_at?: string | null;
  created_at: string;
  updated_at: string;
};

export type CatalogIngestStats = {
  accepted: number;
  rejected: number;
  merged: number;
  inserted: number;
  reasons: string[];
};

export type PeerCatalogIngest = {
  peer_id: string;
  stats: CatalogIngestStats | null;
  error: string | null;
};

export type AccessBundleImportResult = {
  import_id: string;
  expired: boolean;
  issuer_fingerprint?: string | null;
  catalog_stats: CatalogIngestStats | null;
  bridges_accepted: number;
  bridges_rejected: number;
  bridge_reasons: string[];
};

export type AccessBundlePreview = {
  network_id: string;
  bundle_expires_at: string;
  expired: boolean;
  issuer_fingerprint?: string | null;
  private_bridge_count: number;
  has_signed_official_catalog: boolean;
  has_encrypted_payload: boolean;
  local_comment?: string | null;
};

export type AccessBundleImportRow = {
  id: string;
  imported_at: string;
  bundle_expires_at: string;
  network_id: string;
  issuer_fingerprint?: string | null;
  local_comment?: string | null;
  status: string;
  bridges_accepted: number;
  bridges_rejected: number;
  catalog_accepted?: number | null;
  catalog_rejected?: number | null;
};

export type BootstrapNetworkSummary = {
  connected: boolean;
  public_bootstrap_count: number;
  private_bridge_count: number;
  connected_peers: number;
  last_successful_route?: string | null;
};

export type NetworkRoutesStatus = {
  connected_peer_ids: string[];
  lan: boolean;
  internet: boolean;
  direct_tcp: boolean;
  direct_quic: boolean;
  direct_wss: boolean;
  relay_quic: boolean;
  relay_wss: boolean;
  relay_other: boolean;
  webrtc: boolean;
};

export type BootstrapNodeTestResult = {
  reachable: boolean;
  rtt_ms?: number | null;
};

export type VersionInfo = {
  app_version: string;
  protocol_version: string;
  message_envelope_version: number;
  backup_format_version: number;
  database_schema_version: number;
  crypto_suite_version: string;
  debug_build: boolean;
};

export type DesktopIntegrationPrefs = {
  closeToTray: boolean;
  autostart: boolean;
};

export type BackupMetadata = {
  backup_format_version: number;
  app_version: string;
  created_at: string;
  database_schema_version: number;
  crypto_suite_version: string;
  profile_public_id: string;
  backup_kind: "full" | "identity" | "identity_contacts" | string;
  profile_display_name?: string | null;
};

// Multi-device Round 0: "restore" replays the backup onto this same
// installation as-is (including its transport identity), "link" imports the
// profile as a new device with a fresh local transport identity.
export type BackupImportMode = "restore" | "link";

export type ReachabilityStatus = "public" | "private" | "unknown";

export type ReservationStatus = "pending" | "active" | "failed" | "expired";

export type RelayReservationView = {
  relay_peer_id: string;
  reserved_at: string;
  renew_at: string;
  status: ReservationStatus;
  last_error?: string | null;
};

export type ConnectPolicy = "standard" | "lan_only" | "degraded_no_uplink";

export type TrayState =
  | "connected_secure"
  | "new_message"
  | "syncing"
  | "offline"
  | "warning_blocked"
  | "muted_dnd";

export type AppStatus = VersionInfo & {
  initialized: boolean;
  locked: boolean;
  profile_display_name?: string | null;
  p2p_node_status: string;
  listen_addresses: string[];
  p2p_listen_addresses_circuit: string[];
  connected_peers: number;
  contacts_count: number;
  chats_count: number;
  pending_outbox_count: number;
  failed_outbox_count: number;
  bootstrap_nodes_count: number;
  reachability_status: ReachabilityStatus;
  active_relay_reservations: number;
  transport_protocols: string[];
  connect_policy: ConnectPolicy;
  known_contact_routes: number;
  proxy: ProxyStatus;
};

export type ProxyKind = "socks5" | "http_connect";

export type ProxyView = {
  id: string;
  label: string;
  kind: ProxyKind;
  host: string;
  port: number;
  username?: string | null;
  has_password: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_test_at?: string | null;
  last_test_ok?: boolean | null;
  last_error_code?: string | null;
};

/// `password`: omitted keeps the stored secret, `""` clears it, anything else
/// replaces it.
export type ProxyInput = {
  label: string;
  kind: ProxyKind;
  host: string;
  port: number;
  username?: string | null;
  password?: string | null;
};

export type ProxyTestResult = {
  ok: boolean;
  proxy_reached: boolean;
  target_reached: boolean;
  latency_ms?: number | null;
  error_code?: string | null;
};

export type ProxyHealth = "off" | "checking" | "online" | "down";

export type ProxyStatus = {
  enabled: boolean;
  active_id?: string | null;
  active_label?: string | null;
  health: ProxyHealth;
  last_error_code?: string | null;
  outage_id: number;
};

export type ProxyActivation = {
  test: ProxyTestResult;
  status: ProxyStatus;
};
