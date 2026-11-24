use crate::crypto::identity::{sign, verify};
use crate::crypto::storage_crypto::{b64, decrypt_string, encrypt_string, from_b64, StorageKey};
use crate::errors::{AppError, AppResult};
use crate::models::MessageEnvelope;
use crate::p2p::protocol::{FILE_CHUNK_SIZE, MAX_ATTACHMENT_BYTES};
use crate::version::{
    CRYPTO_SUITE_VERSION, CRYPTO_SUITE_VERSION_V1, MESSAGE_ENVELOPE_VERSION,
    MESSAGE_ENVELOPE_VERSION_V1, PROTOCOL_VERSION,
};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{
    EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret,
};
use zeroize::Zeroize;

/// Maximum character count for a quoted excerpt. Sender truncates to this size
/// before signing the payload; the receiver does not enforce a hard limit but
/// the UI clamps display similarly.
pub const QUOTE_EXCERPT_MAX_CHARS: usize = 280;

/// Plaintext payload format version. v2 introduces structured plaintext for
/// quoted messages. Plain messages keep the legacy raw-string format.
const PLAINTEXT_FORMAT_V2: u8 = 2;

/// Plaintext payload format version 3 carries message mutation events
/// (edit, delete) targeting an already-delivered message. Wraps a signed
/// direct-message envelope (the envelope identity provides the authority) and
/// is dispatched through the existing direct-message protocol, so old clients
/// see structured JSON instead of native edit/delete handling — same
/// compatibility trade-off as the v2 quote payload.
const PLAINTEXT_FORMAT_V3: u8 = 3;

/// Quote metadata attached to a sent message (before encryption).
#[derive(Debug, Clone)]
pub struct QuotedMessageMeta {
    pub message_id: String,
    pub excerpt: String,
    pub author_public_key: String,
}

#[derive(Debug, Clone)]
pub struct AttachmentManifest {
    pub transfer_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub media_kind: String,
    pub size_bytes: i64,
    pub sha256_b64: String,
    pub file_key_b64: String,
    pub chunk_size: i64,
    pub chunk_count: i64,
}

/// Longest sender-supplied attachment name accepted off the wire. The export
/// sanitiser shortens further; this only keeps an absurd name out of the
/// database in the first place.
const MANIFEST_MAX_FILE_NAME_CHARS: usize = 255;
/// Longest accepted MIME string and media-kind label.
const MANIFEST_MAX_MIME_CHARS: usize = 128;
const MANIFEST_MAX_MEDIA_KIND_CHARS: usize = 32;
/// ChaCha20-Poly1305 file key and SHA-256 digest are both exactly 32 bytes.
const MANIFEST_KEY_BYTES: usize = 32;
const MANIFEST_DIGEST_BYTES: usize = 32;
/// Policy bound on how many chunks one transfer may be split into: the
/// largest accepted attachment at the standard chunk size. It is what stops a
/// manifest claiming a one-byte chunk size for a gigabyte file — the chunk
/// count would have to be consistent with it, and consistent is enormous.
const MANIFEST_MAX_CHUNK_COUNT: i64 =
    (MAX_ATTACHMENT_BYTES as i64 + FILE_CHUNK_SIZE as i64 - 1) / FILE_CHUNK_SIZE as i64;
/// Bound on the identifiers a quote carries; a public key is 44 base64 chars
/// and a message id is a UUID, so this is generous by design.
const QUOTE_MAX_ID_CHARS: usize = 128;

/// Validates an inbound attachment manifest as one object.
///
/// Every field here is chosen by the sender, and until now they were written
/// to the database almost verbatim — only `media_kind` was distrusted, and
/// only for policy (code review 2026-07-27, P2). A manifest that fails any
/// check is rejected whole: storing the fields that happen to look plausible
/// is how a half-valid transfer ends up half-created.
pub fn validate_inbound_attachment_manifest(manifest: &AttachmentManifest) -> AppResult<()> {
    if !crate::storage::attachment_names::is_safe_transfer_id(&manifest.transfer_id) {
        return Err(AppError::MessageDeliveryFailed);
    }
    let file_name_chars = manifest.file_name.chars().count();
    if manifest.file_name.trim().is_empty() || file_name_chars > MANIFEST_MAX_FILE_NAME_CHARS {
        return Err(AppError::MessageDeliveryFailed);
    }
    if manifest.mime_type.chars().count() > MANIFEST_MAX_MIME_CHARS
        || manifest.mime_type.chars().any(|c| c.is_control())
        || manifest.media_kind.chars().count() > MANIFEST_MAX_MEDIA_KIND_CHARS
    {
        return Err(AppError::MessageDeliveryFailed);
    }
    if manifest.size_bytes < 0 || manifest.size_bytes > MAX_ATTACHMENT_BYTES as i64 {
        return Err(AppError::MessageDeliveryFailed);
    }
    if manifest.chunk_size <= 0 || manifest.chunk_size > FILE_CHUNK_SIZE as i64 {
        return Err(AppError::MessageDeliveryFailed);
    }
    // The same formula the sender uses (`attachment_manifest_for_*`): an
    // empty file is still one chunk.
    let expected_chunks =
        ((manifest.size_bytes + manifest.chunk_size - 1) / manifest.chunk_size).max(1);
    if manifest.chunk_count != expected_chunks || manifest.chunk_count > MANIFEST_MAX_CHUNK_COUNT {
        return Err(AppError::MessageDeliveryFailed);
    }
    if from_b64(&manifest.file_key_b64)?.len() != MANIFEST_KEY_BYTES
        || from_b64(&manifest.sha256_b64)?.len() != MANIFEST_DIGEST_BYTES
    {
        return Err(AppError::MessageDeliveryFailed);
    }
    Ok(())
}

/// Validates the quote metadata that rides inside an inbound plaintext.
///
/// The excerpt is display text and the ids address a local row, so both are
/// bounded before they reach storage.
pub fn validate_inbound_quote(quote: &QuotedMessageMeta) -> AppResult<()> {
    if quote.message_id.is_empty()
        || quote.message_id.chars().count() > QUOTE_MAX_ID_CHARS
        || quote.author_public_key.chars().count() > QUOTE_MAX_ID_CHARS
        || quote.excerpt.chars().count() > QUOTE_EXCERPT_MAX_CHARS
    {
        return Err(AppError::MessageDeliveryFailed);
    }
    Ok(())
}

/// Decoded plaintext payload after envelope decryption.
#[derive(Debug, Clone)]
pub struct DirectMessagePayload {
    pub text: String,
    pub quote: Option<QuotedMessageMeta>,
    pub mutation: Option<MessageMutation>,
    pub attachment: Option<AttachmentManifest>,
    pub attachment_control: Option<AttachmentControl>,
}

/// File-transfer-polish slice A: a service control event for one attachment
/// transfer, carried E2E-encrypted and account-signed over the ordinary
/// direct-message path. Never shown as a chat message. The envelope
/// identity is the authority source — the inbound handler verifies the
/// sender's role on `(message_id, transfer_id)` before applying, and the
/// per-side monotonic `seq` drops replays and stale reordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentControl {
    /// accept | decline | pause | resume | cancel
    pub action: String,
    pub target_message_id: String,
    pub transfer_id: String,
    pub seq: i64,
}

pub const ATTACHMENT_CONTROL_ACTIONS: [&str; 5] =
    ["accept", "decline", "pause", "resume", "cancel"];

/// Edit/delete operation carried inside a v3 plaintext payload. The envelope
/// identity is the source of truth for authority — the inbound handler must
/// verify that `target_message_id` was originally authored by
/// `envelope.sender_public_key` before applying.
#[derive(Debug, Clone)]
pub enum MessageMutation {
    /// Replace the body of `target_message_id` with `new_text`.
    Edit {
        target_message_id: String,
        new_text: String,
    },
    /// Soft-delete `target_message_id`. The receiver shows a tombstone in
    /// place of the original body.
    Delete { target_message_id: String },
}

/// On-wire JSON representation of a quoted message, embedded inside the
/// encrypted plaintext. Field order is fixed by serde for canonical encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuotedMessageWire {
    message_id: String,
    excerpt: String,
    author_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttachmentManifestWire {
    transfer_id: String,
    file_name: String,
    mime_type: String,
    media_kind: String,
    size_bytes: i64,
    sha256_b64: String,
    file_key_b64: String,
    chunk_size: i64,
    chunk_count: i64,
}

/// On-wire JSON for v2-format plaintext. The `_veyra_msg_v` marker is required
/// so that legitimate JSON-shaped user text is not misparsed as a quote payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaintextV2 {
    #[serde(rename = "_veyra_msg_v")]
    veyra_msg_v: u8,
    text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quote: Option<QuotedMessageWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment: Option<AttachmentManifestWire>,
}

/// On-wire JSON for v3-format plaintext (message mutation event). The
/// `_veyra_msg_v` marker disambiguates it from v2 quote payloads and from raw
/// user text; `op` is `"edit"` or `"delete"`; `target` references the original
/// message_id. `text` is only present for edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaintextV3 {
    #[serde(rename = "_veyra_msg_v")]
    veyra_msg_v: u8,
    op: String,
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

/// A v4 plaintext is an attachment-transfer control event. A pre-v4
/// receiver decodes it as legacy plain text (structured JSON in the chat) —
/// the slice-E capability gate keeps mixed fleets on the old eager mode so
/// this never fires there.
const PLAINTEXT_FORMAT_V4: u8 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaintextV4 {
    #[serde(rename = "_veyra_msg_v")]
    veyra_msg_v: u8,
    ctl: String,
    action: String,
    target: String,
    transfer_id: String,
    seq: i64,
}

/// Encodes the plaintext that will be encrypted into the envelope. When no
/// quote is attached, the legacy raw-string form is preserved so that
/// pre-v2 clients keep receiving normal messages unchanged.
pub fn encode_message_plaintext(text: &str, quote: Option<&QuotedMessageMeta>) -> String {
    encode_message_plaintext_with_attachment(text, quote, None)
}

pub fn encode_message_plaintext_with_attachment(
    text: &str,
    quote: Option<&QuotedMessageMeta>,
    attachment: Option<&AttachmentManifest>,
) -> String {
    if quote.is_none() && attachment.is_none() {
        return text.to_string();
    }
    let wire = PlaintextV2 {
        veyra_msg_v: PLAINTEXT_FORMAT_V2,
        text: text.to_string(),
        quote: quote.map(|q| QuotedMessageWire {
            message_id: q.message_id.clone(),
            excerpt: q.excerpt.clone(),
            author_public_key: q.author_public_key.clone(),
        }),
        attachment: attachment.map(|item| AttachmentManifestWire {
            transfer_id: item.transfer_id.clone(),
            file_name: item.file_name.clone(),
            mime_type: item.mime_type.clone(),
            media_kind: item.media_kind.clone(),
            size_bytes: item.size_bytes,
            sha256_b64: item.sha256_b64.clone(),
            file_key_b64: item.file_key_b64.clone(),
            chunk_size: item.chunk_size,
            chunk_count: item.chunk_count,
        }),
    };
    serde_json::to_string(&wire).unwrap_or_else(|_| text.to_string())
}

/// Encodes a mutation event (edit or delete) as v3 plaintext.
pub fn encode_message_mutation(mutation: &MessageMutation) -> String {
    let (op, target, text) = match mutation {
        MessageMutation::Edit {
            target_message_id,
            new_text,
        } => ("edit", target_message_id.as_str(), Some(new_text.clone())),
        MessageMutation::Delete { target_message_id } => {
            ("delete", target_message_id.as_str(), None)
        }
    };
    let wire = PlaintextV3 {
        veyra_msg_v: PLAINTEXT_FORMAT_V3,
        op: op.to_string(),
        target: target.to_string(),
        text,
    };
    serde_json::to_string(&wire).unwrap_or_default()
}

/// Encodes an attachment-transfer control event as v4 plaintext.
pub fn encode_attachment_control(control: &AttachmentControl) -> String {
    let wire = PlaintextV4 {
        veyra_msg_v: PLAINTEXT_FORMAT_V4,
        ctl: "attachment".to_string(),
        action: control.action.clone(),
        target: control.target_message_id.clone(),
        transfer_id: control.transfer_id.clone(),
        seq: control.seq,
    };
    serde_json::to_string(&wire).unwrap_or_default()
}

/// Creates a signed direct-message envelope carrying an attachment-transfer
/// control event. Same wire shape as a regular direct message; receivers
/// detect it in `decode_message_plaintext` and route to the transfer state
/// machine instead of inserting a chat row.
pub fn create_attachment_control_envelope(
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    control: &AttachmentControl,
    envelope_type: &str,
) -> AppResult<MessageEnvelope> {
    let plaintext = encode_attachment_control(control);
    create_envelope_with_plaintext(
        storage_key,
        signing_key,
        chat_id,
        sender_public_key,
        recipient_public_key,
        &plaintext,
        envelope_type,
    )
}

/// Decodes plaintext produced by `encode_message_plaintext`,
/// `encode_message_mutation` or `encode_attachment_control`. Falls back to
/// treating the input as legacy plain text when no v2/v3/v4 marker is found.
pub fn decode_message_plaintext(plaintext: &str) -> DirectMessagePayload {
    // The structured formats share the `_veyra_msg_v` marker; try v4 and v3
    // first so a control/mutation payload that happens to deserialize as v2
    // (with a null quote) cannot mask its op.
    if let Ok(parsed) = serde_json::from_str::<PlaintextV4>(plaintext) {
        if parsed.veyra_msg_v == PLAINTEXT_FORMAT_V4
            && parsed.ctl == "attachment"
            && ATTACHMENT_CONTROL_ACTIONS.contains(&parsed.action.as_str())
        {
            return DirectMessagePayload {
                text: String::new(),
                quote: None,
                mutation: None,
                attachment: None,
                attachment_control: Some(AttachmentControl {
                    action: parsed.action,
                    target_message_id: parsed.target,
                    transfer_id: parsed.transfer_id,
                    seq: parsed.seq,
                }),
            };
        }
    }
    if let Ok(parsed) = serde_json::from_str::<PlaintextV3>(plaintext) {
        if parsed.veyra_msg_v == PLAINTEXT_FORMAT_V3 {
            let mutation = match parsed.op.as_str() {
                "edit" => Some(MessageMutation::Edit {
                    target_message_id: parsed.target,
                    new_text: parsed.text.unwrap_or_default(),
                }),
                "delete" => Some(MessageMutation::Delete {
                    target_message_id: parsed.target,
                }),
                _ => None,
            };
            if mutation.is_some() {
                return DirectMessagePayload {
                    text: String::new(),
                    quote: None,
                    mutation,
                    attachment: None,
                    attachment_control: None,
                };
            }
        }
    }
    if let Ok(parsed) = serde_json::from_str::<PlaintextV2>(plaintext) {
        if parsed.veyra_msg_v == PLAINTEXT_FORMAT_V2 {
            let quote = parsed.quote.map(|q| QuotedMessageMeta {
                message_id: q.message_id,
                excerpt: q.excerpt,
                author_public_key: q.author_public_key,
            });
            return DirectMessagePayload {
                text: parsed.text,
                quote,
                mutation: None,
                attachment: parsed.attachment.map(|item| AttachmentManifest {
                    transfer_id: item.transfer_id,
                    file_name: item.file_name,
                    mime_type: item.mime_type,
                    media_kind: item.media_kind,
                    size_bytes: item.size_bytes,
                    sha256_b64: item.sha256_b64,
                    file_key_b64: item.file_key_b64,
                    chunk_size: item.chunk_size,
                    chunk_count: item.chunk_count,
                }),
                attachment_control: None,
            };
        }
    }
    DirectMessagePayload {
        text: plaintext.to_string(),
        quote: None,
        mutation: None,
        attachment: None,
        attachment_control: None,
    }
}

/// Creates a signed direct-message envelope carrying an edit/delete mutation
/// event in its plaintext. Same wire shape as a regular direct message, just
/// with a structured v3 plaintext payload — receivers detect the mutation in
/// `decode_message_plaintext` and route to the mutation handler instead of
/// inserting a new message row.
pub fn create_mutation_envelope(
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    mutation: &MessageMutation,
    envelope_type: &str,
) -> AppResult<MessageEnvelope> {
    let plaintext = encode_message_mutation(mutation);
    create_envelope_with_plaintext(
        storage_key,
        signing_key,
        chat_id,
        sender_public_key,
        recipient_public_key,
        &plaintext,
        envelope_type,
    )
}

/// Creates a signed MVP message envelope using local application-level encryption.
pub fn create_envelope(
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    text: &str,
    envelope_type: &str,
    quote: Option<&QuotedMessageMeta>,
) -> AppResult<MessageEnvelope> {
    let plaintext = encode_message_plaintext(text, quote);
    create_envelope_with_plaintext(
        storage_key,
        signing_key,
        chat_id,
        sender_public_key,
        recipient_public_key,
        &plaintext,
        envelope_type,
    )
}

pub fn create_attachment_envelope(
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    text: &str,
    envelope_type: &str,
    quote: Option<&QuotedMessageMeta>,
    attachment: &AttachmentManifest,
) -> AppResult<MessageEnvelope> {
    let plaintext = encode_message_plaintext_with_attachment(text, quote, Some(attachment));
    create_envelope_with_plaintext(
        storage_key,
        signing_key,
        chat_id,
        sender_public_key,
        recipient_public_key,
        &plaintext,
        envelope_type,
    )
}

fn create_envelope_with_plaintext(
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    plaintext: &str,
    envelope_type: &str,
) -> AppResult<MessageEnvelope> {
    // Direct messages use v2 (ephemeral sender key). Non-direct (self/broadcast)
    // messages keep using the local storage key.
    let (encrypted, ephemeral_public_key, envelope_version, crypto_suite) =
        match recipient_public_key.as_deref() {
            Some(recipient_pk) => {
                let (enc, eph_pk) = encrypt_direct_text_v2(recipient_pk, plaintext)?;
                (
                    enc,
                    Some(eph_pk),
                    MESSAGE_ENVELOPE_VERSION,
                    CRYPTO_SUITE_VERSION,
                )
            }
            None => (
                encrypt_string(storage_key, plaintext)?,
                None,
                MESSAGE_ENVELOPE_VERSION,
                CRYPTO_SUITE_VERSION,
            ),
        };

    let (nonce, ciphertext) = encrypted.split_once(':').unwrap_or(("", &encrypted));
    let message_id = Uuid::new_v4().to_string();
    let created_at = Utc::now().to_rfc3339();
    // v2 signed payload binds the ephemeral public key so it cannot be swapped.
    let signed_payload = build_signed_payload(
        PROTOCOL_VERSION,
        envelope_version,
        crypto_suite,
        &message_id,
        chat_id,
        ciphertext,
        ephemeral_public_key.as_deref(),
    );

    Ok(MessageEnvelope {
        protocol_version: PROTOCOL_VERSION.to_string(),
        message_envelope_version: envelope_version,
        crypto_suite_version: crypto_suite.to_string(),
        envelope_type: envelope_type.to_string(),
        message_id,
        chat_id: chat_id.to_string(),
        sender_public_key: sender_public_key.to_string(),
        recipient_public_key,
        ciphertext: ciphertext.to_string(),
        nonce: nonce.to_string(),
        signature: sign(signing_key, signed_payload.as_bytes()),
        created_at,
        ephemeral_public_key,
    })
}

fn build_signed_payload(
    protocol_version: &str,
    envelope_version: i64,
    crypto_suite: &str,
    message_id: &str,
    chat_id: &str,
    ciphertext: &str,
    ephemeral_public_key: Option<&str>,
) -> String {
    match ephemeral_public_key {
        Some(eph_pk) => format!(
            "{}|{}|{}|{}|{}|{}|{}",
            protocol_version,
            envelope_version,
            crypto_suite,
            message_id,
            chat_id,
            ciphertext,
            eph_pk
        ),
        None => format!(
            "{}|{}|{}|{}|{}|{}",
            protocol_version, envelope_version, crypto_suite, message_id, chat_id, ciphertext
        ),
    }
}

/// Verifies and decrypts an envelope body.
#[allow(dead_code)]
pub fn open_envelope(storage_key: &StorageKey, envelope: &MessageEnvelope) -> AppResult<String> {
    verify_envelope_signature(envelope)?;
    decrypt_string(
        storage_key,
        &format!("{}:{}", envelope.nonce, envelope.ciphertext),
    )
}

/// Verifies and decrypts an envelope for this recipient. v2 direct envelopes
/// use the per-message ephemeral sender key; v1 direct envelopes use the static
/// sender key. Non-direct envelopes fall back to the local storage key.
pub fn open_envelope_for_recipient(
    storage_key: &StorageKey,
    recipient_signing_key: &SigningKey,
    envelope: &MessageEnvelope,
) -> AppResult<String> {
    verify_envelope_signature(envelope)?;
    if envelope.recipient_public_key.is_none() {
        return decrypt_string(
            storage_key,
            &format!("{}:{}", envelope.nonce, envelope.ciphertext),
        );
    }
    // Dispatch on version: v2 uses ephemeral key, v1 uses static sender key.
    if envelope.message_envelope_version >= MESSAGE_ENVELOPE_VERSION
        && envelope.ephemeral_public_key.is_some()
    {
        decrypt_direct_text_v2(recipient_signing_key, envelope)
    } else {
        decrypt_direct_text(recipient_signing_key, envelope)
    }
}

/// Contact-side restore: the RECIPIENT re-derives the per-message content
/// key of a direct envelope so it can hand it back to the envelope's own
/// author. The author cannot open its own v2 envelope (the ephemeral sender
/// secret dies with the send), and this key opens exactly one message the
/// author wrote itself — nothing else of the conversation.
///
/// v1 envelopes (static pair key) return `None`: the author derives that key
/// on its own and no disclosure is needed.
pub fn content_key_for_recipient(
    recipient_signing_key: &SigningKey,
    envelope: &MessageEnvelope,
) -> AppResult<Option<String>> {
    let Some(recipient_public_key) = envelope.recipient_public_key.as_deref() else {
        return Ok(None);
    };
    if envelope.message_envelope_version < MESSAGE_ENVELOPE_VERSION
        || envelope.ephemeral_public_key.is_none()
    {
        return Ok(None);
    }
    let eph_bytes: [u8; 32] = from_b64(envelope.ephemeral_public_key.as_deref().unwrap_or(""))?
        .try_into()
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let ephemeral_public = X25519PublicKey::from(eph_bytes);
    let recipient_secret = X25519StaticSecret::from(recipient_signing_key.to_scalar_bytes());
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
    let key = derive_direct_message_key_v2(shared_secret.as_bytes(), recipient_public_key)?;
    Ok(Some(b64(&key.0)))
}

/// Contact-side restore, author side: verifies that this envelope is the
/// author's own (signature over the ciphertext) and opens it. `content_key`
/// is the key the recipient disclosed for a v2 envelope; a v1 envelope is
/// opened with the pair key the author derives itself.
///
/// The AEAD tag is what makes the restore honest: a contact that hands back
/// a different plaintext, ciphertext or key fails to decrypt here.
pub fn open_own_envelope_with_content_key(
    author_signing_key: &SigningKey,
    author_public_key: &str,
    envelope: &MessageEnvelope,
    content_key: Option<&str>,
) -> AppResult<String> {
    if envelope.sender_public_key != author_public_key {
        return Err(AppError::InvalidSignature);
    }
    verify_envelope_signature(envelope)?;
    let recipient_public_key = envelope
        .recipient_public_key
        .as_deref()
        .ok_or(AppError::MessageDecryptionFailed)?;
    let key = match content_key {
        Some(raw) => {
            let bytes: [u8; 32] = from_b64(raw)?
                .try_into()
                .map_err(|_| AppError::MessageDecryptionFailed)?;
            StorageKey(bytes)
        }
        // v1: the static pair key, derived from our own signing key.
        None => direct_message_key_from_sender(
            author_signing_key,
            author_public_key,
            recipient_public_key,
        )?,
    };
    decrypt_string(&key, &format!("{}:{}", envelope.nonce, envelope.ciphertext))
}

pub fn verify_envelope_signature(envelope: &MessageEnvelope) -> AppResult<()> {
    let signed_payload = build_signed_payload(
        &envelope.protocol_version,
        envelope.message_envelope_version,
        &envelope.crypto_suite_version,
        &envelope.message_id,
        &envelope.chat_id,
        &envelope.ciphertext,
        envelope.ephemeral_public_key.as_deref(),
    );
    verify(
        &from_b64(&envelope.sender_public_key)?,
        signed_payload.as_bytes(),
        &from_b64(&envelope.signature)?,
    )?;
    Ok(())
}

fn encrypt_direct_text(
    sender_signing_key: &SigningKey,
    sender_public_key: &str,
    recipient_public_key: &str,
    text: &str,
) -> AppResult<String> {
    let key = direct_message_key_from_sender(
        sender_signing_key,
        sender_public_key,
        recipient_public_key,
    )?;
    encrypt_string(&key, text)
}

fn decrypt_direct_text(
    recipient_signing_key: &SigningKey,
    envelope: &MessageEnvelope,
) -> AppResult<String> {
    let recipient_public_key = envelope
        .recipient_public_key
        .as_deref()
        .ok_or(AppError::MessageDecryptionFailed)?;
    let key = direct_message_key_from_recipient(
        recipient_signing_key,
        &envelope.sender_public_key,
        recipient_public_key,
    )?;
    decrypt_string(&key, &format!("{}:{}", envelope.nonce, envelope.ciphertext))
}

fn direct_message_key_from_sender(
    sender_signing_key: &SigningKey,
    sender_public_key: &str,
    recipient_public_key: &str,
) -> AppResult<StorageKey> {
    let sender_secret = X25519StaticSecret::from(sender_signing_key.to_scalar_bytes());
    let recipient_public = ed25519_public_to_x25519(recipient_public_key)?;
    derive_direct_message_key(
        sender_secret.diffie_hellman(&recipient_public).as_bytes(),
        sender_public_key,
        recipient_public_key,
    )
}

fn direct_message_key_from_recipient(
    recipient_signing_key: &SigningKey,
    sender_public_key: &str,
    recipient_public_key: &str,
) -> AppResult<StorageKey> {
    let recipient_secret = X25519StaticSecret::from(recipient_signing_key.to_scalar_bytes());
    let sender_public = ed25519_public_to_x25519(sender_public_key)?;
    derive_direct_message_key(
        recipient_secret.diffie_hellman(&sender_public).as_bytes(),
        sender_public_key,
        recipient_public_key,
    )
}

fn ed25519_public_to_x25519(public_key: &str) -> AppResult<X25519PublicKey> {
    let bytes = from_b64(public_key)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    let verifying_key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| AppError::MessageEncryptionFailed)?;
    Ok(X25519PublicKey::from(
        verifying_key.to_montgomery().to_bytes(),
    ))
}

/// v2 sender: generate a per-message ephemeral X25519 key, ECDH with the
/// receiver's static X25519 key, HKDF → ChaCha20-Poly1305 key.
/// Returns `(encrypted_nonce:ciphertext, ephemeral_public_key_b64)`.
/// The ephemeral secret is consumed and zeroed by `diffie_hellman`.
fn encrypt_direct_text_v2(recipient_public_key: &str, text: &str) -> AppResult<(String, String)> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_x25519 = ed25519_public_to_x25519(recipient_public_key)?;
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);
    let key = derive_direct_message_key_v2(shared_secret.as_bytes(), recipient_public_key)?;
    let encrypted = encrypt_string(&key, text)?;
    Ok((encrypted, b64(ephemeral_public.as_bytes())))
}

/// v2 receiver: ECDH(receiver static secret, ephemeral sender public key) → key → decrypt.
fn decrypt_direct_text_v2(
    recipient_signing_key: &SigningKey,
    envelope: &MessageEnvelope,
) -> AppResult<String> {
    let eph_b64 = envelope
        .ephemeral_public_key
        .as_deref()
        .ok_or(AppError::MessageDecryptionFailed)?;
    let eph_bytes: [u8; 32] = from_b64(eph_b64)?
        .try_into()
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let ephemeral_public = X25519PublicKey::from(eph_bytes);
    let recipient_secret = X25519StaticSecret::from(recipient_signing_key.to_scalar_bytes());
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
    let recipient_public_key = envelope
        .recipient_public_key
        .as_deref()
        .ok_or(AppError::MessageDecryptionFailed)?;
    let key = derive_direct_message_key_v2(shared_secret.as_bytes(), recipient_public_key)?;
    decrypt_string(&key, &format!("{}:{}", envelope.nonce, envelope.ciphertext))
}

/// HKDF for v2: domain-separated from v1; binds to the recipient's long-term key.
fn derive_direct_message_key_v2(
    shared_secret: &[u8; 32],
    recipient_public_key: &str,
) -> AppResult<StorageKey> {
    let salt = format!("veyra-direct-message-v2:{}", recipient_public_key);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret);
    let mut key = [0_u8; 32];
    hk.expand(b"veyra message body v2", &mut key)
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    let derived = StorageKey(key);
    // The array is `Copy`, so the HKDF output outlives the construction.
    key.zeroize();
    Ok(derived)
}

fn derive_direct_message_key(
    shared_secret: &[u8; 32],
    sender_public_key: &str,
    recipient_public_key: &str,
) -> AppResult<StorageKey> {
    let mut salt_parts = [sender_public_key, recipient_public_key];
    salt_parts.sort_unstable();
    let salt = format!(
        "veyra-direct-message-v1:{}:{}",
        salt_parts[0], salt_parts[1]
    );
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret);
    let mut key = [0_u8; 32];
    hk.expand(b"veyra message body", &mut key)
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    let derived = StorageKey(key);
    key.zeroize();
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};

    #[test]
    fn attachment_control_plaintext_round_trips_and_rejects_unknown_action() {
        let control = AttachmentControl {
            action: "pause".to_string(),
            target_message_id: "m-1".to_string(),
            transfer_id: "t-1".to_string(),
            seq: 7,
        };
        let decoded = decode_message_plaintext(&encode_attachment_control(&control));
        assert_eq!(decoded.attachment_control, Some(control.clone()));
        assert!(decoded.mutation.is_none());
        assert!(decoded.text.is_empty());

        // An unknown action never becomes a control (and, being valid JSON
        // without the other markers, falls through to legacy text).
        let forged = AttachmentControl {
            action: "detonate".to_string(),
            ..control
        };
        let decoded = decode_message_plaintext(&encode_attachment_control(&forged));
        assert!(decoded.attachment_control.is_none());
    }

    // ── v2 ephemeral sender key tests ────────────────────────────────────────

    #[test]
    fn v2_direct_message_envelope_round_trip() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat-v2",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "hello bob v2",
            "direct_message_envelope",
            None,
        )
        .unwrap();

        assert_eq!(
            envelope.message_envelope_version, MESSAGE_ENVELOPE_VERSION,
            "new direct messages must use the current envelope version"
        );
        assert!(
            envelope.ephemeral_public_key.is_some(),
            "v2 envelope must carry an ephemeral sender public key"
        );
        assert_eq!(
            open_envelope_for_recipient(&key_b, &bob.signing_key, &envelope).unwrap(),
            "hello bob v2"
        );
    }

    fn valid_manifest() -> AttachmentManifest {
        AttachmentManifest {
            transfer_id: Uuid::new_v4().to_string(),
            file_name: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            media_kind: "image".to_string(),
            size_bytes: FILE_CHUNK_SIZE as i64 + 1,
            sha256_b64: b64([1_u8; 32]),
            file_key_b64: b64([2_u8; 32]),
            chunk_size: FILE_CHUNK_SIZE as i64,
            chunk_count: 2,
        }
    }

    #[test]
    fn a_well_formed_manifest_passes() {
        validate_inbound_attachment_manifest(&valid_manifest()).unwrap();

        // An empty file is still one chunk — the sender's own formula.
        let mut empty = valid_manifest();
        empty.size_bytes = 0;
        empty.chunk_count = 1;
        validate_inbound_attachment_manifest(&empty).unwrap();
    }

    #[test]
    fn manifests_are_rejected_whole_on_any_bad_field() {
        let cases: Vec<(&str, Box<dyn Fn(&mut AttachmentManifest)>)> = vec![
            (
                "transfer id escaping the attachments directory",
                Box::new(|m: &mut AttachmentManifest| m.transfer_id = "../../etc".to_string()),
            ),
            (
                "empty transfer id",
                Box::new(|m: &mut AttachmentManifest| m.transfer_id = String::new()),
            ),
            (
                "blank file name",
                Box::new(|m: &mut AttachmentManifest| m.file_name = "   ".to_string()),
            ),
            (
                "absurd file name",
                Box::new(|m: &mut AttachmentManifest| m.file_name = "a".repeat(4096)),
            ),
            (
                "mime with a control character",
                Box::new(|m: &mut AttachmentManifest| m.mime_type = "image/\u{0}jpeg".to_string()),
            ),
            (
                "negative size",
                Box::new(|m: &mut AttachmentManifest| m.size_bytes = -1),
            ),
            (
                "size over the policy cap",
                Box::new(|m: &mut AttachmentManifest| {
                    m.size_bytes = MAX_ATTACHMENT_BYTES as i64 + 1
                }),
            ),
            (
                "zero chunk size",
                Box::new(|m: &mut AttachmentManifest| m.chunk_size = 0),
            ),
            (
                "chunk size above the wire chunk",
                Box::new(|m: &mut AttachmentManifest| m.chunk_size = FILE_CHUNK_SIZE as i64 + 1),
            ),
            (
                "chunk count inconsistent with the size",
                Box::new(|m: &mut AttachmentManifest| m.chunk_count = 7),
            ),
            (
                // 1-byte chunks over a huge file: the only consistent chunk
                // count is astronomical, so consistency alone kills it.
                "a chunk count past the policy bound",
                Box::new(|m: &mut AttachmentManifest| {
                    m.chunk_size = 1;
                    m.size_bytes = MAX_ATTACHMENT_BYTES as i64;
                    m.chunk_count = MAX_ATTACHMENT_BYTES as i64;
                }),
            ),
            (
                "short file key",
                Box::new(|m: &mut AttachmentManifest| m.file_key_b64 = b64([3_u8; 16])),
            ),
            (
                "digest that is not a SHA-256",
                Box::new(|m: &mut AttachmentManifest| m.sha256_b64 = b64([4_u8; 20])),
            ),
            (
                "file key that is not base64",
                Box::new(|m: &mut AttachmentManifest| m.file_key_b64 = "not base64!!".to_string()),
            ),
        ];
        for (label, break_it) in cases {
            let mut manifest = valid_manifest();
            break_it(&mut manifest);
            assert!(
                validate_inbound_attachment_manifest(&manifest).is_err(),
                "manifest accepted despite {label}"
            );
        }
    }

    #[test]
    fn quote_metadata_is_bounded() {
        let quote = QuotedMessageMeta {
            message_id: Uuid::new_v4().to_string(),
            excerpt: "hello".to_string(),
            author_public_key: "pk".to_string(),
        };
        validate_inbound_quote(&quote).unwrap();

        let mut long_excerpt = quote.clone();
        long_excerpt.excerpt = "x".repeat(QUOTE_EXCERPT_MAX_CHARS + 1);
        assert!(validate_inbound_quote(&long_excerpt).is_err());

        let mut long_id = quote.clone();
        long_id.message_id = "m".repeat(QUOTE_MAX_ID_CHARS + 1);
        assert!(validate_inbound_quote(&long_id).is_err());

        let mut empty_id = quote;
        empty_id.message_id = String::new();
        assert!(validate_inbound_quote(&empty_id).is_err());
    }

    /// The signature does not cover the nonce, so a nonce of any length rides
    /// a validly signed envelope all the way into the cipher. Opening it must
    /// return an error rather than panic the p2p event task that called us.
    #[test]
    fn envelope_with_wrong_length_nonce_is_rejected() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat-nonce",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "hello bob",
            "direct_message_envelope",
            None,
        )
        .unwrap();

        for length in [0_usize, 1, 11, 13, 64] {
            let mut tampered = envelope.clone();
            tampered.nonce = b64(vec![3_u8; length]);
            assert!(
                verify_envelope_signature(&tampered).is_ok(),
                "a tampered nonce still passes the signature — that is why the \
                 length check has to live in the crypto layer"
            );
            assert!(
                open_envelope_for_recipient(&key_b, &bob.signing_key, &tampered).is_err(),
                "envelope with a {length}-byte nonce was not rejected"
            );
        }
    }

    #[test]
    fn v2_wrong_recipient_cannot_decrypt() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let salt_c = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let key_c = derive_key("carol", &salt_c).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let carol = generate_identity(&key_c).unwrap();
        let envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "secret",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        // Carol has the wrong key — decryption must fail (wrong ECDH shared secret)
        assert!(
            open_envelope_for_recipient(&key_c, &carol.signing_key, &envelope).is_err(),
            "non-recipient must not decrypt v2 envelope"
        );
    }

    #[test]
    fn v2_tampered_ephemeral_key_fails_signature() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let mut envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "tamper test",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        // Replace the ephemeral public key with a different random key
        let fake_secret = EphemeralSecret::random_from_rng(OsRng);
        let fake_public = X25519PublicKey::from(&fake_secret);
        envelope.ephemeral_public_key = Some(b64(fake_public.as_bytes()));
        // Signature verification must catch the substitution
        assert!(
            open_envelope_for_recipient(&key_b, &bob.signing_key, &envelope).is_err(),
            "substituted ephemeral key must invalidate the envelope signature"
        );
    }

    #[test]
    fn v1_envelope_still_decrypts_on_v2_receiver() {
        // Simulate a v1 sender by creating the envelope with static key logic
        // directly, bypassing the current create_envelope path.
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();

        let plaintext = "hello from v1 sender";
        let encrypted = encrypt_direct_text(
            &alice.signing_key,
            &alice.public_key,
            &bob.public_key,
            plaintext,
        )
        .unwrap();
        let (nonce, ciphertext) = encrypted.split_once(':').unwrap();
        let message_id = uuid::Uuid::new_v4().to_string();
        let signed_payload = format!(
            "{}|{}|{}|{}|{}|{}",
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION_V1,
            CRYPTO_SUITE_VERSION_V1,
            message_id,
            "chat-v1",
            ciphertext
        );
        let envelope = MessageEnvelope {
            protocol_version: PROTOCOL_VERSION.to_string(),
            message_envelope_version: MESSAGE_ENVELOPE_VERSION_V1,
            crypto_suite_version: CRYPTO_SUITE_VERSION_V1.to_string(),
            envelope_type: "direct_message_envelope".to_string(),
            message_id,
            chat_id: "chat-v1".to_string(),
            sender_public_key: alice.public_key.clone(),
            recipient_public_key: Some(bob.public_key.clone()),
            ciphertext: ciphertext.to_string(),
            nonce: nonce.to_string(),
            signature: crate::crypto::identity::sign(&alice.signing_key, signed_payload.as_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            ephemeral_public_key: None,
        };
        assert_eq!(
            open_envelope_for_recipient(&key_b, &bob.signing_key, &envelope).unwrap(),
            plaintext,
            "v2 client must still decrypt v1 envelopes from legacy senders"
        );
    }

    // ── existing tests below ─────────────────────────────────────────────────

    #[test]
    fn message_envelope_roundtrip() {
        let salt = generate_salt();
        let password = Uuid::new_v4().to_string();
        let key = derive_key(&password, &salt).unwrap();
        let identity = generate_identity(&key).unwrap();
        let envelope = create_envelope(
            &key,
            &identity.signing_key,
            "chat",
            &identity.public_key,
            None,
            "hello",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        assert_eq!(open_envelope(&key, &envelope).unwrap(), "hello");
    }

    #[test]
    fn direct_message_envelope_opens_with_recipient_identity() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "hello bob",
            "direct_message_envelope",
            None,
        )
        .unwrap();

        assert_eq!(
            open_envelope_for_recipient(&key_b, &bob.signing_key, &envelope).unwrap(),
            "hello bob"
        );
    }

    #[test]
    fn encode_plaintext_without_quote_returns_legacy_string() {
        let encoded = encode_message_plaintext("hi there", None);
        assert_eq!(encoded, "hi there");
        let decoded = decode_message_plaintext(&encoded);
        assert_eq!(decoded.text, "hi there");
        assert!(decoded.quote.is_none());
    }

    #[test]
    fn encode_plaintext_with_quote_roundtrips() {
        let quote = QuotedMessageMeta {
            message_id: "msg-1".to_string(),
            excerpt: "the original body".to_string(),
            author_public_key: "alice-pk".to_string(),
        };
        let encoded = encode_message_plaintext("replying", Some(&quote));
        let decoded = decode_message_plaintext(&encoded);
        assert_eq!(decoded.text, "replying");
        let got = decoded.quote.expect("quote must be present");
        assert_eq!(got.message_id, "msg-1");
        assert_eq!(got.excerpt, "the original body");
        assert_eq!(got.author_public_key, "alice-pk");
    }

    #[test]
    fn encode_plaintext_with_quote_and_attachment_roundtrips() {
        let quote = QuotedMessageMeta {
            message_id: "msg-1".to_string(),
            excerpt: "the original body".to_string(),
            author_public_key: "alice-pk".to_string(),
        };
        let attachment = AttachmentManifest {
            transfer_id: "transfer-1".to_string(),
            file_name: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            media_kind: "image".to_string(),
            size_bytes: 42,
            sha256_b64: "sha".to_string(),
            file_key_b64: "key".to_string(),
            chunk_size: 262144,
            chunk_count: 1,
        };
        let encoded =
            encode_message_plaintext_with_attachment("caption", Some(&quote), Some(&attachment));
        let decoded = decode_message_plaintext(&encoded);

        assert_eq!(decoded.text, "caption");
        assert!(decoded.quote.is_some());
        let got = decoded.attachment.expect("attachment must be present");
        assert_eq!(got.transfer_id, "transfer-1");
        assert_eq!(got.file_name, "photo.jpg");
        assert_eq!(got.mime_type, "image/jpeg");
        assert_eq!(got.media_kind, "image");
        assert_eq!(got.size_bytes, 42);
        assert_eq!(got.chunk_count, 1);
    }

    #[test]
    fn decode_plaintext_treats_unmarked_json_as_plain_text() {
        // A user-typed JSON object without the `_veyra_msg_v` marker must NOT
        // be misparsed as a quote payload — it is just legitimate user content.
        let raw = "{\"hello\":\"world\"}";
        let decoded = decode_message_plaintext(raw);
        assert_eq!(decoded.text, raw);
        assert!(decoded.quote.is_none());
    }

    #[test]
    fn encode_and_decode_edit_mutation_roundtrip() {
        let mutation = MessageMutation::Edit {
            target_message_id: "orig-1".to_string(),
            new_text: "fixed typo".to_string(),
        };
        let encoded = encode_message_mutation(&mutation);
        let decoded = decode_message_plaintext(&encoded);
        assert_eq!(decoded.text, "");
        assert!(decoded.quote.is_none());
        match decoded.mutation {
            Some(MessageMutation::Edit {
                target_message_id,
                new_text,
            }) => {
                assert_eq!(target_message_id, "orig-1");
                assert_eq!(new_text, "fixed typo");
            }
            other => panic!("expected Edit mutation, got {:?}", other),
        }
    }

    #[test]
    fn encode_and_decode_delete_mutation_roundtrip() {
        let mutation = MessageMutation::Delete {
            target_message_id: "orig-2".to_string(),
        };
        let encoded = encode_message_mutation(&mutation);
        let decoded = decode_message_plaintext(&encoded);
        assert_eq!(decoded.text, "");
        assert!(decoded.quote.is_none());
        match decoded.mutation {
            Some(MessageMutation::Delete { target_message_id }) => {
                assert_eq!(target_message_id, "orig-2");
            }
            other => panic!("expected Delete mutation, got {:?}", other),
        }
    }

    #[test]
    fn decode_plaintext_with_quote_does_not_yield_mutation() {
        let quote = QuotedMessageMeta {
            message_id: "m".to_string(),
            excerpt: "e".to_string(),
            author_public_key: "pk".to_string(),
        };
        let encoded = encode_message_plaintext("hi", Some(&quote));
        let decoded = decode_message_plaintext(&encoded);
        assert!(decoded.mutation.is_none());
        assert!(decoded.quote.is_some());
    }

    #[test]
    fn direct_envelope_with_quote_decrypts_and_decodes() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let key_a = derive_key("alice", &salt_a).unwrap();
        let key_b = derive_key("bob", &salt_b).unwrap();
        let alice = generate_identity(&key_a).unwrap();
        let bob = generate_identity(&key_b).unwrap();
        let quote = QuotedMessageMeta {
            message_id: "orig-1".to_string(),
            excerpt: "original body excerpt".to_string(),
            author_public_key: alice.public_key.clone(),
        };
        let envelope = create_envelope(
            &key_a,
            &alice.signing_key,
            "chat",
            &alice.public_key,
            Some(bob.public_key.clone()),
            "replying with quote",
            "direct_message_envelope",
            Some(&quote),
        )
        .unwrap();
        let plaintext = open_envelope_for_recipient(&key_b, &bob.signing_key, &envelope).unwrap();
        let payload = decode_message_plaintext(&plaintext);
        assert_eq!(payload.text, "replying with quote");
        let got = payload.quote.expect("inbound quote");
        assert_eq!(got.message_id, "orig-1");
        assert_eq!(got.excerpt, "original body excerpt");
    }
}
