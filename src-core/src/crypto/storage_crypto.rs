use crate::errors::{AppError, AppResult};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

pub const STORAGE_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length. `Nonce::from_slice` panics on anything
/// else, and both `decrypt_string` and `decrypt_bytes` are fed nonces that
/// arrived over the wire — an inbound envelope or file chunk with a 3-byte
/// nonce used to take down the p2p event task instead of failing the message
/// (code review 2026-07-27, P1).
const NONCE_LEN: usize = 12;

/// Fallible nonce conversion for wire-supplied bytes.
fn nonce_from_wire(bytes: &[u8]) -> AppResult<[u8; NONCE_LEN]> {
    let nonce: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    Ok(nonce)
}

/// The 256-bit key everything at rest is encrypted under.
///
/// It deliberately has no derived `Debug`: the key used to print itself in
/// full anywhere a containing struct was formatted with `{:?}` — a log line,
/// a panic message, a `tracing` field (code review 2026-07-27, P3). Dropping
/// one wipes its bytes, so a copy left behind by a clone does not sit in
/// freed memory for the rest of the process's life.
#[derive(Clone)]
pub struct StorageKey(pub [u8; STORAGE_KEY_LEN]);

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageKey(<redacted>)")
    }
}

impl Drop for StorageKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
}

/// Creates a new Argon2id salt for local storage or backup KDF.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit encryption key from a password and salt.
pub fn derive_key(password: &str, salt: &[u8]) -> AppResult<StorageKey> {
    let mut out = [0_u8; STORAGE_KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| AppError::WrongPassword)?;
    let key = StorageKey(out);
    // `[u8; 32]` is `Copy`: constructing the key copied it, so the buffer
    // that Argon2 filled is still sitting on this stack frame.
    out.zeroize();
    Ok(key)
}

/// Encrypts UTF-8 plaintext as base64(nonce):base64(ciphertext).
pub fn encrypt_string(key: &StorageKey, plaintext: &str) -> AppResult<String> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageEncryptionFailed)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    Ok(format!(
        "{}:{}",
        STANDARD.encode(nonce),
        STANDARD.encode(ciphertext)
    ))
}

/// Decrypts a value produced by encrypt_string.
pub fn decrypt_string(key: &StorageKey, value: &str) -> AppResult<String> {
    let (nonce_b64, ciphertext_b64) = value
        .split_once(':')
        .ok_or(AppError::MessageDecryptionFailed)?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let nonce = nonce_from_wire(&nonce_bytes)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageDecryptionFailed)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| AppError::MessageDecryptionFailed)
}

/// Encrypts bytes as separate nonce and ciphertext base64 strings.
pub fn encrypt_bytes(key: &StorageKey, plaintext: &[u8]) -> AppResult<(String, String)> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageEncryptionFailed)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    Ok((STANDARD.encode(nonce), STANDARD.encode(ciphertext)))
}

/// Single-field wrapper for `encrypt_bytes` / `decrypt_bytes` (nonce:ciphertext, both base64).
pub fn encrypt_bytes_to_token(key: &StorageKey, plaintext: &[u8]) -> AppResult<String> {
    let (nonce_b64, ciphertext_b64) = encrypt_bytes(key, plaintext)?;
    Ok(format!("{nonce_b64}:{ciphertext_b64}"))
}

/// Decrypts a value produced by `encrypt_bytes_to_token`.
pub fn decrypt_bytes_from_token(key: &StorageKey, token: &str) -> AppResult<Vec<u8>> {
    let (nonce_b64, ciphertext_b64) = token
        .split_once(':')
        .ok_or(AppError::MessageDecryptionFailed)?;
    decrypt_bytes(key, nonce_b64, ciphertext_b64)
}

/// Decrypts bytes from base64 nonce and ciphertext.
pub fn decrypt_bytes(
    key: &StorageKey,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> AppResult<Vec<u8>> {
    let nonce = STANDARD
        .decode(nonce_b64)
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let nonce = nonce_from_wire(&nonce)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageDecryptionFailed)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| AppError::MessageDecryptionFailed)
}

// ---------------------------------------------------------------------------
// Attachment at-rest format v2: chunked STREAM AEAD (chat-media arc,
// 2026-07-09). v1 stored one `nonce_b64:ciphertext_b64` token — any access
// decrypted the whole file in memory and no random access existed, which is
// why video previews shipped the entire file through base64/IPC. v2 is a
// binary file of independently sealed chunks:
//
//   [0..4)  magic  "VMA2"
//   [4]     version = 2
//   [5..9)  chunk_size (u32 LE, plaintext bytes per chunk)
//   [9..16) nonce base (7 random bytes)
//   then N chunks, each = ChaCha20-Poly1305 seal (chunk plaintext + 16 tag)
//
// Chunk i's nonce = base(7) || i as u32 BE || last_flag u8 — the counter
// binds order (swapped chunks fail) and the final-chunk flag binds length
// (a truncated file re-labels some middle chunk as last, whose nonce then
// never validates). A byte range maps to a chunk span, so decryption is
// O(range), not O(file) — the veyra-media streaming protocol serves HTTP
// Ranges straight out of the encrypted store; no plaintext ever lands on
// disk.
// ---------------------------------------------------------------------------

pub const ATTACHMENT_V2_MAGIC: [u8; 4] = *b"VMA2";
pub const ATTACHMENT_V2_VERSION: u8 = 2;
pub const ATTACHMENT_V2_HEADER_LEN: u64 = 16;
pub const ATTACHMENT_V2_CHUNK_SIZE: u32 = 256 * 1024;
const ATTACHMENT_V2_TAG_LEN: u64 = 16;

fn attachment_v2_nonce(base: &[u8; 7], index: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..7].copy_from_slice(base);
    nonce[7..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// Seals plaintext into the v2 chunked container.
pub fn encrypt_attachment_v2(key: &StorageKey, plaintext: &[u8]) -> AppResult<Vec<u8>> {
    encrypt_attachment_v2_with_chunk_size(key, plaintext, ATTACHMENT_V2_CHUNK_SIZE)
}

fn encrypt_attachment_v2_with_chunk_size(
    key: &StorageKey,
    plaintext: &[u8],
    chunk_size: u32,
) -> AppResult<Vec<u8>> {
    if chunk_size == 0 {
        return Err(AppError::MessageEncryptionFailed);
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageEncryptionFailed)?;
    let mut base = [0_u8; 7];
    rand::thread_rng().fill_bytes(&mut base);
    let chunk_len = chunk_size as usize;
    let chunk_count = plaintext.len().div_ceil(chunk_len).max(1);
    let mut out = Vec::with_capacity(
        ATTACHMENT_V2_HEADER_LEN as usize
            + plaintext.len()
            + chunk_count * ATTACHMENT_V2_TAG_LEN as usize,
    );
    out.extend_from_slice(&ATTACHMENT_V2_MAGIC);
    out.push(ATTACHMENT_V2_VERSION);
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&base);
    for index in 0..chunk_count {
        let start = index * chunk_len;
        let end = (start + chunk_len).min(plaintext.len());
        let last = index == chunk_count - 1;
        let index = u32::try_from(index).map_err(|_| AppError::MessageEncryptionFailed)?;
        let nonce = attachment_v2_nonce(&base, index, last);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), &plaintext[start..end])
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

/// True when the blob (or any prefix of it that covers the first five
/// bytes) starts with the v2 container magic; v1 token files start with
/// base64 text and can never collide.
pub fn is_attachment_v2(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[..4] == ATTACHMENT_V2_MAGIC && bytes[4] == ATTACHMENT_V2_VERSION
}

/// Streaming sealer for the v2 chunked container (slice D). Accepts
/// plaintext in arbitrary slices and writes sealed chunks through `out`,
/// holding at most one container chunk in memory — the large-file paths
/// (upload finalize, inbound assembly) feed it instead of building the
/// whole plaintext `Vec`.
///
/// The container's last chunk carries a distinct nonce flag (length
/// binding), and "last" is only known at the end — so a full chunk is
/// sealed lazily, once at least one more plaintext byte arrives after it.
/// `finish()` seals whatever remains (possibly an empty chunk: an empty
/// plaintext still produces one sealed chunk, matching
/// `encrypt_attachment_v2`).
pub struct AttachmentV2StreamWriter<W: std::io::Write> {
    cipher: ChaCha20Poly1305,
    nonce_base: [u8; 7],
    chunk_size: usize,
    buffer: Vec<u8>,
    next_index: u32,
    out: W,
}

impl<W: std::io::Write> AttachmentV2StreamWriter<W> {
    pub fn new(key: &StorageKey, mut out: W) -> AppResult<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        let mut nonce_base = [0_u8; 7];
        rand::thread_rng().fill_bytes(&mut nonce_base);
        let mut header = Vec::with_capacity(ATTACHMENT_V2_HEADER_LEN as usize);
        header.extend_from_slice(&ATTACHMENT_V2_MAGIC);
        header.push(ATTACHMENT_V2_VERSION);
        header.extend_from_slice(&ATTACHMENT_V2_CHUNK_SIZE.to_le_bytes());
        header.extend_from_slice(&nonce_base);
        out.write_all(&header)
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        Ok(Self {
            cipher,
            nonce_base,
            chunk_size: ATTACHMENT_V2_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(ATTACHMENT_V2_CHUNK_SIZE as usize),
            next_index: 0,
            out,
        })
    }

    fn seal_chunk(&mut self, plain: &[u8], last: bool) -> AppResult<()> {
        let nonce = attachment_v2_nonce(&self.nonce_base, self.next_index, last);
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        self.out
            .write_all(&sealed)
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(AppError::MessageEncryptionFailed)?;
        Ok(())
    }

    pub fn write(&mut self, mut data: &[u8]) -> AppResult<()> {
        while !data.is_empty() {
            // Seal a buffered full chunk only when more plaintext follows:
            // that chunk is then provably not the last one.
            if self.buffer.len() == self.chunk_size {
                let chunk =
                    std::mem::replace(&mut self.buffer, Vec::with_capacity(self.chunk_size));
                self.seal_chunk(&chunk, false)?;
            }
            let take = (self.chunk_size - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(())
    }

    /// Seals the tail chunk with the last-flag nonce and flushes `out`.
    pub fn finish(mut self) -> AppResult<()> {
        let tail = std::mem::take(&mut self.buffer);
        self.seal_chunk(&tail, true)?;
        self.out
            .flush()
            .map_err(|_| AppError::MessageEncryptionFailed)?;
        Ok(())
    }
}

struct AttachmentV2Layout {
    chunk_size: u64,
    nonce_base: [u8; 7],
    chunk_count: u64,
    plain_len: u64,
}

fn attachment_v2_layout(header: &[u8], file_len: u64) -> AppResult<AttachmentV2Layout> {
    if header.len() < ATTACHMENT_V2_HEADER_LEN as usize || !is_attachment_v2(header) {
        return Err(AppError::MessageDecryptionFailed);
    }
    let chunk_size = u64::from(u32::from_le_bytes(
        header[5..9]
            .try_into()
            .map_err(|_| AppError::MessageDecryptionFailed)?,
    ));
    if chunk_size == 0 || file_len < ATTACHMENT_V2_HEADER_LEN + ATTACHMENT_V2_TAG_LEN {
        return Err(AppError::MessageDecryptionFailed);
    }
    let mut nonce_base = [0_u8; 7];
    nonce_base.copy_from_slice(&header[9..16]);
    let body = file_len - ATTACHMENT_V2_HEADER_LEN;
    let full_chunk = chunk_size + ATTACHMENT_V2_TAG_LEN;
    let chunk_count = body.div_ceil(full_chunk).max(1);
    let plain_len = body
        .checked_sub(chunk_count * ATTACHMENT_V2_TAG_LEN)
        .ok_or(AppError::MessageDecryptionFailed)?;
    Ok(AttachmentV2Layout {
        chunk_size,
        nonce_base,
        chunk_count,
        plain_len,
    })
}

/// Plaintext length of a v2 container given its header and on-disk size.
pub fn attachment_v2_plain_len(header: &[u8], file_len: u64) -> AppResult<u64> {
    attachment_v2_layout(header, file_len).map(|layout| layout.plain_len)
}

/// Decrypts a plaintext byte range `[start, start+len)` from a v2 container,
/// touching only the chunks the range overlaps. The range is clamped to the
/// plaintext length; out-of-range starts yield an empty vector.
pub fn decrypt_attachment_v2_range<R: std::io::Read + std::io::Seek>(
    key: &StorageKey,
    file: &mut R,
    file_len: u64,
    start: u64,
    len: u64,
) -> AppResult<Vec<u8>> {
    use std::io::SeekFrom;
    let mut header = [0_u8; ATTACHMENT_V2_HEADER_LEN as usize];
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    file.read_exact(&mut header)
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let layout = attachment_v2_layout(&header, file_len)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AppError::MessageDecryptionFailed)?;
    let start = start.min(layout.plain_len);
    let end = start.saturating_add(len).min(layout.plain_len);
    if start >= end {
        return Ok(Vec::new());
    }
    let first_chunk = start / layout.chunk_size;
    let last_chunk = (end - 1) / layout.chunk_size;
    let full_chunk = layout.chunk_size + ATTACHMENT_V2_TAG_LEN;
    let mut out = Vec::with_capacity((end - start) as usize);
    for index in first_chunk..=last_chunk {
        let offset = ATTACHMENT_V2_HEADER_LEN + index * full_chunk;
        let sealed_len = full_chunk.min(file_len - offset) as usize;
        let mut sealed = vec![0_u8; sealed_len];
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| AppError::MessageDecryptionFailed)?;
        file.read_exact(&mut sealed)
            .map_err(|_| AppError::MessageDecryptionFailed)?;
        let last = index == layout.chunk_count - 1;
        let nonce = attachment_v2_nonce(
            &layout.nonce_base,
            u32::try_from(index).map_err(|_| AppError::MessageDecryptionFailed)?,
            last,
        );
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce), sealed.as_ref())
            .map_err(|_| AppError::MessageDecryptionFailed)?;
        let chunk_plain_start = index * layout.chunk_size;
        let take_from = start.saturating_sub(chunk_plain_start) as usize;
        let take_to = ((end - chunk_plain_start) as usize).min(plain.len());
        out.extend_from_slice(&plain[take_from..take_to]);
    }
    Ok(out)
}

/// Decrypts a whole v2 container held in memory.
pub fn decrypt_attachment_v2_full(key: &StorageKey, bytes: &[u8]) -> AppResult<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(bytes);
    let file_len = bytes.len() as u64;
    let plain_len = attachment_v2_plain_len(
        bytes
            .get(..ATTACHMENT_V2_HEADER_LEN as usize)
            .ok_or(AppError::MessageDecryptionFailed)?,
        file_len,
    )?;
    decrypt_attachment_v2_range(key, &mut cursor, file_len, 0, plain_len)
}

/// Encodes bytes as base64.
pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}

/// Decodes base64 bytes.
pub fn from_b64(value: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| AppError::Internal("invalid base64".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_encryption_roundtrip() {
        let salt = generate_salt();
        let password = uuid::Uuid::new_v4().to_string();
        let key = derive_key(&password, &salt).unwrap();
        let encrypted = encrypt_string(&key, "hello").unwrap();
        let decrypted = decrypt_string(&key, &encrypted).unwrap();
        assert_eq!(decrypted, "hello");
    }

    fn test_key() -> StorageKey {
        derive_key("password", &generate_salt()).unwrap()
    }

    /// The key must not print itself. Anything holding one — the unlocked
    /// profile, a request context — is routinely formatted with `{:?}` into a
    /// log line or a panic message.
    #[test]
    fn the_storage_key_never_prints_its_bytes() {
        let key = StorageKey([0xAB; STORAGE_KEY_LEN]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "StorageKey(<redacted>)");
        assert!(!rendered.contains("171") && !rendered.to_lowercase().contains("ab"));

        // And a struct that merely contains one inherits the redaction.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            key: StorageKey,
            name: &'static str,
        }
        let holder = format!("{:?}", Holder { key, name: "alice" });
        assert!(holder.contains("<redacted>"), "{holder}");
        assert!(holder.contains("alice"), "{holder}");
    }

    /// A wire-supplied nonce of the wrong length must fail the message, not
    /// the process: `Nonce::from_slice` panics on anything but 12 bytes, and
    /// this is where inbound envelopes and file chunks arrive.
    #[test]
    fn wrong_length_nonce_is_an_error_not_a_panic() {
        let key = test_key();
        let sealed = encrypt_string(&key, "hello").unwrap();
        let ciphertext_b64 = sealed.split_once(':').unwrap().1.to_string();
        for length in [0_usize, 1, 11, 13, 24, 4096] {
            let nonce_b64 = STANDARD.encode(vec![7_u8; length]);
            assert!(
                decrypt_string(&key, &format!("{nonce_b64}:{ciphertext_b64}")).is_err(),
                "decrypt_string accepted a {length}-byte nonce"
            );
            assert!(
                decrypt_bytes(&key, &nonce_b64, &ciphertext_b64).is_err(),
                "decrypt_bytes accepted a {length}-byte nonce"
            );
        }
        // The right length still round-trips (the guard is on length only).
        assert_eq!(decrypt_string(&key, &sealed).unwrap(), "hello");
    }

    // Pins the v2 chunked-container contract (chat-media arc 2026-07-09):
    // roundtrip across chunk boundaries, ranged reads touch only the
    // requested span, tampering and truncation are rejected, and the
    // plaintext length is recoverable from the on-disk size alone.
    #[test]
    fn attachment_v2_roundtrip_ranges_and_integrity() {
        let key = test_key();
        let chunk = 32_u32;
        let plaintext: Vec<u8> = (0..=254_u8).cycle().take(100).collect();
        let sealed = encrypt_attachment_v2_with_chunk_size(&key, &plaintext, chunk).unwrap();
        assert!(is_attachment_v2(&sealed));
        // 100 bytes / 32-byte chunks = 4 chunks (32+32+32+4), each +16 tag.
        assert_eq!(sealed.len() as u64, ATTACHMENT_V2_HEADER_LEN + 100 + 4 * 16);
        assert_eq!(
            attachment_v2_plain_len(&sealed[..16], sealed.len() as u64).unwrap(),
            100
        );
        assert_eq!(
            decrypt_attachment_v2_full(&key, &sealed).unwrap(),
            plaintext
        );

        // Ranges: inside one chunk, across a boundary, the tail, past-the-end.
        let mut cursor = std::io::Cursor::new(sealed.clone());
        let file_len = sealed.len() as u64;
        let range = |c: &mut std::io::Cursor<Vec<u8>>, start: u64, len: u64| {
            decrypt_attachment_v2_range(&key, c, file_len, start, len).unwrap()
        };
        assert_eq!(range(&mut cursor, 5, 10), plaintext[5..15]);
        assert_eq!(range(&mut cursor, 30, 10), plaintext[30..40]);
        assert_eq!(range(&mut cursor, 90, 100), plaintext[90..100]);
        assert!(range(&mut cursor, 200, 10).is_empty());

        // Tamper: flip one ciphertext byte.
        let mut tampered = sealed.clone();
        let byte = tampered.len() - 5;
        tampered[byte] ^= 0x01;
        assert!(decrypt_attachment_v2_full(&key, &tampered).is_err());

        // Truncation: drop the final chunk — the new "last" chunk was sealed
        // with last_flag = 0, so its nonce no longer validates.
        let truncated = sealed[..(ATTACHMENT_V2_HEADER_LEN + 3 * (32 + 16)) as usize].to_vec();
        assert!(decrypt_attachment_v2_full(&key, &truncated).is_err());

        // Empty payload still seals and opens.
        let empty = encrypt_attachment_v2_with_chunk_size(&key, &[], chunk).unwrap();
        assert_eq!(
            attachment_v2_plain_len(&empty[..16], empty.len() as u64).unwrap(),
            0
        );
        assert!(decrypt_attachment_v2_full(&key, &empty).unwrap().is_empty());

        // Exact multiple of the chunk size: no phantom trailing chunk.
        let exact: Vec<u8> = vec![7_u8; 64];
        let sealed = encrypt_attachment_v2_with_chunk_size(&key, &exact, chunk).unwrap();
        assert_eq!(
            attachment_v2_plain_len(&sealed[..16], sealed.len() as u64).unwrap(),
            64
        );
        assert_eq!(decrypt_attachment_v2_full(&key, &sealed).unwrap(), exact);
    }

    #[test]
    fn v2_stream_writer_matches_whole_buffer_sealer() {
        let key = StorageKey([9_u8; 32]);
        let chunk = ATTACHMENT_V2_CHUNK_SIZE as usize;
        // Sizes straddling the container chunk boundaries, incl. empty and
        // an exact multiple; fed in awkward slice sizes to exercise the
        // internal buffering.
        for size in [
            0_usize,
            1,
            chunk - 1,
            chunk,
            chunk + 1,
            2 * chunk,
            2 * chunk + 511,
        ] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut sealed: Vec<u8> = Vec::new();
            let mut writer = AttachmentV2StreamWriter::new(&key, &mut sealed).unwrap();
            for slice in plain.chunks(97_531) {
                writer.write(slice).unwrap();
            }
            writer.finish().unwrap();
            assert!(is_attachment_v2(&sealed), "size {size}");
            assert_eq!(
                attachment_v2_plain_len(&sealed[..16], sealed.len() as u64).unwrap(),
                size as u64,
                "size {size}"
            );
            assert_eq!(
                decrypt_attachment_v2_full(&key, &sealed).unwrap(),
                plain,
                "size {size}"
            );
        }
    }
}
