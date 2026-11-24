//! Loopback media server (Android video path).
//!
//! Android WebView cannot play large videos over the intercepted
//! `veyra-media` scheme: the media pipeline never advances past the first
//! capped 206 window (next-steps/android-video-streaming.md, diagnosed
//! 2026-07-22 on a 942 MB transfer), and wry materializes every intercepted
//! response body as one `byte[]`, so answering an open-ended range with the
//! whole remainder would OOM. This server gives the player an honest ranged
//! HTTP endpoint on `127.0.0.1:<random port>`: full `Content-Range`
//! semantics with the body streamed in 1 MB decrypted slices as the player
//! reads — plaintext exists only in RAM, one window at a time.
//!
//! Security model: the listener binds loopback only, but on Android loopback
//! is reachable by every app on the device — every request must therefore
//! carry the per-process 128-bit token (`?t=<hex>`), compared via SHA-256
//! digests. Requests are served only while a profile is unlocked (403
//! otherwise), ids are opaque UUIDs looked up in the DB, and nothing is
//! logged beyond the same privacy-safe attachment tag the `veyra-media`
//! protocol uses.
//!
//! Started on Android only (`setup`); desktop/iOS keep the custom protocol,
//! which streams fine there. The module itself is platform-neutral so the
//! host test suite covers the request parsing and span math.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Serialize;
use tauri::Manager as _;

use crate::app_state::AppState;
use crate::storage::db;

const MAX_REQUEST_LINE_BYTES: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_CONCURRENT_CONNECTIONS: usize = 8;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A paused player stops draining the socket; give it this long before the
/// connection is dropped (it re-requests the range it needs on resume, like
/// against any ordinary HTTP server with a send timeout).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

struct MediaServer {
    port: u16,
    token: String,
}

static SERVER: OnceLock<MediaServer> = OnceLock::new();

/// What the frontend needs to build `http://127.0.0.1:<port>/attachment/<id>?t=<token>`.
#[derive(Debug, Clone, Serialize)]
pub struct MediaServerInfoDto {
    pub port: u16,
    pub token: String,
}

pub fn client_info() -> Option<MediaServerInfoDto> {
    SERVER.get().map(|server| MediaServerInfoDto {
        port: server.port,
        token: server.token.clone(),
    })
}

/// Binds the loopback listener and spawns the accept loop. Idempotent;
/// failure to bind only logs — the app then behaves exactly as before this
/// server existed (frontend falls back to the custom protocol).
pub fn start(app_handle: tauri::AppHandle) {
    if SERVER.get().is_some() {
        return;
    }
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(%error, "media server: bind failed; videos fall back to veyra-media");
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(error) => {
            tracing::warn!(%error, "media server: local_addr failed");
            return;
        }
    };
    let mut token_bytes = [0_u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token_bytes);
    let token: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
    if SERVER
        .set(MediaServer {
            port,
            token: token.clone(),
        })
        .is_err()
    {
        return;
    }
    tracing::info!(port, "media server: listening on loopback");
    let spawned = std::thread::Builder::new()
        .name("veyra-media-server".into())
        .spawn(move || accept_loop(listener, app_handle, token));
    if let Err(error) = spawned {
        tracing::warn!(%error, "media server: accept thread failed to spawn");
    }
}

fn accept_loop(listener: TcpListener, app_handle: tauri::AppHandle, token: String) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, "media server: accept failed");
                continue;
            }
        };
        if active.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
            let _ = write_simple_status(&stream, 503, "Service Unavailable");
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let active_in_conn = Arc::clone(&active);
        let app_handle = app_handle.clone();
        let token = token.clone();
        let spawned = std::thread::Builder::new()
            .name("veyra-media-conn".into())
            .spawn(move || {
                handle_connection(stream, &app_handle, &token);
                active_in_conn.fetch_sub(1, Ordering::Relaxed);
            });
        if let Err(error) = spawned {
            active.fetch_sub(1, Ordering::Relaxed);
            tracing::debug!(%error, "media server: connection thread failed to spawn");
        }
    }
}

/// One request per connection (`Connection: close`), the way the player
/// treats any short-lived range server. Chromium reopens per range.
fn handle_connection(stream: TcpStream, app_handle: &tauri::AppHandle, token: &str) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });

    let mut request_line = String::new();
    {
        let mut limited = (&mut reader).take(MAX_REQUEST_LINE_BYTES as u64);
        if limited.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
            return;
        }
    }
    let mut range_header: Option<String> = None;
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        let mut limited = (&mut reader).take(MAX_REQUEST_LINE_BYTES as u64);
        if limited.read_line(&mut line).is_err() {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("range") {
                range_header = Some(value.trim().to_string());
            }
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        let _ = write_simple_status(&stream, 405, "Method Not Allowed");
        return;
    }
    let Some(request) = parse_request_target(target) else {
        let _ = write_simple_status(&stream, 404, "Not Found");
        return;
    };
    if !token_matches(&request.token, token) {
        let _ = write_simple_status(&stream, 403, "Forbidden");
        return;
    }

    let state = app_handle.state::<AppState>();
    let Some(profile) = state.profile() else {
        let _ = write_simple_status(&stream, 403, "Forbidden");
        return;
    };
    let data_dir = state.data_dir();
    let Ok(conn) = db::open_db(&data_dir) else {
        let _ = write_simple_status(&stream, 500, "Internal Server Error");
        return;
    };

    let attachment_tag = crate::media_attachment_tag(&request.attachment_id);
    let range = crate::parse_media_range(range_header.as_deref());

    // One cheap probe read learns total_len + mime before headers go out;
    // the effective span is then computed here (the db-layer 1 MB cap is a
    // per-slice window, not the response contract).
    let probe = db::read_attachment_stream_slice(
        &conn,
        &data_dir,
        &profile.storage_key,
        &request.attachment_id,
        db::AttachmentStreamRange::Bounded {
            start: 0,
            end_inclusive: 0,
        },
    );
    let (total_len, mime_type) = match probe {
        Ok(db::AttachmentStreamRead::Slice(slice)) => (slice.total_len, slice.mime_type),
        Ok(db::AttachmentStreamRead::Unsatisfiable { total_len }) => {
            (total_len, "application/octet-stream".to_string())
        }
        Err(crate::errors::AppError::MessageNotFound) => {
            let _ = write_simple_status(&stream, 404, "Not Found");
            return;
        }
        Err(_) => {
            let _ = write_simple_status(&stream, 500, "Internal Server Error");
            return;
        }
    };

    let Some((start, end, status)) = effective_span(total_len, range) else {
        let mut out = stream;
        let _ = out.write_all(
            format!(
                "HTTP/1.1 416 Range Not Satisfiable\r\nAccept-Ranges: bytes\r\nContent-Range: bytes */{total_len}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        return;
    };

    let mut out = stream;
    let mut header = String::new();
    if status == 206 {
        header.push_str("HTTP/1.1 206 Partial Content\r\n");
    } else {
        header.push_str("HTTP/1.1 200 OK\r\n");
    }
    header.push_str(&format!("Content-Type: {mime_type}\r\n"));
    header.push_str(&format!("Content-Length: {}\r\n", end - start));
    header.push_str("Accept-Ranges: bytes\r\n");
    header.push_str("Cache-Control: no-store\r\n");
    header.push_str("Connection: close\r\n");
    if status == 206 {
        header.push_str(&format!(
            "Content-Range: bytes {}-{}/{}\r\n",
            start,
            end.saturating_sub(1),
            total_len
        ));
    }
    header.push_str("\r\n");
    if out.write_all(header.as_bytes()).is_err() {
        return;
    }

    // Stream the span in db-capped windows; the player consuming slowly (or
    // closing early) simply ends the loop through a write error/timeout.
    let started = std::time::Instant::now();
    let mut position = start;
    let mut sent: u64 = 0;
    let mut outcome = "complete";
    while position < end {
        let slice = match db::read_attachment_stream_slice(
            &conn,
            &data_dir,
            &profile.storage_key,
            &request.attachment_id,
            db::AttachmentStreamRange::Bounded {
                start: position,
                end_inclusive: end - 1,
            },
        ) {
            Ok(db::AttachmentStreamRead::Slice(slice)) => slice,
            _ => {
                outcome = "read_error";
                break;
            }
        };
        if slice.range_start != position || slice.bytes.is_empty() {
            outcome = "short_read";
            break;
        }
        if out.write_all(&slice.bytes).is_err() {
            outcome = "client_gone";
            break;
        }
        position += slice.bytes.len() as u64;
        sent += slice.bytes.len() as u64;
    }
    tracing::debug!(
        attachment = %attachment_tag,
        purpose = request.purpose,
        status,
        span_start = start,
        span_end_exclusive = end,
        total_len,
        sent_bytes = sent,
        elapsed_millis = started.elapsed().as_millis() as u64,
        outcome,
        "media server request"
    );
}

fn write_simple_status(mut stream: &TcpStream, code: u16, reason: &str) -> std::io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
}

struct MediaRequest {
    attachment_id: String,
    token: String,
    purpose: &'static str,
}

/// `/attachment/<uuid>?t=<hex>[&purpose=poster]`. Ids are UUIDs and tokens
/// hex, so no percent-decoding is needed; anything else is a 404.
fn parse_request_target(target: &str) -> Option<MediaRequest> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let attachment_id = path.strip_prefix("/attachment/")?;
    if attachment_id.is_empty() || attachment_id.contains('/') {
        return None;
    }
    let mut token = None;
    let mut purpose = "playback";
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("t=") {
            token = Some(value.to_string());
        } else if pair.eq_ignore_ascii_case("purpose=poster") {
            purpose = "poster";
        }
    }
    Some(MediaRequest {
        attachment_id: attachment_id.to_string(),
        token: token?,
        purpose,
    })
}

/// Timing-safe enough: comparing SHA-256 digests means byte-position timing
/// leaks nothing usable about the token itself.
fn token_matches(candidate: &str, expected: &str) -> bool {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(candidate.as_bytes()) == Sha256::digest(expected.as_bytes())
}

/// The response contract for a parsed Range against a resource of
/// `total_len` bytes: `(start, end_exclusive, http_status)`, or `None` → 416.
/// Unlike the db-layer window cap, a served span always covers the WHOLE
/// requested range — that is exactly what the WebView player needs and what
/// the veyra-media protocol cannot give it.
fn effective_span(total_len: u64, range: db::AttachmentStreamRange) -> Option<(u64, u64, u16)> {
    use db::AttachmentStreamRange as R;
    match range {
        R::Full => Some((0, total_len, 200)),
        R::Invalid => None,
        R::OpenEnded { start } => (start < total_len).then_some((start, total_len, 206)),
        R::Bounded {
            start,
            end_inclusive,
        } => (start < total_len && start <= end_inclusive).then_some((
            start,
            end_inclusive.saturating_add(1).min(total_len),
            206,
        )),
        R::Suffix { length } => (length > 0 && total_len > 0).then_some((
            total_len - length.min(total_len),
            total_len,
            206,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db::AttachmentStreamRange as R;

    #[test]
    fn request_target_parses_id_token_and_purpose() {
        let request = parse_request_target("/attachment/abc-123?t=deadbeef").unwrap();
        assert_eq!(request.attachment_id, "abc-123");
        assert_eq!(request.token, "deadbeef");
        assert_eq!(request.purpose, "playback");

        let poster = parse_request_target("/attachment/abc?t=00ff&purpose=poster").unwrap();
        assert_eq!(poster.purpose, "poster");

        assert!(parse_request_target("/attachment/abc").is_none()); // no token
        assert!(parse_request_target("/attachment/?t=00").is_none()); // empty id
        assert!(parse_request_target("/attachment/a/b?t=00").is_none()); // traversal
        assert!(parse_request_target("/other/abc?t=00").is_none());
    }

    #[test]
    fn effective_span_covers_whole_requested_range() {
        let total = 988_442_821_u64;
        // Open-ended seek must promise the rest of the file, not a window.
        assert_eq!(
            effective_span(total, R::OpenEnded { start: 1_048_576 }),
            Some((1_048_576, total, 206))
        );
        assert_eq!(effective_span(total, R::Full), Some((0, total, 200)));
        assert_eq!(
            effective_span(
                total,
                R::Bounded {
                    start: 10,
                    end_inclusive: 19
                }
            ),
            Some((10, 20, 206))
        );
        // Bounded end past EOF clamps; suffix larger than the file clamps.
        assert_eq!(
            effective_span(
                100,
                R::Bounded {
                    start: 90,
                    end_inclusive: 1000
                }
            ),
            Some((90, 100, 206))
        );
        assert_eq!(
            effective_span(100, R::Suffix { length: 5000 }),
            Some((0, 100, 206))
        );
        assert_eq!(
            effective_span(total, R::Suffix { length: 16 }),
            Some((total - 16, total, 206))
        );
    }

    #[test]
    fn effective_span_rejects_unsatisfiable() {
        assert_eq!(effective_span(100, R::OpenEnded { start: 100 }), None);
        assert_eq!(
            effective_span(
                100,
                R::Bounded {
                    start: 100,
                    end_inclusive: 200
                }
            ),
            None
        );
        assert_eq!(effective_span(100, R::Suffix { length: 0 }), None);
        assert_eq!(effective_span(0, R::Suffix { length: 5 }), None);
        assert_eq!(effective_span(100, R::Invalid), None);
    }

    #[test]
    fn token_comparison_matches_exact_only() {
        assert!(token_matches("aabbcc", "aabbcc"));
        assert!(!token_matches("aabbcc", "aabbcd"));
        assert!(!token_matches("", "aabbcc"));
    }
}
