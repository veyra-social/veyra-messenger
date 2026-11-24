//! Passive local-clock skew detector. Every HTTPS exchange with a
//! bootstrap node already carries the server's `Date` header; sampling it
//! costs nothing extra and gives an estimate of how far the local clock is
//! from the network without trusting any single node (median across
//! hosts — our own nodes drift too). The signed protocol windows start
//! breaking at ±30–60 s (HTTPS request signatures, presence TTLs), so the
//! user is warned before the symptom becomes "everything is rejected as
//! invalid_signature/stale_request".

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

/// Samples older than this no longer describe the current clock state.
const SAMPLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Hard cap so chatty HTTPS paths cannot grow the tracker unboundedly.
const MAX_SAMPLES: usize = 64;
/// Warn when the median |offset| reaches this many seconds…
const WARN_THRESHOLD_SECONDS: i64 = 40;
/// …and disarm once it is back under this (hysteresis against flapping).
const CLEAR_THRESHOLD_SECONDS: i64 = 20;
/// Independent hosts required before the median is trusted at all.
const MIN_DISTINCT_HOSTS: usize = 2;
/// Do not nag: at most one warning per this interval while the skew lasts.
const WARN_MIN_INTERVAL: Duration = Duration::from_secs(60 * 60);

struct Sample {
    host: String,
    skew_seconds: i64,
    at: Instant,
}

#[derive(Default)]
struct Tracker {
    samples: Vec<Sample>,
    warned_active: bool,
    last_warned_at: Option<Instant>,
}

fn tracker() -> &'static Mutex<Tracker> {
    static TRACKER: OnceLock<Mutex<Tracker>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(Tracker::default()))
}

/// HTTP `Date` is IMF-fixdate, which chrono's RFC 2822 parser accepts
/// (including the literal `GMT` zone).
fn parse_http_date(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(raw.trim())
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Records one `Date`-header observation from a node HTTPS response.
/// `local_before` is the local wall clock right before the request went
/// out and `rtt` the full request duration: the header is compared against
/// the request midpoint so symmetric network delay cancels out. Header
/// granularity keeps each sample at ±1–2 s — plenty against the
/// tens-of-seconds thresholds.
pub fn record_http_date_sample(
    url: &str,
    local_before: DateTime<Utc>,
    rtt: Duration,
    date_header: Option<&str>,
) {
    let Some(server) = date_header.and_then(parse_http_date) else {
        return;
    };
    let Some(host) = host_of(url) else {
        return;
    };
    let midpoint = local_before
        + chrono::Duration::milliseconds(i64::try_from(rtt.as_millis() / 2).unwrap_or(0));
    let skew_seconds = (server - midpoint).num_seconds();
    let now = Instant::now();
    let mut guard = tracker()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .samples
        .retain(|sample| now.duration_since(sample.at) < SAMPLE_TTL);
    guard.samples.push(Sample {
        host,
        skew_seconds,
        at: now,
    });
    let len = guard.samples.len();
    if len > MAX_SAMPLES {
        guard.samples.drain(..len - MAX_SAMPLES);
    }
}

/// Median offset across the freshest sample of every distinct host inside
/// the TTL window, or None while fewer than MIN_DISTINCT_HOSTS reported.
/// One node with a broken clock cannot move the median.
fn median_offset(samples: &[Sample], now: Instant) -> Option<i64> {
    let mut freshest: HashMap<&str, (Instant, i64)> = HashMap::new();
    for sample in samples {
        if now.duration_since(sample.at) >= SAMPLE_TTL {
            continue;
        }
        let entry = freshest
            .entry(sample.host.as_str())
            .or_insert((sample.at, sample.skew_seconds));
        if sample.at >= entry.0 {
            *entry = (sample.at, sample.skew_seconds);
        }
    }
    if freshest.len() < MIN_DISTINCT_HOSTS {
        return None;
    }
    let mut offsets: Vec<i64> = freshest.into_values().map(|(_, skew)| skew).collect();
    offsets.sort_unstable();
    Some(offsets[offsets.len() / 2])
}

/// Pure warning gate so the hysteresis is unit-testable without the
/// global tracker: returns the offset to warn about and mutates the
/// armed/rate-limit state exactly when it does.
fn due_warning(tracker: &mut Tracker, now: Instant) -> Option<i64> {
    let offset = median_offset(&tracker.samples, now)?;
    if offset.abs() < CLEAR_THRESHOLD_SECONDS {
        tracker.warned_active = false;
        return None;
    }
    if offset.abs() < WARN_THRESHOLD_SECONDS {
        return None;
    }
    let rate_ok = tracker
        .last_warned_at
        .is_none_or(|at| now.duration_since(at) >= WARN_MIN_INTERVAL);
    if tracker.warned_active && !rate_ok {
        return None;
    }
    tracker.warned_active = true;
    tracker.last_warned_at = Some(now);
    Some(offset)
}

/// Cheap to poll from a periodic tick: Some(offset_seconds) exactly when a
/// user-facing warning should fire right now (threshold reached, at most
/// once per WARN_MIN_INTERVAL while the skew persists).
pub fn take_due_warning() -> Option<i64> {
    let mut guard = tracker()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    due_warning(&mut guard, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(host: &str, skew: i64, at: Instant) -> Sample {
        Sample {
            host: host.to_string(),
            skew_seconds: skew,
            at,
        }
    }

    #[test]
    fn parses_imf_fixdate_with_gmt_zone() {
        let parsed = parse_http_date("Tue, 14 Jul 2026 07:56:53 GMT").expect("parses");
        assert_eq!(parsed.timestamp(), 1_784_015_813);
    }

    #[test]
    fn host_extraction_handles_ports_and_paths() {
        assert_eq!(
            host_of("https://retired.example/presence"),
            Some("retired.example".to_string())
        );
        assert_eq!(
            host_of("http://beta.example:8080/h"),
            Some("beta.example".to_string())
        );
        assert_eq!(host_of("nonsense"), None);
    }

    #[test]
    fn median_needs_two_distinct_hosts_and_ignores_expired() {
        let now = Instant::now();
        let lone = vec![sample("a", 100, now), sample("a", 90, now)];
        assert_eq!(median_offset(&lone, now), None);

        let expired = now - SAMPLE_TTL;
        let mixed = vec![
            sample("a", 100, now),
            sample("b", 50, now),
            sample("c", 0, expired),
        ];
        // Two live hosts -> upper median of [50, 100].
        assert_eq!(median_offset(&mixed, now), Some(100));
    }

    #[test]
    fn median_uses_freshest_sample_per_host() {
        let now = Instant::now();
        let earlier = now - Duration::from_secs(60);
        let samples = vec![
            sample("a", 500, earlier),
            sample("a", 45, now),
            sample("b", 45, now),
            sample("c", 44, now),
        ];
        assert_eq!(median_offset(&samples, now), Some(45));
    }

    #[test]
    fn warning_fires_once_then_rate_limits_and_clears() {
        let now = Instant::now();
        let mut tracker = Tracker {
            samples: vec![sample("a", 45, now), sample("b", 50, now)],
            ..Tracker::default()
        };
        // Upper median of [45, 50].
        assert_eq!(due_warning(&mut tracker, now), Some(50));
        // Immediately after: armed and rate-limited.
        assert_eq!(due_warning(&mut tracker, now), None);
        // An hour later the skew still holds (fresh samples keep arriving
        // on the HTTPS paths) -> nag again.
        let later = now + WARN_MIN_INTERVAL;
        tracker.samples = vec![sample("a", 45, later), sample("b", 50, later)];
        assert_eq!(due_warning(&mut tracker, later), Some(50));
        // Clock fixed -> disarm below the clear threshold…
        tracker.samples = vec![sample("a", 3, later), sample("b", -2, later)];
        assert_eq!(due_warning(&mut tracker, later), None);
        assert!(!tracker.warned_active);
        // …and a fresh drift warns immediately again after the interval.
        let much_later = later + WARN_MIN_INTERVAL;
        tracker.samples = vec![sample("a", -70, much_later), sample("b", -66, much_later)];
        assert_eq!(due_warning(&mut tracker, much_later), Some(-66));
    }

    #[test]
    fn between_clear_and_warn_thresholds_stays_silent_but_armed() {
        let now = Instant::now();
        let mut tracker = Tracker {
            samples: vec![sample("a", 30, now), sample("b", 25, now)],
            ..Tracker::default()
        };
        assert_eq!(due_warning(&mut tracker, now), None);
        assert!(!tracker.warned_active);
    }
}
