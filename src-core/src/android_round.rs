//! Round-scoped wakelock bridge (Android only).
//!
//! Deep idle (§10) already silences the network between 10-minute rounds,
//! but the `veyra:net` partial wakelock stayed held around the clock, so
//! the SoC never suspended — the night-2026-07-17 dumps attribute the
//! Zenfone's ~79 mA overnight drain almost entirely to the awake platform
//! (wakelock 175 mAh + awake-idle 320 mAh + kernel 132 mAh), while the
//! network between rounds was already silent. The fix: hand the round
//! timer to `AlarmManager` and hold the lock only around the round.
//!
//! Flow (peer: `VeyraRoundBridge.kt`):
//!  - Kotlin calls `nativeInit` once at startup; we stash the `JavaVM`
//!    and a global ref to the bridge class (no `ndk-context` — Tauri
//!    does not expose the VM, so Kotlin registers itself instead);
//!  - after the round tail the swarm calls `roundSleep(wakeAtMs)`:
//!    Kotlin arms an exact alarm and releases the wakelock;
//!  - the alarm re-acquires the lock and calls `nativeRoundWake`, which
//!    hands the wake to the swarm loop (a suspended `CLOCK_MONOTONIC`
//!    means the Rust round timer cannot be trusted to fire on its own);
//!  - inbound work that arrives while unlocked (Wi-Fi WoW wake on a live
//!    LAN socket) re-grabs the lock via `notify_stay_awake` so an active
//!    exchange keeps the CPU until the next round-sleep decision.
//!
//! Every entry point is fail-soft: a missing bridge (library loaded but
//! Kotlin not initialized yet, or a non-Tauri test harness) only logs.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::sys::jlong;
use jni::{JNIEnv, JavaVM};

struct Bridge {
    vm: JavaVM,
    /// Global ref to the `VeyraRoundBridge` class object, captured in
    /// `nativeInit`. Static methods are resolved through it on every call
    /// (calls are ~once per 10-minute round, caching method ids is not
    /// worth the unsafe bookkeeping).
    class: GlobalRef,
}

static BRIDGE: OnceLock<Bridge> = OnceLock::new();

/// The swarm's round-wake entry, registered by `run_swarm`. Boxed closure
/// instead of a typed sender so this module stays independent of the
/// `Libp2pCommand` enum.
static ROUND_WAKE_HANDLER: Mutex<Option<Box<dyn Fn() + Send>>> = Mutex::new(None);

/// Mirror of "the wakelock is currently held" as this side believes it.
/// Guards the JNI calls so the Kotlin-observed order of sleep/stay-awake
/// matches the state transitions (an atomic would allow the two calls to
/// race and land inverted). Starts `true`: the service acquires the lock
/// on startup.
static AWAKE: Mutex<bool> = Mutex::new(true);

/// Epoch-ms the armed round alarm is supposed to fire at. Written by
/// `notify_round_sleep`, consumed once on the wake path to measure the
/// vendor's delivery delay (0 = no armed alarm / already consumed).
static PLANNED_WAKE_AT_MS: AtomicI64 = AtomicI64::new(0);

/// Delivery delay of the last round alarm, parked here for the swarm loop
/// to pick up on `AndroidRoundWake` (-1 = nothing new). The vendor-parking
/// detector lives swarm-side, where app_meta and the event emitter are.
static LAST_WAKE_DELAY_MS: AtomicI64 = AtomicI64::new(-1);

/// One-shot read of the last measured alarm delivery delay.
pub fn take_last_wake_delay_ms() -> Option<i64> {
    let value = LAST_WAKE_DELAY_MS.swap(-1, Ordering::Relaxed);
    (value >= 0).then_some(value)
}

/// Registers (or replaces, on swarm restart) the closure that forces the
/// next idle round when the alarm fires.
pub fn set_round_wake_handler(handler: Box<dyn Fn() + Send>) {
    if let Ok(mut slot) = ROUND_WAKE_HANDLER.lock() {
        *slot = Some(handler);
    }
}

/// Kotlin: `VeyraRoundBridge.nativeInit()` — capture the VM and the bridge
/// class. Called once per process; later calls are no-ops.
///
/// `nativeInit` is an *instance* method of the Kotlin `object` singleton, so
/// the second JNI argument is the singleton, NOT the class. The class must be
/// resolved by name: pinning that instance and feeding it to
/// `call_static_method` trips CheckJNI ("jclass has wrong type"), which aborts
/// the whole process — the night-2026-07-18 crash on both phones.
#[no_mangle]
pub extern "system" fn Java_app_veyra_messenger_VeyraRoundBridge_nativeInit(
    mut env: JNIEnv,
    _this: JObject,
) {
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(error) => {
            tracing::warn!(%error, "android round bridge: get_java_vm failed");
            return;
        }
    };
    let class = match env.find_class("app/veyra/messenger/VeyraRoundBridge") {
        Ok(class) => class,
        Err(error) => {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            tracing::warn!(%error, "android round bridge: find_class failed");
            return;
        }
    };
    let class = match env.new_global_ref(&class) {
        Ok(class) => class,
        Err(error) => {
            tracing::warn!(%error, "android round bridge: class global ref failed");
            return;
        }
    };
    let registered = BRIDGE.set(Bridge { vm, class }).is_ok();
    tracing::info!(registered, "android round bridge initialized");
}

/// Kotlin: the round alarm fired (the wakelock is already re-acquired on
/// the Kotlin side before this call). Hand the wake to the swarm.
#[no_mangle]
pub extern "system" fn Java_app_veyra_messenger_VeyraRoundBridge_nativeRoundWake(
    _env: JNIEnv,
    _this: JObject,
) {
    if let Ok(mut awake) = AWAKE.lock() {
        *awake = true;
    }
    // Vendor-parking probe: how late did AlarmManager actually deliver the
    // wake versus the epoch-ms we armed it at? (ASUS parked alarms by
    // 39min-1h25m before the 2026-07-20 settings fix; the detector turns
    // this into the "device restricts background work" notice.)
    let planned = PLANNED_WAKE_AT_MS.swap(0, Ordering::Relaxed);
    if planned > 0 {
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            let delay_ms = now.as_millis() as i64 - planned;
            if delay_ms >= 0 {
                tracing::info!(delay_ms, "android round alarm: delivery delay");
                LAST_WAKE_DELAY_MS.store(delay_ms, Ordering::Relaxed);
            }
        }
    }
    let handler = ROUND_WAKE_HANDLER.lock();
    match handler.as_deref() {
        Ok(Some(handler)) => handler(),
        _ => tracing::warn!("android round wake with no swarm handler registered"),
    }
}

/// Returns `true` when the call reached the Java side (even if it failed
/// there), `false` when there was no bridge to call — so callers only mirror
/// a state transition Kotlin had a chance to observe.
fn call_bridge_static(name: &str, sig: &str, args: &[JValue]) -> bool {
    let Some(bridge) = BRIDGE.get() else {
        tracing::warn!(
            method = name,
            "android round bridge not initialized; skipping"
        );
        return false;
    };
    let mut env = match bridge.vm.attach_current_thread() {
        Ok(env) => env,
        Err(error) => {
            tracing::warn!(%error, method = name, "android round bridge: attach failed");
            return false;
        }
    };
    // SAFETY: the global ref pins a class object; viewing it as JClass for
    // the duration of the call is the documented jni-rs pattern.
    let class = unsafe { JClass::from_raw(bridge.class.as_obj().as_raw()) };
    if let Err(error) = env.call_static_method(&class, name, sig, args) {
        // Surface and clear any pending Java exception so it cannot poison
        // the next JNI call on this thread.
        let _ = env.exception_describe();
        let _ = env.exception_clear();
        tracing::warn!(%error, method = name, "android round bridge: static call failed");
    }
    true
}

/// Between-rounds hand-off: release the wakelock and arm an exact alarm at
/// `wake_at_epoch_ms` (wall clock). Kotlin ignores the request while the
/// Activity is foreground and falls back to keeping the lock when exact
/// alarms are not permitted.
pub fn notify_round_sleep(wake_at_epoch_ms: i64) {
    let Ok(mut awake) = AWAKE.lock() else { return };
    if call_bridge_static(
        "roundSleep",
        "(J)V",
        &[JValue::Long(wake_at_epoch_ms as jlong)],
    ) {
        *awake = false;
        PLANNED_WAKE_AT_MS.store(wake_at_epoch_ms, Ordering::Relaxed);
    }
}

/// Safety-net arm at round OPEN: schedule the next round's exact alarm
/// while the wakelock stays held. Vendor freezers (AsusFreezer, night #9
/// 2026-07-22) can suspend the process mid-round, before the release-tail
/// hand-off in `notify_round_sleep` ever runs — with no armed alarm the
/// next round then waits on an outside thaw (holes up to 79 min). The tail
/// hand-off re-arms the same PendingIntent with the same target, so on the
/// healthy path this is replaced, not duplicated.
pub fn arm_round_safety_alarm(delay: std::time::Duration) {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return;
    };
    let wake_at_epoch_ms = now.as_millis() as i64 + delay.as_millis() as i64;
    if call_bridge_static(
        "roundArm",
        "(J)V",
        &[JValue::Long(wake_at_epoch_ms as jlong)],
    ) {
        PLANNED_WAKE_AT_MS.store(wake_at_epoch_ms, Ordering::Relaxed);
    }
}

/// Inbound work arrived while the lock may be released (WoW wake): re-grab
/// it so the exchange keeps the CPU. Dedups while already awake, so the
/// per-chunk call sites cost one mutex lock, not a JNI round-trip.
pub fn notify_stay_awake() {
    let Ok(mut awake) = AWAKE.lock() else { return };
    if *awake {
        return;
    }
    if call_bridge_static("roundStayAwake", "()V", &[]) {
        *awake = true;
    }
}
