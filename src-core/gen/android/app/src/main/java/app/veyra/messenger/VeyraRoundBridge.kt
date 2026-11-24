package app.veyra.messenger

import android.content.Context
import android.util.Log

// Round-scoped wakelock bridge, Kotlin side (Rust peer: src/android_round.rs).
//
// Deep idle (§10) silences the network between 10-minute maintenance rounds,
// but the `veyra:net` partial wakelock used to stay held around the clock, so
// the SoC never suspended (the night-2026-07-17 dumps: ~4x overnight drain on
// the Zenfone from the awake platform alone). This object is the seam between
// the Rust swarm and the Android alarm/wakelock machinery:
//
//  - `init` (MainActivity.onCreate) registers the JavaVM with Rust via
//    `nativeInit` — Tauri exposes no VM handle to Rust, so Kotlin introduces
//    itself instead;
//  - Rust calls `roundSleep(wakeAtMs)` after the round tail: the service
//    arms an exact alarm for the next round and releases the wakelock;
//  - the alarm fires `VeyraRoundAlarmReceiver`, which re-acquires the lock
//    and calls `nativeRoundWake` so the swarm opens the round immediately
//    (its own monotonic timer stalls while the CPU is suspended);
//  - Rust calls `roundStayAwake` when inbound work arrives while unlocked
//    (Wi-Fi WoW wake on a live LAN socket) so an active exchange keeps the
//    CPU until the next round-sleep decision.
object VeyraRoundBridge {
  private const val TAG = "VeyraRoundBridge"

  @Volatile private var appContext: Context? = null
  @Volatile private var nativeReady = false

  fun init(context: Context) {
    appContext = context.applicationContext
    ensureNative()
  }

  // The Rust library is normally loaded by Tauri's generated glue well before
  // MainActivity.onCreate finishes; the explicit loadLibrary fallback covers a
  // START_STICKY service (or alarm) restart in a process where the WebView has
  // not been created yet. loadLibrary is idempotent.
  @Synchronized
  private fun ensureNative(): Boolean {
    if (nativeReady) return true
    nativeReady = try {
      nativeInit()
      true
    } catch (first: UnsatisfiedLinkError) {
      try {
        System.loadLibrary("veyra_messenger_lib")
        nativeInit()
        true
      } catch (second: Throwable) {
        Log.w(TAG, "native bridge unavailable: ${second.message}")
        false
      }
    } catch (e: Throwable) {
      Log.w(TAG, "nativeInit failed: ${e.message}")
      false
    }
    return nativeReady
  }

  private external fun nativeInit()

  private external fun nativeRoundWake()

  // Entry point for the round alarm (VeyraRoundAlarmReceiver.onReceive runs
  // under the system's broadcast wakelock): grab our own lock first, then
  // hand the wake to the swarm.
  fun onRoundAlarm(context: Context) {
    appContext = context.applicationContext
    VeyraConnectivityService.roundWakeAcquire(context.applicationContext)
    if (ensureNative()) {
      try {
        nativeRoundWake()
      } catch (e: Throwable) {
        Log.w(TAG, "nativeRoundWake failed: ${e.message}")
      }
    }
  }

  // Called FROM RUST (arbitrary thread) between rounds: release the wakelock
  // and wake again at `wakeAtMs` (epoch millis).
  @JvmStatic
  fun roundSleep(wakeAtMs: Long) {
    val context = appContext
    if (context == null) {
      Log.w(TAG, "roundSleep before init; keeping wakelock")
      return
    }
    VeyraConnectivityService.roundSleep(context, wakeAtMs)
  }

  // Called FROM RUST (arbitrary thread) at round OPEN: arm the next round's
  // exact alarm as a safety net while the wakelock stays held. Vendor
  // freezers (AsusFreezer) can suspend the process mid-round before the
  // release-tail roundSleep runs — a pre-armed alarm still fires and thaws
  // the app for the next round.
  @JvmStatic
  fun roundArm(wakeAtMs: Long) {
    val context = appContext
    if (context == null) {
      Log.w(TAG, "roundArm before init; ignoring")
      return
    }
    VeyraConnectivityService.roundArm(context, wakeAtMs)
  }

  // Called FROM RUST (arbitrary thread): inbound work arrived while the lock
  // may be released — re-acquire it.
  @JvmStatic
  fun roundStayAwake() {
    val context = appContext
    if (context == null) {
      Log.w(TAG, "roundStayAwake before init; ignoring")
      return
    }
    VeyraConnectivityService.roundWakeAcquire(context)
  }
}
