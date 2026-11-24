package app.veyra.messenger

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log

// Phase A of next-steps/android-background-foreground-service.md.
//
// Veyra is a single-Activity Tauri app: the whole Rust libp2p swarm lives inside
// the Activity process. When the Activity is backgrounded or the screen locks,
// Android puts that process into Doze / App-Standby and eventually the LMK (or an
// OEM killer) reaps it, so the swarm dies and the phone stops being reachable.
//
// This foreground service keeps the process alive and the CPU awake while it runs:
//   - startForeground() with a persistent low-importance notification stops the
//     system from treating the process as cached/killable;
//   - a PARTIAL_WAKE_LOCK keeps the CPU running so the swarm can hold connections
//     while the screen is off.
//
// Foreground-service type is SPECIAL_USE (not DATA_SYNC) on purpose: from Android 15
// DATA_SYNC services get a per-day time budget and are force-stopped after it, which
// would re-introduce the exact "dies in background" bug for an always-on P2P node.
// SPECIAL_USE has no such cap. Veyra ships as a directly-signed APK, so Play Store
// SPECIAL_USE justification review is not the gate here.
//
// Round-scoped wakelock (§10 follow-up, night-2026-07-17 finding): holding the
// partial wakelock around the clock kept the SoC from ever suspending, which on
// its own quadrupled the overnight drain on the Zenfone while the network between
// deep-idle rounds was already silent. The lock now follows the swarm's round
// machinery: between rounds Rust hands the timer to an exact alarm
// (`roundSleep`), the alarm re-acquires the lock and kicks the next round
// (`VeyraRoundAlarmReceiver` → `VeyraRoundBridge.onRoundAlarm`), and inbound
// work while unlocked re-grabs it (`roundWakeAcquire`). When exact alarms are
// not permitted the hand-off is refused and the lock is simply kept — that is
// exactly the pre-round-scoping behavior.
//
// Battery-optimization exemption (REQUEST_IGNORE_BATTERY_OPTIMIZATIONS) and the
// adaptive background network throttling live in later phases (B/C). Without the
// exemption some aggressive OEM ROMs may still kill this service; that is expected
// and covered by Phase B.
class VeyraConnectivityService : Service() {
  private val tag = "VeyraConnService"

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onCreate() {
    super.onCreate()
    Log.i(tag, "service onCreate")
    createNotificationChannel()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    Log.i(tag, "service onStartCommand action=${intent?.action}")
    startForegroundCompat()
    // Phase C: the wake lock is held only while backgrounded. In the foreground
    // the Activity is already top, so a partial wake lock would just pin the CPU
    // for nothing. ACTION_FOREGROUND releases it; ACTION_BACKGROUND (and a null
    // restart intent) re-acquires it so the swarm survives Doze with the screen
    // off — the Rust round machinery then decides when it may lapse between
    // rounds (roundSleep). Screen-bright wake is Activity-owned and call-scoped.
    when (intent?.action) {
      ACTION_FOREGROUND -> enterForeground(applicationContext)
      else -> enterBackground(applicationContext)
    }
    // START_STICKY: if the system kills us under memory pressure, recreate the
    // service (with a null intent) so connectivity comes back without the user
    // re-opening the app.
    return START_STICKY
  }

  override fun onDestroy() {
    Log.i(tag, "service onDestroy")
    releaseWakeLock()
    cancelRoundAlarm(applicationContext)
    super.onDestroy()
  }

  private fun startForegroundCompat() {
    val openAppIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
      addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
    val pendingFlags =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
      else
        PendingIntent.FLAG_UPDATE_CURRENT
    val contentIntent = openAppIntent?.let {
      PendingIntent.getActivity(this, 0, it, pendingFlags)
    }

    val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      Notification.Builder(this, CHANNEL_ID)
    } else {
      @Suppress("DEPRECATION")
      Notification.Builder(this)
    }
    builder
      .setContentTitle(getString(R.string.bg_service_title))
      .setContentText(getString(R.string.bg_service_text))
      // Monochrome status-bar glyph (veyra_status_tray_icon_pack universal_monochrome):
      // Android masks small icons by alpha, so the colored launcher icon previously
      // rendered as a white blob. setColor tints the glyph + app name with brand emerald.
      .setSmallIcon(R.drawable.ic_stat_veyra)
      .setColor(0xFF08A95F.toInt())
      .setOngoing(true)
      .setShowWhen(false)
    if (contentIntent != null) {
      builder.setContentIntent(contentIntent)
    }
    val notification = builder.build()

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      // API 34+ requires the runtime type to match a declared FOREGROUND_SERVICE_* permission.
      startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (manager.getNotificationChannel(CHANNEL_ID) != null) return
    val channel = NotificationChannel(
      CHANNEL_ID,
      getString(R.string.bg_service_channel_name),
      // LOW: visible persistent notification, but no sound/vibration/heads-up.
      NotificationManager.IMPORTANCE_LOW,
    ).apply {
      description = getString(R.string.bg_service_channel_desc)
      setShowBadge(false)
    }
    manager.createNotificationChannel(channel)
  }

  companion object {
    private const val TAG = "VeyraConnService"
    private const val CHANNEL_ID = "veyra_connectivity"
    private const val NOTIFICATION_ID = 0x5645 // 'VE'
    private const val ACTION_FOREGROUND = "app.veyra.messenger.action.FOREGROUND"
    private const val ACTION_BACKGROUND = "app.veyra.messenger.action.BACKGROUND"
    private const val ROUND_ALARM_REQUEST = 0x5652 // 'VR'

    // The wakelock lives in the companion: the service instance, the round
    // alarm receiver and the Rust bridge (via VeyraRoundBridge) all drive it,
    // and a START_STICKY recreation must find the same state. Guarded by
    // @Synchronized on every mutator so the Kotlin-observed order of
    // sleep/stay-awake transitions matches the Rust side's mutex order.
    @Volatile private var wakeLock: PowerManager.WakeLock? = null
    @Volatile private var activityForeground = false

    fun start(context: Context) = send(context, null)

    /** Activity moved to the foreground: release the service partial wake lock. */
    fun signalForeground(context: Context) = send(context, ACTION_FOREGROUND)

    /** Activity left the foreground: hold the wake lock so the swarm survives Doze. */
    fun signalBackground(context: Context) = send(context, ACTION_BACKGROUND)

    private fun send(context: Context, action: String?) {
      val intent = Intent(context, VeyraConnectivityService::class.java).setAction(action)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(intent)
      } else {
        context.startService(intent)
      }
    }

    fun stop(context: Context) {
      context.stopService(Intent(context, VeyraConnectivityService::class.java))
    }

    @Synchronized
    private fun enterForeground(context: Context) {
      activityForeground = true
      cancelRoundAlarm(context)
      releaseWakeLock()
    }

    @Synchronized
    private fun enterBackground(context: Context) {
      activityForeground = false
      // A fresh background entry always starts locked; the Rust round
      // machinery decides later whether (and until when) it may lapse. Any
      // previously armed alarm is stale against that decision.
      cancelRoundAlarm(context)
      acquireWakeLock(context)
    }

    // Rust (via VeyraRoundBridge.roundSleep): between deep-idle rounds, arm an
    // exact alarm for the next round and release the wakelock. Refused while
    // the Activity is foreground (nothing to release: the lock is already
    // down) and when exact alarms are not permitted — keeping the lock is the
    // safe pre-round-scoping behavior.
    @Synchronized
    fun roundSleep(context: Context, wakeAtMs: Long) {
      if (activityForeground) {
        Log.i(TAG, "roundSleep ignored: activity is foreground")
        return
      }
      val alarmManager =
        context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
      if (alarmManager == null) {
        Log.w(TAG, "roundSleep refused: AlarmManager unavailable; keeping wakelock")
        return
      }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
        !alarmManager.canScheduleExactAlarms()
      ) {
        Log.w(TAG, "roundSleep refused: exact alarms not permitted; keeping wakelock")
        return
      }
      try {
        alarmManager.setExactAndAllowWhileIdle(
          AlarmManager.RTC_WAKEUP,
          wakeAtMs,
          roundAlarmIntent(context),
        )
      } catch (e: Throwable) {
        Log.w(TAG, "roundSleep failed to arm alarm (${e.message}); keeping wakelock")
        return
      }
      Log.i(TAG, "round sleep: wakelock released, alarm at $wakeAtMs")
      releaseWakeLock()
    }

    // Rust (via VeyraRoundBridge.roundArm): safety-net arm at round OPEN —
    // the same exact alarm as roundSleep, but the wakelock stays held. If a
    // vendor freezer suspends the process mid-round (ASUS night #9), the
    // release-tail hand-off never runs; the pre-armed alarm still fires and
    // thaws the app for the next round. roundSleep later re-arms the same
    // PendingIntent, so the healthy path ends with a single alarm.
    @Synchronized
    fun roundArm(context: Context, wakeAtMs: Long) {
      if (activityForeground) {
        Log.i(TAG, "roundArm ignored: activity is foreground")
        return
      }
      val alarmManager =
        context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
      if (alarmManager == null) {
        Log.w(TAG, "roundArm refused: AlarmManager unavailable")
        return
      }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
        !alarmManager.canScheduleExactAlarms()
      ) {
        Log.w(TAG, "roundArm refused: exact alarms not permitted")
        return
      }
      try {
        alarmManager.setExactAndAllowWhileIdle(
          AlarmManager.RTC_WAKEUP,
          wakeAtMs,
          roundAlarmIntent(context),
        )
        Log.i(TAG, "round open: safety alarm armed at $wakeAtMs")
      } catch (e: Throwable) {
        Log.w(TAG, "roundArm failed to arm alarm: ${e.message}")
      }
    }

    // Round alarm / inbound-while-unlocked path: re-acquire the wakelock. The
    // armed alarm (if any) is left in place — a spurious round wake under an
    // already-held lock is harmless, and the Rust side re-arms on its next
    // sleep decision anyway.
    @Synchronized
    fun roundWakeAcquire(context: Context) {
      if (activityForeground) return
      acquireWakeLock(context)
    }

    private fun roundAlarmIntent(context: Context): PendingIntent {
      val intent = Intent(context, VeyraRoundAlarmReceiver::class.java)
      return PendingIntent.getBroadcast(
        context,
        ROUND_ALARM_REQUEST,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
      )
    }

    private fun cancelRoundAlarm(context: Context) {
      val alarmManager =
        context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
      try {
        alarmManager.cancel(roundAlarmIntent(context))
      } catch (e: Throwable) {
        Log.w(TAG, "cancelRoundAlarm failed: ${e.message}")
      }
    }

    private fun acquireWakeLock(context: Context) {
      if (wakeLock?.isHeld == true) return
      val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
      wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "veyra:net").apply {
        setReferenceCounted(false)
        acquire()
      }
      Log.i(TAG, "partial wakelock acquired")
    }

    private fun releaseWakeLock() {
      wakeLock?.let {
        if (it.isHeld) it.release()
      }
      wakeLock = null
    }
  }
}
