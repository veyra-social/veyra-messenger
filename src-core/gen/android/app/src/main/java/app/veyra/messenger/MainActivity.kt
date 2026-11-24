package app.veyra.messenger

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge
import androidx.core.content.FileProvider
import androidx.core.view.WindowCompat
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONObject

class MainActivity : TauriActivity() {
  private val lifecycleTag = "VeyraLifecycle"
  private var multicastLock: WifiManager.MulticastLock? = null
  private var webView: WebView? = null
  @Volatile private var resumeSequence = 0
  @Volatile private var confirmedResumeSequence = -1
  @Volatile private var callKeepScreenOnRequested = false
  @Volatile private var chatKeepScreenOnRequested = false
  @Volatile private var manualKeepScreenOnRequested = false
  @Volatile private var backupKeepScreenOnRequested = false

  companion object {
    private const val NOTIFICATION_PERMISSION_REQUEST = 0x4E50 // 'NP'
    private const val BACKUP_EXPORT_DOCUMENT_REQUEST = 0x5645 // 'VE'
    private const val BACKUP_IMPORT_DOCUMENT_REQUEST = 0x5649 // 'VI'

    // Entry/boot-splash backgrounds from index.html (`.boot-splash` light and
    // dark). Keep in sync with the frontend splash palette.
    private val ENTRY_BACKGROUND_LIGHT = 0xFFFBFDFB.toInt()
    private val ENTRY_BACKGROUND_DARK = 0xFF07140E.toInt()
  }

  private class PendingSafRequest(val requestCode: Int) {
    val latch = CountDownLatch(1)
    @Volatile var resultUri: String? = null
    @Volatile var error: String? = null
  }

  @Volatile private var pendingSafRequest: PendingSafRequest? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    // Materialize the app-scoped external files dir BEFORE Rust boots:
    // logging.rs targets /storage/emulated/0/Android/data/<pkg>/files/logs so
    // the diagnostic file log is adb-pullable without root, but only the
    // framework may create the package root under /Android/data — a bare
    // mkdir from Rust is denied there, and the log silently fell back to the
    // private data dir (night-2026-07-17 finding). getExternalFilesDir
    // creates the tree persistently; Rust then appends "logs" itself.
    runCatching { getExternalFilesDir(null) }
    super.onCreate(savedInstanceState)
    // Start with light status-bar icons (dark glyphs) because the Veyra
    // default theme is light. The Veyra frontend overrides this immediately
    // after resolving its actual theme via `window.VeyraNative.setStatusBarLight`
    // (see VeyraNativeBridge below + src/lib/uiPrefs.ts:applyTheme) so the
    // system clock/SIM/battery glyphs stay readable in both light and dark
    // Veyra themes regardless of the host device's system UI mode.
    WindowCompat.getInsetsController(window, window.decorView)
      .isAppearanceLightStatusBars = true
    // Privacy shield for the Recents screen — the Android pair of the iOS
    // app-switcher shield (`ios_privacy_shield` in src-core/src/lib.rs): the
    // task card must not show chat content. On API 33+ the system replaces
    // the snapshot with an app-themed placeholder; screenshots and screen
    // recording deliberately keep working (ratified 2026-07-31: no
    // FLAG_SECURE). Older Android keeps the live snapshot — the onPause
    // FLAG_SECURE fallback loses the snapshot race and was rejected with the
    // same ratification.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      setRecentsScreenshotEnabled(false)
      // Light is the Veyra default until the frontend resolves the stored
      // theme and re-calls this via VeyraNative.setStatusBarLight (same
      // handshake as the status-bar appearance above).
      applyRecentsCardColor(light = true)
    }
    Log.i(lifecycleTag, "activity onCreate")
    // Phase A: keep the libp2p swarm process alive in the background / when the
    // screen is locked. Foreground service is started here (always-on by default,
    // per next-steps/android-background-foreground-service.md). A user toggle and
    // battery-optimization exemption arrive in later phases.
    ensureNotificationPermission()
    // Round-scoped wakelock: register the JavaVM with the Rust bridge before
    // the connectivity service takes the first lock, so the swarm can hand
    // the between-rounds timer to AlarmManager (VeyraRoundBridge docs).
    VeyraRoundBridge.init(applicationContext)
    VeyraConnectivityService.start(applicationContext)
  }

  // POST_NOTIFICATIONS is runtime-gated from API 33. The foreground service runs
  // regardless, but without the grant Android suppresses its ongoing notification,
  // so we ask once on launch. (Battery-optimization exemption is a later phase.)
  private fun ensureNotificationPermission() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
      PackageManager.PERMISSION_GRANTED
    ) {
      return
    }
    requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    this.webView = webView
    // Expose a tiny native bridge to the Veyra WebView so the frontend can
    // drive system-bar appearance from its live theme. JS calls
    // `window.VeyraNative.setStatusBarLight(boolean)` whenever the resolved
    // theme changes; the bridge hops to the UI thread and flips the
    // WindowInsetsControllerCompat appearance flag.
    webView.addJavascriptInterface(VeyraNativeBridge(this), "VeyraNative")
    Log.i(lifecycleTag, "webview created")
  }

  override fun onResume() {
    super.onResume()
    Log.i(lifecycleTag, "activity onResume")
    applyKeepScreenOnFlag()
    // Phase C: mDNS multicast and the service wake lock follow the foreground
    // state. mDNS LAN discovery is only useful while the app is on screen, and
    // the service wake lock is redundant while the Activity is top. Screen-bright
    // wake is no longer a generic foreground policy; explicit call/chat requests
    // below own the flag and must release it.
    acquireMulticastLock()
    VeyraConnectivityService.signalForeground(applicationContext)
    requestResumeRepaint()
  }

  override fun onPause() {
    Log.i(lifecycleTag, "activity onPause")
    window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    super.onPause()
  }

  override fun onStop() {
    Log.i(lifecycleTag, "activity onStop")
    notifyWebViewBackground()
    releaseMulticastLock()
    VeyraConnectivityService.signalBackground(applicationContext)
    super.onStop()
  }

  // The backgrounded flag normally rides the WebView's `visibilitychange`,
  // but an overlay that covers the Activity without hiding the WebView
  // document (e.g. a screensaver Dream while docked) stops the Activity while
  // the page still believes it is visible - foreground network cadences then
  // run for hours on an idle device (2026-07-06 idle-traffic acceptance
  // finding). Mirror the native stop into the same frontend handler as a
  // fallback; the handler is idempotent with visibilitychange.
  private fun notifyWebViewBackground() {
    val currentWebView = webView ?: return
    currentWebView.post {
      currentWebView.evaluateJavascript(
        """window.dispatchEvent(new Event("veyra-native-background"));""",
        null,
      )
    }
  }

  override fun onDestroy() {
    Log.i(lifecycleTag, "activity onDestroy")
    webView = null
    callKeepScreenOnRequested = false
    chatKeepScreenOnRequested = false
    manualKeepScreenOnRequested = false
    backupKeepScreenOnRequested = false
    window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    releaseMulticastLock()
    super.onDestroy()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    Log.i(lifecycleTag, "window focus changed: $hasFocus")
  }

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    val request = pendingSafRequest
    if (request != null && request.requestCode == requestCode) {
      if (resultCode == Activity.RESULT_OK) {
        val uri = data?.data
        if (uri == null) {
          request.error = "document picker returned no URI"
        } else {
          val grantMask =
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
          val grantFlags = data.flags and grantMask
          if (grantFlags != 0) {
            try {
              contentResolver.takePersistableUriPermission(uri, grantFlags)
            } catch (e: SecurityException) {
              Log.w(lifecycleTag, "persistable URI grant unavailable: ${e.message}")
            } catch (e: Throwable) {
              Log.w(lifecycleTag, "persistable URI grant failed: ${e.message}")
            }
          }
          request.resultUri = uri.toString()
        }
      }
      request.latch.countDown()
      synchronized(this) {
        if (pendingSafRequest === request) {
          pendingSafRequest = null
        }
      }
      return
    }
    super.onActivityResult(requestCode, resultCode, data)
  }

  private fun requestResumeRepaint() {
    val currentWebView = webView
    if (currentWebView == null) {
      Log.w(lifecycleTag, "resume repaint skipped: webview missing")
      return
    }

    val sequence = ++resumeSequence

    currentWebView.post {
      if (webView !== currentWebView) return@post
      Log.i(lifecycleTag, "resume repaint requested sequence=$sequence")
      // resumeTimers() only resumes global JavaScript timers. Android WebView
      // also has a per-instance paused state; after a long OEM background sleep
      // ASUS kept the renderer alive but never produced another frontend frame.
      currentWebView.onResume()
      currentWebView.resumeTimers()
      currentWebView.requestLayout()
      currentWebView.invalidate()
      currentWebView.postInvalidateOnAnimation()
      dispatchResumeProbe(currentWebView, sequence)

      // A JavaScript evaluation callback alone is insufficient: on the ASUS
      // failure the event executed, but requestAnimationFrame and frontend IPC
      // stayed suspended. Require a two-frame heartbeat from the page, retry
      // the documented WebView wake sequence once, then reload only if the
      // still-focused visible renderer remains stuck.
      currentWebView.postDelayed({
        if (!resumeRecoveryNeeded(currentWebView, sequence)) return@postDelayed
        Log.w(lifecycleTag, "resume frame heartbeat delayed; retrying sequence=$sequence")
        currentWebView.onResume()
        currentWebView.resumeTimers()
        currentWebView.requestLayout()
        currentWebView.invalidate()
        currentWebView.postInvalidateOnAnimation()
        dispatchResumeProbe(currentWebView, sequence)
      }, 750L)
      currentWebView.postDelayed({
        if (!resumeRecoveryNeeded(currentWebView, sequence)) return@postDelayed
        Log.e(lifecycleTag, "resume frame heartbeat missing; reloading webview sequence=$sequence")
        currentWebView.reload()
      }, 2500L)
    }
  }

  private fun dispatchResumeProbe(currentWebView: WebView, sequence: Int) {
    currentWebView.evaluateJavascript(
      """
        (() => {
          window.dispatchEvent(new Event("veyra-native-resume"));
          requestAnimationFrame(() => requestAnimationFrame(() => {
            document.documentElement.dataset.veyraResumeTick = String(Date.now());
            try { window.VeyraNative.confirmResumeFrame($sequence); } catch (_) {}
          }));
        })();
      """.trimIndent(),
      null,
    )
  }

  private fun resumeRecoveryNeeded(currentWebView: WebView, sequence: Int): Boolean {
    return webView === currentWebView &&
      confirmedResumeSequence != sequence &&
      !isFinishing &&
      !isDestroyed &&
      hasWindowFocus() &&
      currentWebView.isShown
  }

  fun confirmResumeFrame(sequence: Int) {
    runOnUiThread {
      if (sequence == resumeSequence && confirmedResumeSequence != sequence) {
        confirmedResumeSequence = sequence
        Log.i(lifecycleTag, "resume frame heartbeat confirmed sequence=$sequence")
      }
    }
  }

  private fun acquireMulticastLock() {
    if (multicastLock?.isHeld == true) return
    val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
    multicastLock = wifi.createMulticastLock("veyra-mdns").apply {
      setReferenceCounted(false)
      acquire()
    }
  }

  private fun releaseMulticastLock() {
    multicastLock?.let {
      if (it.isHeld) {
        it.release()
      }
    }
    multicastLock = null
  }

  fun pickBackupExportUri(defaultName: String): String? {
    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "application/octet-stream"
      putExtra(Intent.EXTRA_TITLE, defaultName)
      addFlags(
        Intent.FLAG_GRANT_READ_URI_PERMISSION or
          Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
          Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
      )
    }
    return awaitSafDocument(intent, BACKUP_EXPORT_DOCUMENT_REQUEST)
  }

  fun pickBackupImportUri(): String? {
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "*/*"
      addFlags(
        Intent.FLAG_GRANT_READ_URI_PERMISSION or
          Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
      )
    }
    return awaitSafDocument(intent, BACKUP_IMPORT_DOCUMENT_REQUEST)
  }

  private fun awaitSafDocument(intent: Intent, requestCode: Int): String? {
    val request = PendingSafRequest(requestCode)
    synchronized(this) {
      if (pendingSafRequest != null) {
        throw java.io.IOException("another Android document picker is already open")
      }
      pendingSafRequest = request
    }
    runOnUiThread {
      try {
        startActivityForResult(intent, requestCode)
      } catch (e: Throwable) {
        request.error = e.message ?: e.toString()
        request.latch.countDown()
      }
    }
    val completed = request.latch.await(5, TimeUnit.MINUTES)
    synchronized(this) {
      if (pendingSafRequest === request) {
        pendingSafRequest = null
      }
    }
    if (!completed) {
      throw java.io.IOException("Android document picker timed out")
    }
    request.error?.let { throw java.io.IOException(it) }
    return request.resultUri
  }

  fun setCallKeepScreenOn(enabled: Boolean) {
    callKeepScreenOnRequested = enabled
    runOnUiThread {
      applyKeepScreenOnFlag()
    }
  }

  fun setChatKeepScreenOn(enabled: Boolean) {
    chatKeepScreenOnRequested = enabled
    runOnUiThread {
      applyKeepScreenOnFlag()
    }
  }

  fun setManualKeepScreenOn(enabled: Boolean) {
    manualKeepScreenOnRequested = enabled
    runOnUiThread {
      applyKeepScreenOnFlag()
    }
  }

  // Separate slot so a long backup export/restore cannot be interrupted by
  // display auto-lock, and releasing it cannot clobber the call/chat/manual
  // keep-screen-on requests.
  fun setBackupKeepScreenOn(enabled: Boolean) {
    backupKeepScreenOnRequested = enabled
    runOnUiThread {
      applyKeepScreenOnFlag()
    }
  }

  private fun applyKeepScreenOnFlag() {
    if (callKeepScreenOnRequested || chatKeepScreenOnRequested || manualKeepScreenOnRequested || backupKeepScreenOnRequested) {
      window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }
  }

  // Color of the Recents placeholder card (API 33+, pairs with
  // setRecentsScreenshotEnabled in onCreate). The system draws that
  // placeholder as a FLAT TaskDescription background color — it cannot embed
  // a logo (TaskSnapshotController#drawAppThemeSnapshot) — and the default
  // theme-derived color showed up as an unreadable near-black spot in the
  // 2026-07-31 field check. Paint it with the entry/boot-splash background of
  // the resolved Veyra theme instead, so the card reads as "the app
  // entrance"; the bar colors are set to the same value to keep the card
  // uniform, and the launcher badges the card with the Veyra icon itself.
  fun applyRecentsCardColor(light: Boolean) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val background = if (light) ENTRY_BACKGROUND_LIGHT else ENTRY_BACKGROUND_DARK
    setTaskDescription(
      ActivityManager.TaskDescription.Builder()
        .setBackgroundColor(background)
        .setStatusBarColor(background)
        .setNavigationBarColor(background)
        .build()
    )
  }
}

private class VeyraNativeBridge(private val activity: MainActivity) {
  private val tag = "VeyraNativeBridge"

  // Voice-call audio session state. WebRTC audio inside the WebView otherwise
  // plays on the media path with no audio-focus handoff, so other apps keep
  // playing over the call and the call routes/volumes through the wrong stream.
  // The media controller brackets a live call with startCallAudio/stopCallAudio.
  private val audioManager: AudioManager by lazy {
    activity.applicationContext.getSystemService(Context.AUDIO_SERVICE) as AudioManager
  }
  private var audioFocusRequest: AudioFocusRequest? = null
  private var savedAudioMode: Int = AudioManager.MODE_NORMAL
  private var callAudioActive = false

  // Enters the communication audio session: voice-call mode + audio focus so
  // other media ducks, routed to earpiece unless `speaker` is set. Safe to call
  // more than once; the first call remembers the prior mode for restoration.
  @JavascriptInterface
  fun startCallAudio(speaker: Boolean): String {
    return try {
      if (!callAudioActive) {
        savedAudioMode = audioManager.mode
      }
      audioManager.mode = AudioManager.MODE_IN_COMMUNICATION
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val attributes = AudioAttributes.Builder()
          .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
          .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
          .build()
        val request = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
          .setAudioAttributes(attributes)
          .build()
        audioFocusRequest = request
        audioManager.requestAudioFocus(request)
      } else {
        @Suppress("DEPRECATION")
        audioManager.requestAudioFocus(
          null,
          AudioManager.STREAM_VOICE_CALL,
          AudioManager.AUDIOFOCUS_GAIN,
        )
      }
      audioManager.isSpeakerphoneOn = speaker
      callAudioActive = true
      activity.setCallKeepScreenOn(true)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "startCallAudio failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Switches the in-call route between earpiece (off) and loudspeaker (on).
  @JavascriptInterface
  fun setSpeakerphone(on: Boolean): String {
    return try {
      audioManager.isSpeakerphoneOn = on
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "setSpeakerphone failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  @JavascriptInterface
  fun confirmResumeFrame(sequence: Int) {
    activity.confirmResumeFrame(sequence)
  }

  @JavascriptInterface
  fun setKeepScreenOn(enabled: Boolean): String {
    return try {
      activity.setManualKeepScreenOn(enabled)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "setKeepScreenOn failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  @JavascriptInterface
  fun setChatKeepScreenOn(enabled: Boolean): String {
    return try {
      activity.setChatKeepScreenOn(enabled)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "setChatKeepScreenOn failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  @JavascriptInterface
  fun setBackupKeepScreenOn(enabled: Boolean): String {
    return try {
      activity.setBackupKeepScreenOn(enabled)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "setBackupKeepScreenOn failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Leaves the communication audio session: abandon focus, drop the speaker
  // route and restore the previous audio mode.
  @JavascriptInterface
  fun stopCallAudio(): String {
    return try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        audioFocusRequest?.let { audioManager.abandonAudioFocusRequest(it) }
      } else {
        @Suppress("DEPRECATION")
        audioManager.abandonAudioFocus(null)
      }
      audioFocusRequest = null
      audioManager.isSpeakerphoneOn = false
      audioManager.mode = if (callAudioActive) savedAudioMode else AudioManager.MODE_NORMAL
      callAudioActive = false
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "stopCallAudio failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    } finally {
      activity.setCallKeepScreenOn(false)
    }
  }

  @JavascriptInterface
  fun setStatusBarLight(light: Boolean) {
    activity.runOnUiThread {
      WindowCompat.getInsetsController(activity.window, activity.window.decorView)
        .isAppearanceLightStatusBars = light
      // The Recents placeholder follows the same resolved theme: this is the
      // one call the frontend already makes on every theme change.
      activity.applyRecentsCardColor(light)
    }
  }

  @JavascriptInterface
  fun pickBackupExportUri(defaultName: String): String {
    return try {
      val uri = activity.pickBackupExportUri(defaultName)
      val envelope = JSONObject().put("ok", true)
      if (uri == null) {
        envelope.put("cancelled", true)
      } else {
        envelope.put("uri", uri)
      }
      envelope.toString()
    } catch (e: Throwable) {
      Log.w(tag, "pickBackupExportUri failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  @JavascriptInterface
  fun pickBackupImportUri(): String {
    return try {
      val uri = activity.pickBackupImportUri()
      val envelope = JSONObject().put("ok", true)
      if (uri == null) {
        envelope.put("cancelled", true)
      } else {
        envelope.put("uri", uri)
      }
      envelope.toString()
    } catch (e: Throwable) {
      Log.w(tag, "pickBackupImportUri failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Reads a content:// (or file://) URI through ContentResolver inside our
  // Activity context, where the SAF transient URI permission grant returned by
  // ACTION_OPEN_DOCUMENT is still alive. Tauri's plugin-fs hits DocumentsProvider
  // from a context without the grant and dies with
  //   "java.lang.SecurityException: ... requires android.permission.MANAGE_DOCUMENTS
  //    or grant UriPermissions()"
  // so the backup-restore flow uses this bridge on Android instead of plugin-fs.
  //
  // Returns a JSON envelope: {"ok":true,"b64":"<base64-bytes>"} on success,
  // {"ok":false,"error":"<message>"} on failure. JavascriptInterface methods can
  // only return primitives/strings, so the envelope is the simplest way to surface
  // a structured error back to TypeScript without crashing the WebView.
  // Best-effort persistent URI permission grab. Required for `DownloadsProvider`
  // URIs on some Android versions: the transient grant returned by SAF picker
  // is enough for `ExternalStorageProvider` (Documents folder) but not for
  // `DownloadsProvider` (Downloads folder), which does additional caller-package
  // checks. `takePersistableUriPermission` only succeeds when the originating
  // intent carried `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` -- when it didn't
  // we silently fall through to rely on the transient grant.
  private fun tryTakePersistableUriPermission(uri: Uri, modeFlags: Int) {
    try {
      activity.contentResolver.takePersistableUriPermission(uri, modeFlags)
    } catch (e: SecurityException) {
      // Intent wasn't persistable; transient grant is what we have.
    } catch (e: Throwable) {
      Log.w(tag, "takePersistableUriPermission unexpected error: ${e.message}")
    }
  }

  private fun openWritableFileDescriptor(uri: Uri): android.os.ParcelFileDescriptor {
    var lastError: Throwable? = null
    for (mode in arrayOf("rwt", "wt", "w")) {
      try {
        val descriptor = activity.contentResolver.openFileDescriptor(uri, mode)
        if (descriptor != null) return descriptor
      } catch (e: Throwable) {
        lastError = e
        Log.w(tag, "openFileDescriptor($mode) failed: ${e.message}")
      }
    }
    throw java.io.IOException(
      "openFileDescriptor returned null for $uri",
      lastError,
    )
  }

  private fun writeContentUriWithStream(uriString: String, write: (OutputStream) -> Unit) {
    val uri = Uri.parse(uriString)
    tryTakePersistableUriPermission(
      uri,
      android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
        android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
    )
    openWritableFileDescriptor(uri).use { descriptor ->
      FileOutputStream(descriptor.fileDescriptor).use { output ->
        write(output)
        output.flush()
        try {
          descriptor.fileDescriptor.sync()
        } catch (e: Throwable) {
          Log.w(tag, "file descriptor sync failed: ${e.message}")
        }
      }
    }
  }

  @JavascriptInterface
  fun readContentUri(uriString: String): String {
    return try {
      val uri = Uri.parse(uriString)
      tryTakePersistableUriPermission(uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
      val bytes = activity.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        ?: throw java.io.IOException("openInputStream returned null for $uriString")
      val b64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
      JSONObject().put("ok", true).put("b64", b64).toString()
    } catch (e: Throwable) {
      Log.w(tag, "readContentUri failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Streams a SAF content:// source into a private app file without
  // materializing it as a giant Java/JS base64 string — readContentUri on a
  // ~200 MB backup exhausted the Java heap ("Failed to allocate"). Mirror of
  // writeContentUriFromFile for the import direction; the destination is a
  // backend-minted temp path inside the app data dir.
  @JavascriptInterface
  fun readContentUriToFile(uriString: String, destPath: String): String {
    return try {
      val uri = Uri.parse(uriString)
      tryTakePersistableUriPermission(uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
      val dest = File(destPath)
      dest.parentFile?.mkdirs()
      activity.contentResolver.openInputStream(uri)?.use { input ->
        FileOutputStream(dest).use { output ->
          input.copyTo(output, 64 * 1024)
          output.flush()
        }
      } ?: throw java.io.IOException("openInputStream returned null for $uriString")
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "readContentUriToFile failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Writes base64-decoded bytes to a content:// (or file://) URI through
  // ContentResolver. Same envelope shape as readContentUri. Used by the
  // backup-export flow on Android so writes go through the Activity context
  // that owns the ACTION_CREATE_DOCUMENT write grant.
  //
  // Some Android DocumentsProviders disagree on the safest write mode:
  // Samsung/Downloads-like providers need a real file descriptor close/sync,
  // while others reject explicit truncate modes. The helper tries compatible
  // modes and flushes the descriptor before returning success.
  @JavascriptInterface
  fun writeContentUri(uriString: String, b64: String): String {
    return try {
      val bytes = Base64.decode(b64, Base64.DEFAULT)
      writeContentUriWithStream(uriString) { output ->
        output.write(bytes)
      }
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "writeContentUri failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Streams a private app temp file into a SAF content:// destination without
  // materializing the encrypted backup as a giant WebView/JS base64 string.
  @JavascriptInterface
  fun writeContentUriFromFile(uriString: String, sourcePath: String): String {
    return try {
      val source = File(sourcePath)
      if (!source.isFile) {
        throw java.io.IOException("source file is not readable: $sourcePath")
      }
      writeContentUriWithStream(uriString) { output ->
        source.inputStream().use { input ->
          input.copyTo(output, 64 * 1024)
        }
      }
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "writeContentUriFromFile failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  @JavascriptInterface
  fun shareBase64File(fileName: String, mimeType: String, b64: String): String {
    return try {
      val safeName = fileName.replace(Regex("""[\\/:*?"<>|]"""), "_").ifBlank { "attachment" }
      val bytes = Base64.decode(b64, Base64.DEFAULT)
      val shareDir = File(activity.cacheDir, "share").apply { mkdirs() }
      val file = File(shareDir, safeName)
      file.writeBytes(bytes)
      val uri = FileProvider.getUriForFile(
        activity,
        activity.packageName + ".fileprovider",
        file,
      )
      val intent = Intent(Intent.ACTION_SEND).apply {
        type = mimeType.ifBlank { "application/octet-stream" }
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }
      activity.startActivity(Intent.createChooser(intent, null))
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "shareBase64File failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Opens the system app-details settings screen for the current package so
  // the user can grant a runtime permission (RECORD_AUDIO in particular) that
  // Android marked USER_FIXED after a previous denial. Tauri's built-in
  // WebChromeClient.onPermissionRequest can only show the runtime dialog the
  // first time; once the user picks "Don't allow" with "Don't ask again"
  // (or the permission state otherwise becomes USER_FIXED) Android silently
  // denies any further `requestPermissions` calls, and the only recovery
  // path is this deep-link to App Info → Permissions. Phase A voice calls
  // route the noLocalMic toast through this helper so the user gets a
  // working "Open settings" recovery step instead of an opaque dead end.
  @JavascriptInterface
  fun openAppSettings(): String {
    return try {
      val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.parse("package:" + activity.packageName)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      activity.startActivity(intent)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "openAppSettings failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Phase B (next-steps/android-background-foreground-service.md): whether the
  // user has excluded Veyra from battery optimization. When false, aggressive
  // OEM power management can still kill the foreground connectivity service.
  // Envelope: {"ok":true,"ignoring":bool}.
  @JavascriptInterface
  fun isIgnoringBatteryOptimizations(): String {
    return try {
      val power = activity.getSystemService(Context.POWER_SERVICE) as PowerManager
      val ignoring = power.isIgnoringBatteryOptimizations(activity.packageName)
      JSONObject().put("ok", true).put("ignoring", ignoring).toString()
    } catch (e: Throwable) {
      Log.w(tag, "isIgnoringBatteryOptimizations failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Shows the system "ignore battery optimizations?" dialog for our package.
  // Requires the REQUEST_IGNORE_BATTERY_OPTIMIZATIONS permission (declared in
  // the manifest). The grant result is not returned here; the caller re-reads
  // isIgnoringBatteryOptimizations() after the user returns to the app.
  @JavascriptInterface
  fun requestBatteryExemption(): String {
    return try {
      val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
        data = Uri.parse("package:" + activity.packageName)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      activity.startActivity(intent)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "requestBatteryExemption failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }

  // Opens the system battery-optimization list. Android exposes no API to
  // *revoke* an exemption, so turning background activity back off routes the
  // user here to set Veyra back to "optimized". Also a recovery path if the
  // grant dialog (requestBatteryExemption) was previously dismissed and no
  // longer reappears.
  @JavascriptInterface
  fun openBatteryOptimizationSettings(): String {
    return try {
      val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      activity.startActivity(intent)
      JSONObject().put("ok", true).toString()
    } catch (e: Throwable) {
      Log.w(tag, "openBatteryOptimizationSettings failed: ${e.message}")
      JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
    }
  }
}
