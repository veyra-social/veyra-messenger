package app.veyra.messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

// Fires when the between-rounds exact alarm elapses. onReceive runs under the
// system broadcast wakelock, so re-acquiring `veyra:net` inside it is
// gap-free: the CPU cannot suspend between the alarm and our own lock.
class VeyraRoundAlarmReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent?) {
    Log.i("VeyraRoundAlarm", "round alarm fired")
    VeyraRoundBridge.onRoundAlarm(context)
  }
}
