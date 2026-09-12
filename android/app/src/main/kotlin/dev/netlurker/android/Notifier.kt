package dev.netlurker.android

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.netlurker.android.core.AnomalyAlert
import dev.netlurker.android.core.Format

/**
 * Anomaly notifications.
 *
 * Posting a notification needs POST_NOTIFICATIONS from Android 13 on, so [canNotify] is
 * checked first: when the permission is missing the in-app alert still appears and nothing
 * is silently dropped.
 */
class Notifier(private val context: Context) {

    private val manager: NotificationManager? =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager

    fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = context.getString(R.string.notif_channel_description)
            setShowBadge(false)
        }
        runCatching { manager?.createNotificationChannel(channel) }
    }

    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    @android.annotation.SuppressLint("NotificationPermission") // guarded by canNotify()
    fun anomaly(alert: AnomalyAlert) {
        if (manager == null) return
        val title = context.getString(R.string.notif_anomaly_title)
        // Placeholders are {name} rather than %1$s: the catalog is shared with the desktop
        // build's INI files, which use their own escaping, and a plain replace cannot be
        // broken by a translation that reorders the sentence.
        val body = context.getString(R.string.notif_anomaly_body)
            .replace("{subject}", alert.subject)
            .replace("{current}", Format.bytesPerSec(alert.current))
            .replace("{baseline}", Format.bytesPerSec(alert.baseline))
            .replace("{percent}", alert.percent.toString())
        val notification: Notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        val notifications = manager ?: return
        runCatching { notifications.notify(alert.subject.hashCode(), notification) }
    }

    private companion object {
        const val CHANNEL_ID = "netlurker.anomaly"
    }
}
