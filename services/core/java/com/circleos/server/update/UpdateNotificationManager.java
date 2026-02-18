/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Manages update-related system notifications for the CircleOS update service.
 *
 * All update notifications share a single notification ID (NOTIFICATION_ID) so that
 * new states replace rather than stack the previous notification.
 *
 * The notification channel is created lazily on first use with HIGH importance.
 */
public class UpdateNotificationManager {

    private static final String TAG = "CircleUpdateNotif";

    /** Action sent when the user taps "Install Now" from a notification. */
    public static final String ACTION_APPLY_UPDATE =
            "za.co.circleos.update.action.APPLY_UPDATE";

    /** Shared notification ID for all update state notifications. */
    public static final int NOTIFICATION_ID = 0x43490001;

    private static final String CHANNEL_ID   = "circleos_update";
    private static final String CHANNEL_NAME = "System Updates";

    private final Context             mContext;
    private final NotificationManager mNotificationManager;
    private       boolean             mChannelCreated = false;

    public UpdateNotificationManager(Context context) {
        mContext             = context;
        mNotificationManager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
    }

    /**
     * Shows a persistent "Update available" notification with an "Install Now" action.
     * Tapping the action broadcasts {@link #ACTION_APPLY_UPDATE}.
     */
    public void showUpdateAvailable(String version) {
        ensureChannel();
        Log.d(TAG, "showUpdateAvailable: " + version);

        Intent applyIntent = new Intent(ACTION_APPLY_UPDATE);
        applyIntent.setPackage(mContext.getPackageName());
        PendingIntent applyPi = PendingIntent.getBroadcast(
                mContext, 0, applyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification notif = new Notification.Builder(mContext, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("CircleOS " + version + " is ready to install")
                .setContentText("Tap to apply the update.")
                .setStyle(new Notification.BigTextStyle()
                        .bigText("CircleOS " + version + " is ready to install. "
                                + "Tap \"Install Now\" to apply. "
                                + "Your device will reboot automatically."))
                .addAction(new Notification.Action.Builder(
                        android.R.drawable.ic_menu_upload,
                        "Install Now",
                        applyPi).build())
                .setContentIntent(applyPi)
                .setOngoing(false)
                .setAutoCancel(false)
                .build();

        mNotificationManager.notify(NOTIFICATION_ID, notif);
    }

    /**
     * Shows or updates a progress notification while the update is being downloaded.
     *
     * @param percent 0–100; values outside this range are clamped. Pass 0 for indeterminate.
     */
    public void showDownloading(int percent) {
        ensureChannel();

        boolean indeterminate = percent <= 0;
        int clamped = Math.max(0, Math.min(100, percent));

        Notification notif = new Notification.Builder(mContext, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Downloading CircleOS update\u2026")
                .setContentText(indeterminate ? "Starting download\u2026" : clamped + "%")
                .setProgress(100, clamped, indeterminate)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .build();

        mNotificationManager.notify(NOTIFICATION_ID, notif);
    }

    /**
     * Replaces the downloading notification with a "ready to install" notification.
     *
     * @param version The version that is ready to be applied.
     */
    public void showReadyToInstall(String version) {
        showUpdateAvailable(version);
    }

    /**
     * Shows a dismissible failure notification.
     *
     * @param reason A short human-readable explanation of why the update failed.
     */
    public void showFailed(String reason) {
        ensureChannel();
        Log.d(TAG, "showFailed: " + reason);

        Notification notif = new Notification.Builder(mContext, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_error)
                .setContentTitle("Update failed")
                .setContentText("Update failed: " + reason)
                .setStyle(new Notification.BigTextStyle()
                        .bigText("Update failed: " + reason
                                + "\n\nYour device is still running the current version. "
                                + "The update will be retried automatically."))
                .setOngoing(false)
                .setAutoCancel(true)
                .build();

        mNotificationManager.notify(NOTIFICATION_ID, notif);
    }

    /** Cancels all active update notifications. */
    public void cancel() {
        Log.d(TAG, "Cancelling update notification");
        mNotificationManager.cancel(NOTIFICATION_ID);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void ensureChannel() {
        if (mChannelCreated) return;

        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Notifications for CircleOS system updates");
        channel.enableVibration(false);
        channel.setShowBadge(false);

        mNotificationManager.createNotificationChannel(channel);
        mChannelCreated = true;
        Log.d(TAG, "Created notification channel: " + CHANNEL_ID);
    }
}
