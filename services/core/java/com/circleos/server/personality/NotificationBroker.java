/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.util.Log;

import za.co.circleos.personality.ModeConfig;
import za.co.circleos.personality.PersonalityMode;

/**
 * Tracks notification-silent periods and posts a catch-up summary when a
 * restrictive mode is exited.
 *
 * <p>Because the notification broker runs inside a system service (not a
 * {@code NotificationListenerService}), it tracks time rather than individual
 * notifications. The catch-up summary tells the user how long they were in a
 * restricted mode, prompting them to check missed notifications manually.</p>
 */
class NotificationBroker {

    private static final String TAG        = "CirclePersonality";
    private static final String CHANNEL_ID = "circle_personality_broker";
    private static final int    NOTIF_ID   = 0x43504200; // "CPB\0"

    private final Context             mContext;
    private final NotificationManager mNm;

    private long   mRestrictedSince    = -1;
    private String mRestrictedModeName = null;

    NotificationBroker(Context context) {
        mContext = context;
        mNm      = context.getSystemService(NotificationManager.class);
        ensureChannel();
    }

    /**
     * Called when a new mode is activated. If the mode silences notifications,
     * we start tracking the restricted period.
     */
    void onModeActivated(PersonalityMode mode) {
        if (mode == null || mode.config == null) return;

        if (mode.config.notificationLevel < ModeConfig.NOTIF_ALL) {
            mRestrictedSince    = System.currentTimeMillis();
            mRestrictedModeName = mode.name;
            Log.d(TAG, "NotificationBroker: started tracking restricted period for "
                    + mode.name);
        }
    }

    /**
     * Called when a mode is being deactivated. If we were in a restricted period,
     * post the catch-up summary notification.
     */
    void onModeDeactivated(PersonalityMode mode) {
        if (mRestrictedSince < 0) return;

        long durationMs = System.currentTimeMillis() - mRestrictedSince;
        postCatchUp(mRestrictedModeName, durationMs);

        mRestrictedSince    = -1;
        mRestrictedModeName = null;
    }

    /** Dismiss any pending broker notification. */
    void dismissBrokerNotifications() {
        if (mNm != null) {
            mNm.cancel(NOTIF_ID);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void postCatchUp(String modeName, long durationMs) {
        if (mNm == null) return;

        long minutes = durationMs / 60_000;
        String title = "Back from " + (modeName != null ? modeName : "restricted mode");
        String body  = "You were in " + (modeName != null ? modeName : "restricted mode")
                + " for " + formatDuration(minutes)
                + ". Tap to check missed notifications.";

        Notification notif = new Notification.Builder(mContext, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(title)
                .setContentText(body)
                .setAutoCancel(true)
                .setOnlyAlertOnce(true)
                .build();

        try {
            mNm.notify(NOTIF_ID, notif);
            Log.d(TAG, "NotificationBroker: posted catch-up after "
                    + minutes + " min in " + modeName);
        } catch (Exception e) {
            Log.w(TAG, "Could not post catch-up notification: " + e.getMessage());
        }
    }

    private void ensureChannel() {
        if (mNm == null) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID,
                "Mode notifications",
                NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Catch-up summaries after leaving a quiet mode");
        try {
            mNm.createNotificationChannel(ch);
        } catch (Exception e) {
            Log.w(TAG, "Could not create notification channel: " + e.getMessage());
        }
    }

    private static String formatDuration(long minutes) {
        if (minutes < 1)  return "less than a minute";
        if (minutes < 60) return minutes + " minute" + (minutes == 1 ? "" : "s");
        long hours = minutes / 60;
        long rem   = minutes % 60;
        String h   = hours + " hour" + (hours == 1 ? "" : "s");
        if (rem == 0) return h;
        return h + " " + rem + " min";
    }
}
