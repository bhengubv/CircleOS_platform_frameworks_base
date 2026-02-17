/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.app.NotificationManager;
import android.content.Context;
import android.util.Log;

import za.co.circleos.personality.ModeConfig;

/**
 * Applies per-mode notification rules using {@link NotificationManager}.
 */
class NotificationRulesEngine {

    private static final String TAG = "CirclePersonality";

    private final NotificationManager mNm;

    NotificationRulesEngine(Context context) {
        mNm = context.getSystemService(NotificationManager.class);
    }

    /**
     * Applies the notification policy described by {@code config}.
     * Called on the service HandlerThread.
     */
    void applyModeRules(ModeConfig config) {
        if (mNm == null) {
            Log.w(TAG, "NotificationManager unavailable");
            return;
        }

        int filter;
        switch (config.notificationLevel) {
            case ModeConfig.NOTIF_SILENT:
                filter = NotificationManager.INTERRUPTION_FILTER_NONE;
                break;
            case ModeConfig.NOTIF_PRIORITY:
                filter = NotificationManager.INTERRUPTION_FILTER_PRIORITY;
                break;
            case ModeConfig.NOTIF_ALARMS:
                filter = NotificationManager.INTERRUPTION_FILTER_ALARMS;
                break;
            case ModeConfig.NOTIF_ALL:
            default:
                filter = NotificationManager.INTERRUPTION_FILTER_ALL;
                break;
        }

        try {
            mNm.setInterruptionFilter(filter);

            if (filter == NotificationManager.INTERRUPTION_FILTER_PRIORITY) {
                // Allow calls from starred contacts and alarms in priority mode
                NotificationManager.Policy policy = new NotificationManager.Policy(
                        NotificationManager.Policy.PRIORITY_CATEGORY_CALLS
                                | NotificationManager.Policy.PRIORITY_CATEGORY_ALARMS
                                | NotificationManager.Policy.PRIORITY_CATEGORY_SYSTEM,
                        NotificationManager.Policy.PRIORITY_SENDERS_STARRED,
                        NotificationManager.Policy.PRIORITY_SENDERS_STARRED);
                mNm.setNotificationPolicy(policy);
            }

            Log.d(TAG, "Notification filter set to " + filter);
        } catch (SecurityException e) {
            Log.w(TAG, "Cannot set interruption filter: " + e.getMessage());
        }
    }

    /** Restore default (all notifications) without disturbing the DND policy. */
    void reset() {
        applyModeRules(new ModeConfig()); // ModeConfig() defaults to NOTIF_ALL
    }
}
