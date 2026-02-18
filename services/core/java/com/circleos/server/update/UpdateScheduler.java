/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.SystemClock;
import android.util.Log;

/**
 * Schedules periodic update checks using {@link AlarmManager}.
 *
 * Checks are triggered every 12 hours via an inexact repeating alarm. The alarm
 * fires the action {@link #ACTION_CHECK}, which is received by the inner
 * {@link UpdateCheckReceiver}.
 *
 * The receiver is registered programmatically by {@link CircleUpdateService} — it
 * does not require a manifest entry.
 *
 * {@link Intent#ACTION_BOOT_COMPLETED} is also received to reschedule the alarm and
 * trigger an immediate check after device restart.
 */
public class UpdateScheduler {

    private static final String TAG = "CircleUpdateScheduler";

    /** Broadcast action that triggers an immediate update check. */
    public static final String ACTION_CHECK = "za.co.circleos.update.action.CHECK";

    private static final int PENDING_INTENT_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;

    /**
     * Sets an inexact repeating alarm that fires {@link #ACTION_CHECK} every 12 hours.
     * Safe to call multiple times; the existing alarm is replaced.
     */
    public static void schedule(Context context) {
        AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (am == null) {
            Log.e(TAG, "AlarmManager not available — cannot schedule update checks");
            return;
        }

        PendingIntent pi = buildPendingIntent(context);
        am.setInexactRepeating(
                AlarmManager.ELAPSED_REALTIME,
                SystemClock.elapsedRealtime() + AlarmManager.INTERVAL_HALF_DAY,
                AlarmManager.INTERVAL_HALF_DAY,
                pi);

        Log.i(TAG, "Scheduled update checks every 12 hours");
    }

    /** Cancels the repeating update-check alarm. */
    public static void cancel(Context context) {
        AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (am == null) return;

        am.cancel(buildPendingIntent(context));
        Log.i(TAG, "Cancelled scheduled update checks");
    }

    /** Returns the IntentFilter that {@link UpdateCheckReceiver} should be registered with. */
    public static IntentFilter buildIntentFilter() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_CHECK);
        filter.addAction(Intent.ACTION_BOOT_COMPLETED);
        return filter;
    }

    private static PendingIntent buildPendingIntent(Context context) {
        Intent intent = new Intent(ACTION_CHECK);
        intent.setPackage(context.getPackageName());
        return PendingIntent.getBroadcast(context, 0, intent, PENDING_INTENT_FLAGS);
    }

    // ── Inner receiver ────────────────────────────────────────────────────────

    /**
     * Receives {@link #ACTION_CHECK} from the alarm and
     * {@link Intent#ACTION_BOOT_COMPLETED} on device startup.
     *
     * Registered programmatically by {@link CircleUpdateService#onBootCompleted()};
     * no manifest entry is required.
     */
    public static class UpdateCheckReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) return;

            Log.d(TAG, "Received: " + action);

            switch (action) {
                case Intent.ACTION_BOOT_COMPLETED:
                    // Re-arm the alarm after boot and fall through to trigger a check
                    schedule(context);
                    // fall through intentional
                case ACTION_CHECK:
                    CircleUpdateService.triggerCheck();
                    break;

                default:
                    Log.w(TAG, "Unexpected action: " + action);
                    break;
            }
        }
    }
}
