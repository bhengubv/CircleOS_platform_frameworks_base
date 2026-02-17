/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Handler;
import android.util.ArrayMap;
import android.util.Log;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import za.co.circleos.personality.TriggerRule;

/**
 * Manages auto-switch trigger rules and fires them when device context matches.
 *
 * <p>Supported trigger types:
 * <ul>
 *   <li>TIME — fires via {@link AlarmManager} at the configured hour/minute</li>
 *   <li>BATTERY — fires via {@code ACTION_BATTERY_CHANGED} broadcast</li>
 *   <li>CALENDAR — polls CalendarContract every 5 minutes for matching events</li>
 *   <li>CHARGING — fires via {@code ACTION_POWER_CONNECTED/DISCONNECTED}</li>
 * </ul>
 */
class AutoSwitchManager {

    private static final String TAG = "CirclePersonality";

    private static final String ACTION_TIME_TRIGGER =
            "za.co.circleos.personality.ACTION_TIME_TRIGGER";
    private static final String EXTRA_RULE_ID = "rule_id";

    /** Calendar poll interval: 5 minutes. */
    private static final long CALENDAR_POLL_MS = 5 * 60 * 1000L;

    private Context          mContext;
    private ModeManager      mModeManager;
    private ConflictResolver mResolver;
    private Handler          mHandler;
    private AlarmManager     mAlarmManager;

    private final Map<String, TriggerRule> mRules   = new ArrayMap<>();
    private boolean                         mEnabled = true;

    private final BroadcastReceiver mSystemReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) return;

            switch (action) {
                case Intent.ACTION_BATTERY_CHANGED:
                    handleBatteryChanged(intent);
                    break;
                case Intent.ACTION_POWER_CONNECTED:
                    handleChargingChanged(true);
                    break;
                case Intent.ACTION_POWER_DISCONNECTED:
                    handleChargingChanged(false);
                    break;
                case ACTION_TIME_TRIGGER:
                    handleTimeAlarm(intent.getStringExtra(EXTRA_RULE_ID));
                    break;
            }
        }
    };

    void init(Context context, ModeManager modeManager,
              ConflictResolver resolver, Handler handler) {
        mContext      = context;
        mModeManager  = modeManager;
        mResolver     = resolver;
        mHandler      = handler;
        mAlarmManager = context.getSystemService(AlarmManager.class);

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_BATTERY_CHANGED);
        filter.addAction(Intent.ACTION_POWER_CONNECTED);
        filter.addAction(Intent.ACTION_POWER_DISCONNECTED);
        filter.addAction(ACTION_TIME_TRIGGER);
        mContext.registerReceiver(mSystemReceiver, filter);

        scheduleCalendarPoll();
        Log.i(TAG, "AutoSwitchManager initialised");
    }

    // -------------------------------------------------------------------------
    // Rule management
    // -------------------------------------------------------------------------

    void addRule(TriggerRule rule) {
        synchronized (mRules) {
            mRules.put(rule.id, rule);
        }
        if (rule.type == TriggerRule.TYPE_TIME) {
            scheduleTimeAlarm(rule);
        }
        Log.d(TAG, "Added trigger rule: " + rule.id + " type=" + rule.type);
    }

    void removeRule(String ruleId) {
        TriggerRule removed;
        synchronized (mRules) {
            removed = mRules.remove(ruleId);
        }
        if (removed != null && removed.type == TriggerRule.TYPE_TIME) {
            cancelTimeAlarm(ruleId);
        }
        Log.d(TAG, "Removed trigger rule: " + ruleId);
    }

    List<TriggerRule> getRules() {
        synchronized (mRules) {
            return new ArrayList<>(mRules.values());
        }
    }

    void setEnabled(boolean enabled) {
        mEnabled = enabled;
        Log.i(TAG, "AutoSwitch " + (enabled ? "enabled" : "disabled"));
    }

    boolean isEnabled() {
        return mEnabled;
    }

    // -------------------------------------------------------------------------
    // Time-based triggers
    // -------------------------------------------------------------------------

    private void scheduleTimeAlarm(TriggerRule rule) {
        if (mAlarmManager == null) return;

        Calendar next = nextOccurrence(rule);
        if (next == null) return;

        Intent intent = new Intent(ACTION_TIME_TRIGGER);
        intent.putExtra(EXTRA_RULE_ID, rule.id);
        PendingIntent pi = PendingIntent.getBroadcast(mContext,
                rule.id.hashCode(), intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        mAlarmManager.setExact(AlarmManager.RTC_WAKEUP, next.getTimeInMillis(), pi);
        Log.d(TAG, "Scheduled time alarm for rule " + rule.id
                + " at " + next.getTime());
    }

    private void cancelTimeAlarm(String ruleId) {
        Intent intent = new Intent(ACTION_TIME_TRIGGER);
        PendingIntent pi = PendingIntent.getBroadcast(mContext,
                ruleId.hashCode(), intent,
                PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_IMMUTABLE);
        if (pi != null && mAlarmManager != null) {
            mAlarmManager.cancel(pi);
        }
    }

    private Calendar nextOccurrence(TriggerRule rule) {
        Calendar now  = Calendar.getInstance();
        Calendar next = (Calendar) now.clone();
        next.set(Calendar.HOUR_OF_DAY, rule.startHour);
        next.set(Calendar.MINUTE,      rule.startMinute);
        next.set(Calendar.SECOND,      0);
        next.set(Calendar.MILLISECOND, 0);

        // If the time has already passed today, advance to tomorrow
        if (next.before(now)) {
            next.add(Calendar.DAY_OF_YEAR, 1);
        }

        // Find next day matching daysOfWeek bitmask (0 = any day)
        if (rule.daysOfWeek != 0) {
            for (int i = 0; i < 7; i++) {
                int dow = next.get(Calendar.DAY_OF_WEEK) - 1; // 0=Sun
                if ((rule.daysOfWeek & (1 << dow)) != 0) break;
                next.add(Calendar.DAY_OF_YEAR, 1);
            }
        }

        return next;
    }

    private void handleTimeAlarm(String ruleId) {
        if (ruleId == null || !mEnabled) return;
        TriggerRule rule;
        synchronized (mRules) {
            rule = mRules.get(ruleId);
        }
        if (rule == null || !rule.enabled) return;

        onTriggerFired(rule);

        // Reschedule for next occurrence
        scheduleTimeAlarm(rule);
    }

    // -------------------------------------------------------------------------
    // Battery trigger
    // -------------------------------------------------------------------------

    private void handleBatteryChanged(Intent intent) {
        if (!mEnabled) return;
        int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
        if (level < 0 || scale <= 0) return;
        int pct = (level * 100) / scale;

        List<TriggerRule> fired = new ArrayList<>();
        synchronized (mRules) {
            for (TriggerRule rule : mRules.values()) {
                if (rule.type == TriggerRule.TYPE_BATTERY
                        && rule.enabled
                        && pct <= rule.batteryThreshold) {
                    fired.add(rule);
                }
            }
        }
        for (TriggerRule rule : fired) onTriggerFired(rule);
    }

    // -------------------------------------------------------------------------
    // Charging trigger
    // -------------------------------------------------------------------------

    private void handleChargingChanged(boolean charging) {
        if (!mEnabled) return;
        List<TriggerRule> fired = new ArrayList<>();
        synchronized (mRules) {
            for (TriggerRule rule : mRules.values()) {
                if (rule.type == TriggerRule.TYPE_CHARGING
                        && rule.enabled
                        && rule.requireCharging == charging) {
                    fired.add(rule);
                }
            }
        }
        for (TriggerRule rule : fired) onTriggerFired(rule);
    }

    // -------------------------------------------------------------------------
    // Calendar trigger (polled)
    // -------------------------------------------------------------------------

    private void scheduleCalendarPoll() {
        if (mHandler == null) return;
        mHandler.postDelayed(mCalendarPollRunnable, CALENDAR_POLL_MS);
    }

    private final Runnable mCalendarPollRunnable = new Runnable() {
        @Override
        public void run() {
            checkCalendarTriggers();
            mHandler.postDelayed(this, CALENDAR_POLL_MS);
        }
    };

    private void checkCalendarTriggers() {
        if (!mEnabled) return;
        List<TriggerRule> calRules = new ArrayList<>();
        synchronized (mRules) {
            for (TriggerRule rule : mRules.values()) {
                if (rule.type == TriggerRule.TYPE_CALENDAR && rule.enabled
                        && rule.calendarKeyword != null) {
                    calRules.add(rule);
                }
            }
        }
        if (calRules.isEmpty()) return;

        long now  = System.currentTimeMillis();
        long soon = now + (15 * 60 * 1000L); // look ahead 15 min

        try {
            Uri uri = Uri.parse("content://com.android.calendar/events");
            String[] proj   = {"title", "description", "dtstart"};
            String   sel    = "dtstart >= ? AND dtstart <= ?";
            String[] args   = {String.valueOf(now), String.valueOf(soon)};
            Cursor cursor = mContext.getContentResolver().query(uri, proj, sel, args, null);
            if (cursor == null) return;

            try {
                while (cursor.moveToNext()) {
                    String title = cursor.getString(0);
                    String desc  = cursor.getString(1);
                    for (TriggerRule rule : calRules) {
                        String kw = rule.calendarKeyword.toLowerCase();
                        if ((title != null && title.toLowerCase().contains(kw))
                                || (desc != null && desc.toLowerCase().contains(kw))) {
                            onTriggerFired(rule);
                        }
                    }
                }
            } finally {
                cursor.close();
            }
        } catch (Exception e) {
            Log.w(TAG, "Calendar trigger check failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Common trigger dispatch
    // -------------------------------------------------------------------------

    private void onTriggerFired(TriggerRule rule) {
        Log.i(TAG, "Trigger fired: " + rule.id + " -> " + rule.targetModeId);
        ConflictResolver.Resolution r = mResolver.resolve(
                null,
                Collections.singletonList(rule),
                mModeManager.isEmergencyBypassActive());
        if (r != null) {
            mHandler.post(() -> mModeManager.activateMode(r.targetModeId));
        }
    }
}
