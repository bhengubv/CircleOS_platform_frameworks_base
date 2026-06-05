/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.analytics;

import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.os.Binder;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.analytics.ICircleAnalyticsService;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Circle OS Analytics Service.
 *
 * <p>Local-only behavioural analytics for the Privacy Dashboard.
 * Wraps AOSP {@link UsageStatsManager} to answer "how much time has
 * each app spent in the foreground?" and tracks per-package permission
 * event counts via an in-process event log.
 *
 * <p><b>No data ever leaves this service.</b> There is no upload path,
 * no remote endpoint, no cross-device aggregation. The whole point of
 * the dashboard's "Privacy" wording is that the user sees what the
 * other dashboards (Google's, Apple's) would have phoned home -- but
 * we keep it on the device.
 *
 * <p>Permission events are recorded via an internal API that
 * {@link com.circleos.server.privacy.CirclePrivacyManagerService} and
 * {@link com.circleos.server.permission.CirclePermissionService} call
 * when they grant / deny / fake an identifier. The store is in-memory
 * with a 24 h ring buffer per package; the dashboard refreshes
 * frequently enough that persistence isn't worth the disk write
 * volume for alpha.
 */
public final class CircleAnalyticsService extends SystemService {

    private static final String TAG = "CircleAnalytics";

    public static final String SERVICE_NAME = "circle.analytics";

    /** Maximum per-package event count before the oldest event is dropped. */
    private static final int RING_BUFFER_CAP = 256;

    private final AnalyticsBinder mBinder = new AnalyticsBinder();
    private final UsageStatsManager mUsage;
    private final EventRing mEvents = new EventRing();

    public CircleAnalyticsService(Context context) {
        super(context);
        mUsage = context.getSystemService(UsageStatsManager.class);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
    }

    /**
     * Internal entry point for sibling Circle services -- called when a
     * permission grant/deny/fake happens. Not in the binder so it stays
     * in-process and avoids the IPC cost for what can be a hot path.
     */
    public void recordPermissionEvent(String packageName, String eventType) {
        if (TextUtils.isEmpty(packageName)) return;
        mEvents.append(packageName, eventType);
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class AnalyticsBinder extends ICircleAnalyticsService.Stub {

        @Override
        public long getForegroundTimeMs(String packageName, long sinceMs) {
            enforceQuery();
            if (TextUtils.isEmpty(packageName) || mUsage == null) return 0L;
            try {
                final long now = System.currentTimeMillis();
                final List<UsageStats> stats = mUsage.queryUsageStats(
                        UsageStatsManager.INTERVAL_DAILY,
                        sinceMs <= 0 ? now - 24L * 3600_000 : sinceMs,
                        now);
                if (stats == null) return 0L;
                long total = 0;
                for (UsageStats s : stats) {
                    if (packageName.equals(s.getPackageName())) {
                        total += s.getTotalTimeInForeground();
                    }
                }
                return total;
            } catch (Throwable t) {
                Slog.w(TAG, "queryUsageStats failed for " + packageName, t);
                return 0L;
            }
        }

        @Override
        public int getPermissionEventCount(String packageName, long sinceMs) {
            enforceQuery();
            if (TextUtils.isEmpty(packageName)) return 0;
            return mEvents.count(packageName, sinceMs);
        }

        @Override
        public String getTopForegroundPackages(int limit) {
            enforceQuery();
            if (mUsage == null || limit <= 0) return "";
            try {
                final long now = System.currentTimeMillis();
                final Map<String, UsageStats> agg = mUsage.queryAndAggregateUsageStats(
                        now - 24L * 3600_000, now);
                if (agg == null || agg.isEmpty()) return "";
                final java.util.List<Map.Entry<String, UsageStats>> entries =
                        new java.util.ArrayList<>(agg.entrySet());
                Collections.sort(entries, new Comparator<Map.Entry<String, UsageStats>>() {
                    @Override
                    public int compare(Map.Entry<String, UsageStats> a,
                                       Map.Entry<String, UsageStats> b) {
                        return Long.compare(b.getValue().getTotalTimeInForeground(),
                                a.getValue().getTotalTimeInForeground());
                    }
                });
                final StringBuilder sb = new StringBuilder();
                final int n = Math.min(limit, entries.size());
                for (int i = 0; i < n; i++) {
                    final Map.Entry<String, UsageStats> e = entries.get(i);
                    if (i > 0) sb.append(';');
                    sb.append(e.getKey()).append('=').append(e.getValue().getTotalTimeInForeground());
                }
                return sb.toString();
            } catch (Throwable t) {
                Slog.w(TAG, "queryAndAggregateUsageStats failed", t);
                return "";
            }
        }
    }

    // ------------------------------------------------------------------
    //  Event ring buffer (in-memory)
    // ------------------------------------------------------------------

    private static final class EventRing {
        private final Map<String, java.util.Deque<Event>> mByPackage =
                new java.util.concurrent.ConcurrentHashMap<>();

        void append(String pkg, String type) {
            java.util.Deque<Event> q = mByPackage.computeIfAbsent(pkg,
                    k -> new java.util.concurrent.ConcurrentLinkedDeque<>());
            q.addLast(new Event(System.currentTimeMillis(), type));
            while (q.size() > RING_BUFFER_CAP) q.pollFirst();
        }

        int count(String pkg, long sinceMs) {
            final java.util.Deque<Event> q = mByPackage.get(pkg);
            if (q == null) return 0;
            int c = 0;
            for (Event e : q) if (e.ts >= sinceMs) c++;
            return c;
        }
    }

    private static final class Event {
        final long   ts;
        final String type;
        Event(long ts, String type) { this.ts = ts; this.type = type; }
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    private void enforceQuery() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.QUERY_PRIVACY.
    }
}
