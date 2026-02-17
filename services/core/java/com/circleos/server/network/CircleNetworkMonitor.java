/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Slog;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Real-time network connection monitor for Circle OS.
 *
 * Receives events from CircleDomainFilterService (via LocalBroadcastManager)
 * whenever a DNS query is ALLOWED or BLOCKED, and surfaces them as:
 *   1. A persistent notification showing total counts
 *   2. A ring buffer (last 200 events) queryable by CircleSettings
 *
 * Events are broadcast with action:
 *   com.circleos.action.NETWORK_EVENT
 * Extras:
 *   EXTRA_PACKAGE   — source app package name
 *   EXTRA_DOMAIN    — queried domain
 *   EXTRA_ACTION    — "ALLOWED" | "BLOCKED"
 *   EXTRA_TIMESTAMP — System.currentTimeMillis()
 */
public class CircleNetworkMonitor {

    private static final String TAG      = "CircleNetworkMonitor";
    private static final String CHANNEL  = "circle_network_monitor";
    private static final int    NOTIF_ID = 0xC1C1E010;
    private static final int    MAX_EVENTS = 200;

    public static final String ACTION_NETWORK_EVENT = "com.circleos.action.NETWORK_EVENT";
    public static final String EXTRA_PACKAGE   = "pkg";
    public static final String EXTRA_DOMAIN    = "domain";
    public static final String EXTRA_ACTION    = "action";
    public static final String EXTRA_TIMESTAMP = "ts";

    /** A single captured network event. */
    public static class NetworkEvent {
        public final long   timestamp;
        public final String packageName;
        public final String domain;
        public final boolean allowed;

        public NetworkEvent(long ts, String pkg, String domain, boolean allowed) {
            this.timestamp   = ts;
            this.packageName = pkg;
            this.domain      = domain;
            this.allowed     = allowed;
        }
    }

    private final Context               mContext;
    private final HandlerThread         mThread;
    private final Handler               mHandler;
    private final NotificationManager   mNotifMgr;
    private final Deque<NetworkEvent>   mEvents = new ArrayDeque<>(MAX_EVENTS);
    private final AtomicInteger         mTotalMonitored = new AtomicInteger(0);
    private final AtomicInteger         mTotalBlocked   = new AtomicInteger(0);

    public CircleNetworkMonitor(Context context) {
        mContext  = context;
        mNotifMgr = context.getSystemService(NotificationManager.class);

        mThread = new HandlerThread("CircleNetworkMonitor");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());

        createNotificationChannel();
    }

    // ---- Public API ----

    /**
     * Called by CircleDomainFilterService for each DNS event.
     * Thread-safe; dispatches to background handler.
     */
    public void onNetworkEvent(String packageName, String domain, boolean allowed) {
        mHandler.post(() -> {
            NetworkEvent event = new NetworkEvent(
                    System.currentTimeMillis(), packageName, domain, allowed);

            synchronized (mEvents) {
                if (mEvents.size() >= MAX_EVENTS) mEvents.pollFirst();
                mEvents.addLast(event);
            }

            mTotalMonitored.incrementAndGet();
            if (!allowed) mTotalBlocked.incrementAndGet();

            updateNotification();
            broadcastEvent(event);
        });
    }

    /** Returns a snapshot of recent events (newest first, up to limit). */
    public NetworkEvent[] getRecentEvents(int limit) {
        synchronized (mEvents) {
            NetworkEvent[] arr = mEvents.toArray(new NetworkEvent[0]);
            int start = Math.max(0, arr.length - limit);
            NetworkEvent[] result = new NetworkEvent[arr.length - start];
            System.arraycopy(arr, start, result, 0, result.length);
            // Reverse so newest is first
            for (int i = 0, j = result.length - 1; i < j; i++, j--) {
                NetworkEvent tmp = result[i]; result[i] = result[j]; result[j] = tmp;
            }
            return result;
        }
    }

    // ---- Private ----

    private void updateNotification() {
        int monitored = mTotalMonitored.get();
        int blocked   = mTotalBlocked.get();

        Notification notif = new Notification.Builder(mContext, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Circle OS Network Monitor")
                .setContentText(monitored + " connections monitored · " + blocked + " blocked")
                .setOngoing(true)
                .setShowWhen(false)
                .build();

        mNotifMgr.notify(NOTIF_ID, notif);
    }

    private void broadcastEvent(NetworkEvent event) {
        Intent intent = new Intent(ACTION_NETWORK_EVENT);
        intent.putExtra(EXTRA_PACKAGE,   event.packageName);
        intent.putExtra(EXTRA_DOMAIN,    event.domain);
        intent.putExtra(EXTRA_ACTION,    event.allowed ? "ALLOWED" : "BLOCKED");
        intent.putExtra(EXTRA_TIMESTAMP, event.timestamp);
        mContext.sendBroadcast(intent);
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL,
                "Network Monitor",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Real-time network connection monitoring");
        channel.setShowBadge(false);
        mNotifMgr.createNotificationChannel(channel);
    }
}
