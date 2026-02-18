/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.sdpkt;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.TimeUnit;

import za.co.circleos.sdpkt.ProtectionEvent;

/**
 * Persistent circular buffer of the last {@value #MAX_EVENTS} protection events.
 *
 * Events are written to {@code /data/circle/sdpkt/protection_log.json} atomically
 * and pruned to keep only entries from the last 30 days.
 */
public final class ProtectionLog {

    private static final String TAG        = "Sdpkt.ProtectionLog";
    private static final int    MAX_EVENTS = 50;
    private static final long   MAX_AGE_MS = TimeUnit.DAYS.toMillis(30);

    private final File             mFile;
    private final Deque<ProtectionEvent> mEvents = new ArrayDeque<>();

    public ProtectionLog(File dataDir) {
        mFile = new File(dataDir, "protection_log.json");
        load();
        prune();
    }

    /** Append a new protection event and persist. */
    public synchronized void append(ProtectionEvent ev) {
        if (mEvents.size() >= MAX_EVENTS) mEvents.pollFirst();
        mEvents.addLast(ev);
        save();
    }

    /** Return all events, newest first, up to {@code limit}. */
    public synchronized List<ProtectionEvent> getRecent(int limit) {
        List<ProtectionEvent> list = new ArrayList<>();
        ProtectionEvent[] arr = mEvents.toArray(new ProtectionEvent[0]);
        for (int i = arr.length - 1; i >= 0 && list.size() < limit; i--) {
            list.add(arr[i]);
        }
        return list;
    }

    /** Total number of stress-block events recorded. */
    public synchronized int countByType(int type) {
        int count = 0;
        for (ProtectionEvent ev : mEvents) if (ev.type == type) count++;
        return count;
    }

    // ── Internal ──────────────────────────────────────────────

    private void prune() {
        long cutoff = System.currentTimeMillis() - MAX_AGE_MS;
        mEvents.removeIf(ev -> ev.timestampMs < cutoff);
    }

    private void load() {
        if (!mFile.exists()) return;
        try (FileReader r = new FileReader(mFile)) {
            char[] buf = new char[(int) mFile.length()];
            int len = r.read(buf);
            if (len <= 0) return;
            JSONArray arr = new JSONArray(new String(buf, 0, len));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                ProtectionEvent ev = new ProtectionEvent();
                ev.type          = o.getInt("type");
                ev.timestampMs   = o.getLong("ts");
                ev.amountCents   = o.optLong("amountCents", 0);
                ev.reason        = o.optString("reason", "");
                ev.locationLabel = o.optString("locationLabel", null);
                mEvents.addLast(ev);
            }
        } catch (IOException | JSONException e) {
            Log.w(TAG, "Failed to load protection log", e);
        }
    }

    private void save() {
        try (FileWriter w = new FileWriter(mFile, false)) {
            JSONArray arr = new JSONArray();
            for (ProtectionEvent ev : mEvents) {
                JSONObject o = new JSONObject();
                o.put("type",          ev.type);
                o.put("ts",            ev.timestampMs);
                o.put("amountCents",   ev.amountCents);
                o.put("reason",        ev.reason != null ? ev.reason : "");
                if (ev.locationLabel != null) o.put("locationLabel", ev.locationLabel);
                arr.put(o);
            }
            w.write(arr.toString());
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Failed to save protection log", e);
        }
    }
}
