/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Phase 8: maintenance window enforcement.
 *
 * <p>Polls {@code GET /api/os/maintenance?channel={ch}} to learn the operator-
 * configured install window (start/end hour in UTC, days-of-week bitmask).
 * The window is cached to disk so it can be enforced even when the network is
 * unavailable.
 *
 * <p>{@link #isInstallAllowed()} returns {@code true} only when the current
 * UTC time falls within the active window.  Downloads proceed freely; only
 * the <em>install</em> step (handoff to {@link UpdateInstaller}) is gated.
 *
 * <h3>Days-of-week bitmask</h3>
 * Bit 0 = Monday, bit 1 = Tuesday, …, bit 6 = Sunday (127 = every day).
 */
public class MaintenanceWindowChecker {

    private static final String TAG = "MaintenanceWindowChecker";

    private static final String DEFAULT_BASE_URL = "https://sleptonapi.thegeeknetwork.co.za";
    private static final String CACHE_FILE =
            "/data/system/circleos_update/maintenance_window.json";

    private static final int CONNECT_TIMEOUT_MS = 8_000;
    private static final int READ_TIMEOUT_MS    = 8_000;

    // ── Cached window ─────────────────────────────────────────────────────────

    private volatile int  mStartHour = 2;   // default 02:00 UTC
    private volatile int  mEndHour   = 5;   // default 05:00 UTC
    private volatile int  mDaysMask  = 127; // default every day

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Fetches the maintenance window from the server and caches it.
     * Falls back to cached value if network is unavailable.
     * Must be called on a background thread.
     *
     * @param channel The device's release channel.
     */
    public void refresh(String channel) {
        JSONObject window = fetchWindow(channel);
        if (window != null) {
            applyWindow(window);
            cacheWindow(window);
        } else {
            loadCachedWindow();
        }
        Log.i(TAG, "Maintenance window: " + mStartHour + ":00–" + mEndHour
                + ":00 UTC, daysMask=0b" + Integer.toBinaryString(mDaysMask));
    }

    /**
     * Returns {@code true} if the current UTC time falls within the maintenance
     * window and updates are allowed to be installed.
     */
    public boolean isInstallAllowed() {
        Calendar now = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        int hour    = now.get(Calendar.HOUR_OF_DAY);
        int dowJava = now.get(Calendar.DAY_OF_WEEK); // 1=Sun, 2=Mon, ..., 7=Sat
        // Convert Java DOW to bitmask index (Mon=0 … Sun=6)
        int bit = (dowJava == Calendar.SUNDAY) ? 6 : (dowJava - Calendar.MONDAY);
        boolean dayOk  = ((mDaysMask >> bit) & 1) == 1;
        boolean hourOk = (hour >= mStartHour) && (hour < mEndHour);
        boolean allowed = dayOk && hourOk;
        Log.d(TAG, "isInstallAllowed: hour=" + hour + " bit=" + bit
                + " dayOk=" + dayOk + " hourOk=" + hourOk + " → " + allowed);
        return allowed;
    }

    // ── Network ───────────────────────────────────────────────────────────────

    private JSONObject fetchWindow(String channel) {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/maintenance?channel=" + channel;

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            if (code == 404) {
                Log.d(TAG, "No maintenance window configured — installs always allowed");
                return buildAlwaysOpen();
            }
            if (code != 200) {
                Log.w(TAG, "Maintenance window endpoint returned HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }
            return new JSONObject(sb.toString());

        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch maintenance window: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** Window that makes isInstallAllowed() always return true (no restriction). */
    private static JSONObject buildAlwaysOpen() {
        try {
            return new JSONObject()
                    .put("startHour", 0)
                    .put("endHour", 24)
                    .put("daysMask", 127);
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    // ── Apply + cache ─────────────────────────────────────────────────────────

    private void applyWindow(JSONObject w) {
        mStartHour = w.optInt("startHour", 2);
        mEndHour   = w.optInt("endHour",   5);
        mDaysMask  = w.optInt("daysMask",  127);
    }

    private void cacheWindow(JSONObject w) {
        try {
            new File(CACHE_FILE).getParentFile().mkdirs();
            try (FileWriter fw = new FileWriter(CACHE_FILE)) {
                fw.write(w.toString());
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to cache maintenance window: " + e.getMessage());
        }
    }

    private void loadCachedWindow() {
        File f = new File(CACHE_FILE);
        if (!f.exists()) return;
        try (FileReader fr = new FileReader(f)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[2048];
            int n;
            while ((n = fr.read(buf)) > 0) sb.append(buf, 0, n);
            applyWindow(new JSONObject(sb.toString()));
            Log.d(TAG, "Loaded cached maintenance window");
        } catch (Exception e) {
            Log.w(TAG, "Failed to load cached maintenance window: " + e.getMessage());
        }
    }
}
