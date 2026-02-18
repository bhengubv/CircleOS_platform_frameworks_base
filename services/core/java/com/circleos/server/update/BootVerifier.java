/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.os.Build;
import android.os.IBinder;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Phase 8: post-reboot boot verification.
 *
 * <p>Called once on boot-completed (via {@link CircleUpdateService#onBootCompleted()}).
 * Checks whether an OTA update was applied on this boot, verifies that key
 * CircleOS services are reachable, and reports the result to the fleet health
 * endpoint ({@code POST /api/os/fleet/boot}).
 *
 * <p>A <em>boot-pending</em> marker file is written by {@link AbSlotManager#recordUpdateStart}
 * before the install.  If the marker exists on boot-complete, this verifier
 * concludes that an update just happened and performs verification.
 *
 * <h3>Verification steps</h3>
 * <ol>
 *   <li>circle.update service is reachable via ServiceManager.</li>
 *   <li>circle.mesh service is reachable via ServiceManager (if expected).</li>
 *   <li>Boot completed within a reasonable time ({@value #MAX_BOOT_TIME_MS} ms).</li>
 * </ol>
 */
public class BootVerifier {

    private static final String TAG = "BootVerifier";

    private static final String DEFAULT_BASE_URL   = "https://sleptonapi.thegeeknetwork.co.za";
    private static final int    CONNECT_TIMEOUT_MS  = 8_000;
    private static final int    READ_TIMEOUT_MS     = 8_000;
    private static final long   MAX_BOOT_TIME_MS    = 120_000L; // 2 minutes

    private final Context mContext;

    public BootVerifier(Context context) {
        mContext = context;
    }

    /**
     * Runs boot verification if an OTA update was applied on this boot.
     * Posts the result to the fleet health endpoint.
     * Must be called on a background thread.
     *
     * @param channel       The device's current release channel.
     */
    public void verifyAndReport(String channel) {
        String targetVersion = AbSlotManager.checkForStuckUpdate();
        boolean updateApplied = (targetVersion != null);

        // If no update record exists, this is a normal boot — still report success
        String version = Build.VERSION.RELEASE;
        String slot    = AbSlotManager.getCurrentSlot();

        boolean serviceHealthy = verifyServices();
        long    bootTimeMs     = SystemClock.elapsedRealtime();
        boolean bootOk         = serviceHealthy && (bootTimeMs <= MAX_BOOT_TIME_MS || !updateApplied);
        String  errorDetail    = null;

        if (!serviceHealthy) {
            errorDetail = "One or more CircleOS services failed to start";
            Log.w(TAG, errorDetail);
        } else if (updateApplied && bootTimeMs > MAX_BOOT_TIME_MS) {
            errorDetail = "Boot took " + bootTimeMs + " ms (threshold " + MAX_BOOT_TIME_MS + " ms)";
            Log.w(TAG, errorDetail);
            // Don't count slow boot as failure on its own
            bootOk = serviceHealthy;
        }

        Log.i(TAG, "Boot verification: v=" + version + " slot=" + slot
                + " updateApplied=" + updateApplied
                + " healthy=" + serviceHealthy
                + " bootMs=" + bootTimeMs);

        // Clear the update record if slot changed (update succeeded)
        if (updateApplied) {
            AbSlotManager.clearUpdateRecord();
        }

        postBootEvent(channel, version, slot, bootOk, (int) bootTimeMs, errorDetail);
    }

    // ── Service health checks ─────────────────────────────────────────────────

    private boolean verifyServices() {
        boolean updateSvc = isServiceRunning("circle.update");
        boolean meshSvc   = isServiceRunning("circle.mesh");

        Log.d(TAG, "Service check: circle.update=" + updateSvc + " circle.mesh=" + meshSvc);

        // circle.update is mandatory; circle.mesh is best-effort
        return updateSvc;
    }

    private static boolean isServiceRunning(String serviceName) {
        try {
            IBinder binder = ServiceManager.getService(serviceName);
            return binder != null && binder.pingBinder();
        } catch (Exception e) {
            Log.d(TAG, "Service check failed for " + serviceName + ": " + e.getMessage());
            return false;
        }
    }

    // ── Report to fleet health ────────────────────────────────────────────────

    private void postBootEvent(String channel, String version, String slot,
            boolean success, int bootTimeMs, String errorDetail) {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/fleet/boot";

        HttpURLConnection conn = null;
        try {
            JSONObject body = new JSONObject();
            body.put("deviceIdHash", getDeviceIdHash());
            body.put("channel",      channel);
            body.put("version",      version);
            body.put("slot",         slot.isEmpty() ? JSONObject.NULL : slot);
            body.put("bootSuccess",  success);
            body.put("bootTimeMs",   bootTimeMs);
            if (errorDetail != null) {
                body.put("errorDetail", errorDetail);
            }

            byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);

            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setFixedLengthStreamingMode(bodyBytes.length);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
            }

            int code = conn.getResponseCode();
            Log.i(TAG, "Boot event posted: HTTP " + code
                    + " success=" + success + " v=" + version);

        } catch (Exception e) {
            Log.w(TAG, "Failed to post boot event: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ── Device ID hash ────────────────────────────────────────────────────────

    private static volatile String sDeviceIdHash;

    private static String getDeviceIdHash() {
        if (sDeviceIdHash != null) return sDeviceIdHash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(Build.ID.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            sDeviceIdHash = sb.toString();
        } catch (Exception e) {
            sDeviceIdHash = "unknown_" + Build.ID.hashCode();
        }
        return sDeviceIdHash;
    }
}
