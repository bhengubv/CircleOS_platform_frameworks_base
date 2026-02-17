/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.RecoverySystem;
import android.util.Slog;

import com.android.server.SystemService;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

/**
 * Circle OS OTA (Over-The-Air) update service.
 *
 * Registered in SystemServer as "circle.update".
 *
 * Flow:
 *   1. Polls UPDATE_URL on check (manual or scheduled)
 *   2. Compares server version against ro.circle.version
 *   3. If newer: downloads OTA zip to /data/circle/ota/update.zip
 *   4. Verifies SHA-256 against manifest
 *   5. Passes to RecoverySystem.installPackage() → reboot into recovery
 *
 * A/B updates: uses RecoverySystem.scheduleUpdateFromFile() when
 * ro.virtual_ab.enabled=true (Pixel 6+).
 *
 * Update server manifest format (JSON):
 *   {
 *     "version": "0.2.0-alpha",
 *     "url": "https://updates.circleos.org/ota/circle-0.2.0-alpha.zip",
 *     "sha256": "abc123...",
 *     "size_bytes": 134217728,
 *     "changelog": "Bug fixes and security improvements"
 *   }
 */
public class CircleUpdateService extends SystemService {

    private static final String TAG        = "CircleUpdateService";
    public  static final String SERVICE_NAME = "circle.update";

    private static final String UPDATE_URL =
            "https://updates.circleos.org/api/v1/latest?channel=alpha&arch=" +
            Build.CPU_ABI;
    private static final String OTA_DIR   = "/data/circle/ota";
    private static final String OTA_FILE  = OTA_DIR + "/update.zip";

    private final HandlerThread mThread;
    private final Handler       mHandler;

    public static class Lifecycle extends SystemService {
        private CircleUpdateService mService;
        public Lifecycle(Context context) { super(context); }

        @Override
        public void onStart() {
            mService = new CircleUpdateService(getContext());
            mService.onStart();
        }
    }

    public CircleUpdateService(Context context) {
        super(context);
        mThread = new HandlerThread("CircleUpdateService");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, new UpdateBinder());
        Slog.i(TAG, "CircleUpdateService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            // Schedule background check 10 minutes after boot
            mHandler.postDelayed(this::checkForUpdate, 10 * 60 * 1000L);
        }
    }

    // ---- Core update logic ----

    public void checkForUpdate() {
        mHandler.post(() -> {
            try {
                Slog.i(TAG, "Checking for OTA update…");
                JSONObject manifest = fetchManifest();
                if (manifest == null) return;

                String serverVersion  = manifest.getString("version");
                String currentVersion = Build.VERSION.INCREMENTAL; // ro.circle.version

                if (isNewerVersion(serverVersion, currentVersion)) {
                    Slog.i(TAG, "Update available: " + serverVersion);
                    String url    = manifest.getString("url");
                    String sha256 = manifest.getString("sha256");
                    downloadAndInstall(url, sha256, serverVersion);
                } else {
                    Slog.i(TAG, "Circle OS is up to date (" + currentVersion + ")");
                }
            } catch (Exception e) {
                Slog.e(TAG, "Update check failed", e);
            }
        });
    }

    private JSONObject fetchManifest() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(UPDATE_URL).openConnection();
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(15_000);
        try {
            if (conn.getResponseCode() != 200) return null;
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line);
            }
            return new JSONObject(sb.toString());
        } finally {
            conn.disconnect();
        }
    }

    private void downloadAndInstall(String url, String expectedSha256, String version)
            throws Exception {

        new File(OTA_DIR).mkdirs();
        File otaFile = new File(OTA_FILE);

        Slog.i(TAG, "Downloading OTA: " + url);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(60_000);

        try (InputStream in = conn.getInputStream();
             FileOutputStream out = new FileOutputStream(otaFile)) {
            byte[] buf = new byte[65536];
            int len;
            while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
        } finally {
            conn.disconnect();
        }

        // Verify SHA-256
        if (!verifySha256(otaFile, expectedSha256)) {
            Slog.e(TAG, "OTA SHA-256 mismatch — aborting");
            otaFile.delete();
            return;
        }

        Slog.i(TAG, "OTA verified, scheduling install");

        // Install: A/B or classic recovery
        boolean isAB = "true".equals(
                android.os.SystemProperties.get("ro.virtual_ab.enabled", "false"));
        if (isAB) {
            RecoverySystem.scheduleUpdateFromFile(getContext(), otaFile, null, null);
        } else {
            RecoverySystem.installPackage(getContext(), otaFile);
        }
    }

    private static boolean verifySha256(File file, String expected) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new java.io.FileInputStream(file)) {
            byte[] buf = new byte[65536];
            int len;
            while ((len = in.read(buf)) > 0) md.update(buf, 0, len);
        }
        byte[] digest = md.digest();
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest) hex.append(String.format("%02x", b));
        return hex.toString().equalsIgnoreCase(expected);
    }

    private static boolean isNewerVersion(String server, String current) {
        // Simple comparison on semver-like strings; good enough for alpha
        return !server.equals(current) && server.compareTo(current) > 0;
    }

    // Stub binder — full AIDL in next iteration
    private static class UpdateBinder extends android.os.Binder {}
}
