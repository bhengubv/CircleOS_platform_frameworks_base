/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * SystemUpdateService — implements ICircleUpdateService.aidl
 *
 * Registered in SystemServer as "circle.update".
 * Drives the A/B OTA state machine and delegates payload application to UpdateEngine.
 */
package za.co.circleos.update;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UpdateEngine;
import android.os.UpdateEngineCallback;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import za.co.circleos.update.ICircleUpdateService;

/**
 * OTA update service for CircleOS.
 *
 * State machine:
 *   IDLE(0) → CHECKING(1) → IDLE(0)                         [no update]
 *   IDLE(0) → CHECKING(1) → DOWNLOADING(2) → READY(3) → INSTALLING(4) → IDLE(0)
 *   Any → FAILED(5) → IDLE(0)
 */
public class SystemUpdateService extends ICircleUpdateService.Stub {

    private static final String TAG = "CircleUpdateService";

    // State constants (match ICircleUpdateService.aidl)
    public static final int STATE_IDLE             = 0;
    public static final int STATE_CHECKING         = 1;
    public static final int STATE_DOWNLOADING      = 2;
    public static final int STATE_READY_TO_INSTALL = 3;
    public static final int STATE_INSTALLING       = 4;
    public static final int STATE_FAILED           = 5;

    // Periodic check interval: 6 hours
    private static final long CHECK_INTERVAL_MS = 6L * 60 * 60 * 1000;

    private final Context       mContext;
    private final Handler       mHandler;
    private final HandlerThread mThread;
    private final UpdateEngine  mUpdateEngine;

    // Persistent state
    private final AtomicInteger mState           = new AtomicInteger(STATE_IDLE);
    private final AtomicInteger mDownloadProgress = new AtomicInteger(-1);
    private final AtomicLong    mLastCheckTime   = new AtomicLong(0);

    private volatile String mAvailableVersion = null;
    private volatile String mPayloadUrl       = null;
    private volatile long   mPayloadOffset    = 0;
    private volatile long   mPayloadSize      = 0;
    private volatile String mChannel;

    // ── Constructor ───────────────────────────────────────────────────────────

    public SystemUpdateService(Context context) {
        mContext = context;
        mChannel = SystemProperties.get("ro.circleos.channel", "stable");

        mThread = new HandlerThread("CircleUpdateService");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());

        mUpdateEngine = new UpdateEngine();
        mUpdateEngine.bind(new UpdateEngineCallback() {
            @Override
            public void onStatusUpdate(int status, float progress) {
                handleEngineStatusUpdate(status, progress);
            }

            @Override
            public void onPayloadApplicationComplete(int errorCode) {
                handlePayloadComplete(errorCode);
            }
        });

        // Device enrolment on first boot (async so we don't block system_server startup)
        mHandler.post(this::enrollDevice);

        // Schedule periodic checks
        schedulePeriodicCheck();
    }

    // ── ICircleUpdateService implementation ───────────────────────────────────

    @Override
    public boolean checkNow() {
        if (mState.get() != STATE_IDLE && mState.get() != STATE_FAILED) {
            return false; // already in progress
        }
        mHandler.removeCallbacks(mCheckRunnable);
        mHandler.post(mCheckRunnable);
        return true;
    }

    @Override
    public int getState() {
        return mState.get();
    }

    @Override
    public String getAvailableVersion() {
        return mAvailableVersion;
    }

    @Override
    public int getDownloadProgress() {
        return mDownloadProgress.get();
    }

    @Override
    public long getLastCheckTime() {
        return mLastCheckTime.get();
    }

    @Override
    public void applyUpdate() {
        if (mState.get() != STATE_READY_TO_INSTALL || mPayloadUrl == null) return;
        mHandler.post(this::doApplyUpdate);
    }

    @Override
    public String getChannel() {
        return mChannel;
    }

    @Override
    public void setChannel(String channel) {
        if (channel == null || channel.isEmpty()) return;
        mChannel = channel;
        // Trigger a fresh check on channel change
        mHandler.post(mCheckRunnable);
    }

    // ── Periodic check ────────────────────────────────────────────────────────

    private final Runnable mCheckRunnable = this::doCheckForUpdate;

    private void schedulePeriodicCheck() {
        mHandler.postDelayed(() -> {
            if (mState.get() == STATE_IDLE) {
                mHandler.post(mCheckRunnable);
            }
            schedulePeriodicCheck();
        }, CHECK_INTERVAL_MS);
    }

    // ── Device enrolment ──────────────────────────────────────────────────────

    private void enrollDevice() {
        try {
            String deviceIdHash = sha256(Build.ID);
            JSONObject body = new JSONObject();
            body.put("deviceIdHash",    deviceIdHash);
            body.put("model",           Build.MODEL);
            body.put("channel",         mChannel);
            body.put("currentVersion",  SystemProperties.get("ro.circle.version", "unknown"));

            postJson(buildUrl("/api/os/devices/enrol"), body.toString());
            Log.i(TAG, "Device enrolment OK");
        } catch (Exception e) {
            Log.w(TAG, "Device enrolment failed (will retry on next boot): " + e.getMessage());
        }
    }

    // ── Update check ──────────────────────────────────────────────────────────

    private void doCheckForUpdate() {
        if (!mState.compareAndSet(STATE_IDLE, STATE_CHECKING) &&
            !mState.compareAndSet(STATE_FAILED, STATE_CHECKING)) {
            return;
        }
        try {
            String device  = SystemProperties.get("ro.circle.device.codename", Build.DEVICE);
            String version = SystemProperties.get("ro.circle.version", "unknown");
            String url = buildUrl("/api/os/releases/latest")
                    + "?device=" + device
                    + "&channel=" + mChannel
                    + "&version=" + version;

            String response = getJson(url);
            mLastCheckTime.set(System.currentTimeMillis());

            if (response == null || response.isEmpty()) {
                mState.set(STATE_IDLE);
                return;
            }

            JSONObject json = new JSONObject(response);
            if (!json.optBoolean("updateAvailable", false)) {
                mState.set(STATE_IDLE);
                return;
            }

            mAvailableVersion = json.optString("version", null);
            mPayloadUrl       = json.optString("payloadUrl", null);
            mPayloadOffset    = json.optLong("payloadOffset", 0);
            mPayloadSize      = json.optLong("payloadSize", 0);

            if (mPayloadUrl == null) {
                mState.set(STATE_IDLE);
                return;
            }

            // Move to DOWNLOADING — UpdateEngine streams directly from CDN URL
            mState.set(STATE_DOWNLOADING);
            mDownloadProgress.set(0);
            Log.i(TAG, "Update available: " + mAvailableVersion + " payload=" + mPayloadUrl);

        } catch (Exception e) {
            Log.e(TAG, "Update check failed", e);
            mState.set(STATE_FAILED);
            postTelemetry("CHECK_FAILED", e.getMessage());
        }
    }

    // ── Apply update via UpdateEngine ─────────────────────────────────────────

    private void doApplyUpdate() {
        if (mState.get() != STATE_READY_TO_INSTALL || mPayloadUrl == null) return;
        try {
            mState.set(STATE_INSTALLING);

            // Read header key/value pairs from payload_properties.txt
            // (served alongside payload.bin by the CDN)
            String propsUrl = mPayloadUrl.replace("payload.bin", "payload_properties.txt");
            String propsRaw = getJson(propsUrl);
            String[] headerKV = propsRaw != null
                    ? propsRaw.trim().split("\n")
                    : new String[0];

            mUpdateEngine.applyPayload(mPayloadUrl, mPayloadOffset, mPayloadSize, headerKV);
            Log.i(TAG, "UpdateEngine.applyPayload() called");
        } catch (Exception e) {
            Log.e(TAG, "applyPayload failed", e);
            mState.set(STATE_FAILED);
            postTelemetry("APPLY_FAILED", e.getMessage());
        }
    }

    // ── UpdateEngine callbacks ────────────────────────────────────────────────

    private void handleEngineStatusUpdate(int status, float progress) {
        // UpdateEngine status codes:
        //   DOWNLOADING = 5 (AOSP UpdateEngine.UpdateStatusConstants.DOWNLOADING)
        //   VERIFYING   = 6
        //   FINALIZING  = 7
        //   UPDATED_NEED_REBOOT = 8
        switch (status) {
            case 5: // DOWNLOADING
                mState.set(STATE_DOWNLOADING);
                mDownloadProgress.set(Math.round(progress * 100));
                break;
            case 6: // VERIFYING
            case 7: // FINALIZING
                mState.set(STATE_INSTALLING);
                break;
            case 8: // UPDATED_NEED_REBOOT
                mState.set(STATE_READY_TO_INSTALL);
                mDownloadProgress.set(100);
                Log.i(TAG, "Payload applied — reboot required");
                break;
            default:
                break;
        }
    }

    private void handlePayloadComplete(int errorCode) {
        if (errorCode == 0) {
            // SUCCESS — device needs reboot; state stays READY_TO_INSTALL
            // (CircleSettings shows "Install and Reboot" button)
            mState.set(STATE_READY_TO_INSTALL);
            postTelemetry("SUCCESS", null);
            Log.i(TAG, "Payload application complete, error=0");
        } else {
            mState.set(STATE_FAILED);
            postTelemetry("ENGINE_ERROR", "errorCode=" + errorCode);
            Log.e(TAG, "Payload application failed, errorCode=" + errorCode);
        }
    }

    // ── Command polling ───────────────────────────────────────────────────────

    /**
     * Poll /api/os/commands/pending and ACK each command.
     * Called after each successful check.
     */
    private void pollCommands() {
        try {
            String device  = SystemProperties.get("ro.circle.device.codename", Build.DEVICE);
            String url = buildUrl("/api/os/commands/pending") + "?device=" + device;
            String response = getJson(url);
            if (response == null || response.isEmpty()) return;

            org.json.JSONArray commands = new org.json.JSONArray(response);
            for (int i = 0; i < commands.length(); i++) {
                JSONObject cmd = commands.getJSONObject(i);
                String id = cmd.optString("id");
                if (id != null && !id.isEmpty()) {
                    postJson(buildUrl("/api/os/commands/" + id + "/ack"), "{}");
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Command poll: " + e.getMessage());
        }
    }

    // ── Telemetry ─────────────────────────────────────────────────────────────

    private void postTelemetry(String event, String detail) {
        mHandler.post(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("event",          event);
                body.put("detail",         detail != null ? detail : "");
                body.put("version",        SystemProperties.get("ro.circle.version", "unknown"));
                body.put("targetVersion",  mAvailableVersion != null ? mAvailableVersion : "");
                body.put("device",         SystemProperties.get("ro.circle.device.codename", Build.DEVICE));
                body.put("channel",        mChannel);
                body.put("timestamp",      System.currentTimeMillis());
                postJson(buildUrl("/api/os/telemetry"), body.toString());
            } catch (Exception e) {
                Log.d(TAG, "Telemetry post failed: " + e.getMessage());
            }
        });
    }

    // ── Crash reporting ───────────────────────────────────────────────────────

    /**
     * Installs an uncaught exception handler that forwards crashes to the SleptOn API.
     * Called once from the constructor.
     */
    private void installCrashReporter() {
        Thread.UncaughtExceptionHandler upstream = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            try {
                JSONObject body = new JSONObject();
                body.put("thread",    thread.getName());
                body.put("exception", throwable.toString());
                body.put("device",    SystemProperties.get("ro.circle.device.codename", Build.DEVICE));
                body.put("version",   SystemProperties.get("ro.circle.version", "unknown"));
                postJson(buildUrl("/api/os/crashes"), body.toString());
            } catch (Exception ignored) { /* best-effort */ }
            if (upstream != null) upstream.uncaughtException(thread, throwable);
        });
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private String buildUrl(String path) {
        String base = SystemProperties.get("ro.circleos.update.url", "https://ota.circleos.co.za");
        // Strip trailing slash
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + path;
    }

    private String getJson(String urlStr) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(15_000);
            conn.setReadTimeout(15_000);
            int code = conn.getResponseCode();
            if (code != 200) return null;
            return readStream(conn.getInputStream());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private void postJson(String urlStr, String body) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15_000);
            conn.setReadTimeout(15_000);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
            conn.getResponseCode(); // consume response
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private String readStream(InputStream in) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return input; // fallback
        }
    }
}
