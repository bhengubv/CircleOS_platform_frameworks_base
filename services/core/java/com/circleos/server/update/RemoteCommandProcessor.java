/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.Build;
import android.os.PowerManager;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Phase 7: remote command execution.
 *
 * <p>Called once per update-check cycle from {@link CircleUpdateService}.
 * Polls {@code GET /api/os/commands/pending?device_id_hash=X&channel=Y},
 * executes each pending command in order, then ACKs the result back to the
 * server via {@code POST /api/os/commands/{id}/ack}.
 *
 * <h3>Supported command types</h3>
 * <ul>
 *   <li><b>FORCE_UPDATE</b> — triggers an immediate update check regardless of
 *       schedule or current state.</li>
 *   <li><b>CHANGE_CHANNEL</b> — parameters: {@code {"channel":"beta"}}. Persists
 *       the channel override via {@link CircleUpdateService#setChannel}.</li>
 *   <li><b>REBOOT</b> — parameters: {@code {"reason":null}}. Issues a normal
 *       reboot via PowerManager; respects the {@code reason} field if set.</li>
 *   <li><b>CLEAR_CACHE</b> — removes all files from the update staging directory
 *       {@value #UPDATE_DIR}.</li>
 *   <li><b>SET_PROPERTY</b> — parameters: {@code {"key":"circleos.flags.X","value":"1"}}.
 *       Only keys under the {@code circleos.} namespace are allowed.</li>
 * </ul>
 *
 * <p>Each command is ACKed regardless of success/failure so the server can
 * track execution state accurately.
 */
public class RemoteCommandProcessor {

    private static final String TAG = "RemoteCommandProcessor";

    private static final String DEFAULT_BASE_URL = "https://sleptonapi.thegeeknetwork.co.za";
    private static final String UPDATE_DIR       = "/data/system/circleos_update";

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 10_000;

    // ── Callback interfaces ───────────────────────────────────────────────────

    /** Callback supplied by {@link CircleUpdateService} to handle commands that need service-level action. */
    public interface CommandCallback {
        /** Trigger an immediate update check. */
        void onForceUpdate();
        /** Persist and apply a channel change. */
        void onChangeChannel(String newChannel);
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private final android.content.Context mContext;
    private final CommandCallback         mCallback;

    // ── Constructor ───────────────────────────────────────────────────────────

    public RemoteCommandProcessor(android.content.Context context, CommandCallback callback) {
        mContext  = context;
        mCallback = callback;
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /**
     * Fetches and processes all pending commands for this device.
     * Must be called on a background thread.
     *
     * @param channel The device's current release channel.
     */
    public void processPendingCommands(String channel) {
        String deviceIdHash = getDeviceIdHash();
        JSONArray commands  = fetchPendingCommands(deviceIdHash, channel);

        if (commands == null || commands.length() == 0) {
            Log.d(TAG, "No pending commands");
            return;
        }

        Log.i(TAG, "Processing " + commands.length() + " pending command(s)");
        for (int i = 0; i < commands.length(); i++) {
            JSONObject cmd = commands.optJSONObject(i);
            if (cmd == null) continue;
            processCommand(cmd, deviceIdHash);
        }
    }

    // ── Fetch ─────────────────────────────────────────────────────────────────

    private JSONArray fetchPendingCommands(String deviceIdHash, String channel) {
        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/commands/pending"
                + "?device_id_hash=" + deviceIdHash
                + "&channel=" + channel;

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            if (code != 200) {
                Log.d(TAG, "Command endpoint returned HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }

            return new JSONArray(sb.toString());

        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch pending commands: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ── Execute ───────────────────────────────────────────────────────────────

    private void processCommand(JSONObject cmd, String deviceIdHash) {
        int    id          = cmd.optInt("id", -1);
        String commandType = cmd.optString("commandType", "").toUpperCase();
        JSONObject params  = cmd.optJSONObject("parameters");
        if (params == null) params = new JSONObject();

        Log.i(TAG, "Executing command id=" + id + " type=" + commandType);

        boolean success = false;
        String  errorMsg = null;

        try {
            switch (commandType) {
                case "FORCE_UPDATE":
                    success = executeForceUpdate();
                    break;
                case "CHANGE_CHANNEL":
                    success = executeChangeChannel(params);
                    break;
                case "REBOOT":
                    success = executeReboot(params);
                    break;
                case "CLEAR_CACHE":
                    success = executeClearCache();
                    break;
                case "SET_PROPERTY":
                    success = executeSetProperty(params);
                    break;
                default:
                    errorMsg = "Unknown command type: " + commandType;
                    Log.w(TAG, errorMsg);
                    break;
            }
        } catch (Exception e) {
            errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Log.e(TAG, "Command " + id + " failed: " + errorMsg, e);
        }

        ackCommand(id, deviceIdHash, success, errorMsg);
    }

    // ── Command implementations ───────────────────────────────────────────────

    private boolean executeForceUpdate() {
        Log.i(TAG, "FORCE_UPDATE: triggering immediate update check");
        if (mCallback != null) {
            mCallback.onForceUpdate();
            return true;
        }
        return false;
    }

    private boolean executeChangeChannel(JSONObject params) throws Exception {
        String newChannel = params.getString("channel");
        if (newChannel == null || newChannel.isEmpty()) {
            throw new IllegalArgumentException("channel parameter is required for CHANGE_CHANNEL");
        }
        if (!new java.util.HashSet<>(java.util.Arrays.asList("stable", "beta", "nightly"))
                .contains(newChannel)) {
            throw new IllegalArgumentException("Invalid channel: " + newChannel);
        }
        Log.i(TAG, "CHANGE_CHANNEL: switching to " + newChannel);
        if (mCallback != null) {
            mCallback.onChangeChannel(newChannel);
        }
        return true;
    }

    private boolean executeReboot(JSONObject params) {
        String reason = params.optString("reason", null);
        if (reason != null && reason.isEmpty()) reason = null;
        Log.i(TAG, "REBOOT: reason=" + reason);
        PowerManager pm = (PowerManager) mContext.getSystemService(android.content.Context.POWER_SERVICE);
        if (pm == null) {
            Log.e(TAG, "PowerManager unavailable");
            return false;
        }
        pm.reboot(reason);
        return true; // unreachable after reboot, but ACK was already attempted
    }

    private boolean executeClearCache() {
        Log.i(TAG, "CLEAR_CACHE: removing update staging files");
        File dir = new File(UPDATE_DIR);
        if (!dir.exists()) return true;
        File[] files = dir.listFiles();
        if (files == null) return true;
        boolean allDeleted = true;
        for (File f : files) {
            if (f.isFile() && !f.getName().equals("prefs.json")
                    && !f.getName().equals("policy_cache.json")
                    && !f.getName().equals("ab_update_state.json")) {
                boolean deleted = f.delete();
                Log.d(TAG, (deleted ? "Deleted" : "Failed to delete") + ": " + f.getName());
                if (!deleted) allDeleted = false;
            }
        }
        return allDeleted;
    }

    private boolean executeSetProperty(JSONObject params) throws Exception {
        String key   = params.getString("key");
        String value = params.getString("value");

        if (key == null || !key.startsWith("circleos.")) {
            throw new SecurityException(
                    "SET_PROPERTY only allows keys under the 'circleos.' namespace, got: " + key);
        }
        Log.i(TAG, "SET_PROPERTY: " + key + "=" + value);
        SystemProperties.set(key, value);
        return true;
    }

    // ── ACK ───────────────────────────────────────────────────────────────────

    private void ackCommand(int commandId, String deviceIdHash, boolean success, String errorMessage) {
        if (commandId < 0) return;

        String baseUrl = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        String urlStr  = baseUrl + "/api/os/commands/" + commandId + "/ack";

        HttpURLConnection conn = null;
        try {
            JSONObject body = new JSONObject();
            body.put("deviceIdHash", deviceIdHash);
            body.put("success", success);
            if (errorMessage != null) {
                body.put("errorMessage", errorMessage);
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
            Log.d(TAG, "ACK command " + commandId + " → HTTP " + code
                    + " (success=" + success + ")");

        } catch (Exception e) {
            Log.w(TAG, "Failed to ACK command " + commandId + ": " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ── Device ID hash (shared with UpdateTelemetry) ──────────────────────────

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
