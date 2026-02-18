/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.Build;
import android.os.FileObserver;
import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Phase 9: crash and ANR reporter.
 *
 * <p>Installs a JVM {@link Thread.UncaughtExceptionHandler} for the system
 * server process to catch unhandled exceptions and report them to
 * {@code POST /api/os/crashes} before re-throwing.
 *
 * <p>Also watches {@code /data/anr/} for new ANR trace files via
 * {@link FileObserver} and reports the first 8 KB of each new trace.
 *
 * <h3>Usage</h3>
 * Call {@link #install(String)} once in {@link CircleUpdateService#onStart()}.
 * The crash handler and ANR watcher remain active for the lifetime of the process.
 */
public class CrashReporter {

    private static final String TAG = "CrashReporter";

    private static final String DEFAULT_BASE_URL   = "https://sleptonapi.thegeeknetwork.co.za";
    private static final int    CONNECT_TIMEOUT_MS = 8_000;
    private static final int    READ_TIMEOUT_MS    = 8_000;
    private static final int    MAX_STACK_BYTES    = 8192;
    private static final String ANR_DIR            = "/data/anr";

    private volatile String mChannel;
    private AnrWatcher      mAnrWatcher;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Installs the crash handler and starts the ANR watcher.
     * Idempotent — safe to call multiple times.
     *
     * @param channel The device's current release channel.
     */
    public synchronized void install(String channel) {
        mChannel = channel;
        installCrashHandler();
        startAnrWatcher();
        Log.i(TAG, "CrashReporter installed for channel=" + channel);
    }

    /** Updates the active channel (e.g. after a CHANGE_CHANNEL command). */
    public void setChannel(String channel) {
        mChannel = channel;
    }

    // ── Crash handler ─────────────────────────────────────────────────────────

    private void installCrashHandler() {
        final Thread.UncaughtExceptionHandler previous =
                Thread.getDefaultUncaughtExceptionHandler();

        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            try {
                String stackTrace = stackTraceToString(throwable);
                reportCrash("CRASH", thread.getName(), throwable.getClass().getName(), stackTrace);
            } catch (Exception ignored) {
                // Never let the reporter itself prevent crash handling
            } finally {
                if (previous != null) {
                    previous.uncaughtException(thread, throwable);
                }
            }
        });
    }

    // ── ANR watcher ───────────────────────────────────────────────────────────

    private void startAnrWatcher() {
        File anrDir = new File(ANR_DIR);
        if (!anrDir.exists()) return;

        mAnrWatcher = new AnrWatcher(ANR_DIR);
        mAnrWatcher.startWatching();
    }

    private final class AnrWatcher extends FileObserver {
        AnrWatcher(String path) {
            super(path, FileObserver.CLOSE_WRITE);
        }

        @Override
        public void onEvent(int event, String filename) {
            if (filename == null || !filename.startsWith("trace")) return;
            File traceFile = new File(ANR_DIR, filename);
            try {
                String content = readFirst8k(traceFile);
                if (content != null && !content.isEmpty()) {
                    // Extract process name from first line of ANR trace (heuristic)
                    String processName = extractProcessName(content);
                    reportCrash("ANR", processName, "ApplicationNotResponding", content);
                }
            } catch (Exception e) {
                Log.d(TAG, "Failed to read ANR trace " + filename + ": " + e.getMessage());
            }
        }

        private String readFirst8k(File f) {
            try (FileReader reader = new FileReader(f)) {
                char[] buf = new char[MAX_STACK_BYTES];
                int read = reader.read(buf);
                return read > 0 ? new String(buf, 0, read) : null;
            } catch (Exception e) {
                return null;
            }
        }

        private String extractProcessName(String trace) {
            for (String line : trace.split("\n", 10)) {
                if (line.startsWith("----- pid ")) {
                    // "----- pid 1234 at ... -----"
                    String[] parts = line.split(" ");
                    if (parts.length > 2) return "pid:" + parts[2];
                }
            }
            return "unknown";
        }
    }

    // ── Report ────────────────────────────────────────────────────────────────

    private void reportCrash(String type, String processName,
            String exceptionType, String stackTrace) {
        try {
            JSONObject body = new JSONObject();
            body.put("deviceIdHash", DeviceEnrollment.getDeviceIdHash());
            body.put("channel",      mChannel != null ? mChannel : "stable");
            body.put("osVersion",    Build.VERSION.RELEASE);
            body.put("crashType",    type);
            body.put("processName",  processName);
            body.put("exceptionType", exceptionType);
            // Truncate stack trace to MAX_STACK_BYTES
            if (stackTrace != null) {
                body.put("stackTrace", stackTrace.length() > MAX_STACK_BYTES
                        ? stackTrace.substring(0, MAX_STACK_BYTES)
                        : stackTrace);
            }

            post(body.toString());
        } catch (Exception e) {
            Log.d(TAG, "Failed to report crash: " + e.getMessage());
        }
    }

    private void post(String jsonBody) throws Exception {
        String baseUrl   = SystemProperties.get("ro.circleos.update.url", DEFAULT_BASE_URL);
        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection)
                new URL(baseUrl + "/api/os/crashes").openConnection();
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setFixedLengthStreamingMode(bodyBytes.length);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }
        conn.getResponseCode(); // flush
        conn.disconnect();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String stackTraceToString(Throwable t) {
        StringBuilder sb = new StringBuilder();
        appendThrowable(sb, t, 0);
        return sb.length() > MAX_STACK_BYTES
                ? sb.substring(0, MAX_STACK_BYTES)
                : sb.toString();
    }

    private static void appendThrowable(StringBuilder sb, Throwable t, int depth) {
        if (depth > 5 || t == null) return;
        sb.append(t.getClass().getName()).append(": ").append(t.getMessage()).append('\n');
        for (StackTraceElement el : t.getStackTrace()) {
            sb.append("  at ").append(el).append('\n');
            if (sb.length() >= MAX_STACK_BYTES) return;
        }
        if (t.getCause() != null) {
            sb.append("Caused by: ");
            appendThrowable(sb, t.getCause(), depth + 1);
        }
    }
}
