/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.update;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.JsonReader;
import android.util.Slog;

import com.android.server.SystemService;

import org.json.JSONException;
import org.json.JSONObject;

import za.co.circleos.update.ICircleUpdateService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Circle OS OTA Update Service.
 *
 * <p>Real implementation of the {@link ICircleUpdateService} AIDL. Talks
 * to the SleptOnAPI OTA endpoint at {@code https://ota.circleos.co.za}
 * (overridable via {@code ro.circleos.update.url}), persists state to
 * a SharedPreferences file in device-protected storage, and stages
 * updates through Android's {@code update_engine} service.
 *
 * <p>State machine: {@link #STATE_IDLE} -> {@link #STATE_CHECKING} ->
 * {@link #STATE_DOWNLOADING} -> {@link #STATE_STAGED} (or
 * {@link #STATE_ERROR}). Settings UIs treat the int opaquely.
 *
 * <p>SELinux: service_contexts maps {@code circle.update} ->
 * {@code circle_update_service:s0} so {@code system_server} can register
 * and {@code platform_app} can find. The trailing underscore variant
 * {@code circle_update} that the AIDL comment mentions is intentionally
 * NOT registered -- only one canonical name to keep the SELinux
 * footprint minimal.
 */
public final class CircleUpdateService extends SystemService {

    private static final String TAG = "CircleUpdate";

    /** Service name. Matches vendor/circle/sepolicy/service_contexts. */
    public static final String SERVICE_NAME = "circle.update";

    // ---- State machine ----
    public static final int STATE_IDLE        = 0;
    public static final int STATE_CHECKING    = 1;
    public static final int STATE_DOWNLOADING = 2;
    public static final int STATE_STAGED      = 3;
    public static final int STATE_ERROR       = 4;

    // ---- Persistence keys ----
    private static final String PREFS_FILE       = "circle_update";
    private static final String KEY_STATE        = "state";
    private static final String KEY_AVAILABLE    = "available_version";
    private static final String KEY_PAYLOAD_URL  = "payload_url";
    private static final String KEY_PAYLOAD_HASH = "payload_hash";
    private static final String KEY_LAST_CHECK   = "last_check_ms";
    private static final String KEY_CHANNEL      = "channel";

    /** Default channel when ro.circleos.channel isn't set. */
    private static final String DEFAULT_CHANNEL = "stable";

    /** Connect timeout for the OTA check (ms). */
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 15_000;

    private final SharedPreferences mPrefs;
    private final HandlerThread     mWorker = new HandlerThread("CircleUpdate");
    private final Handler           mHandler;
    private final UpdateBinder      mBinder = new UpdateBinder();

    /** Mutable while a download is in flight; -1 otherwise. */
    private volatile int mDownloadProgress = -1;

    public CircleUpdateService(Context context) {
        super(context);
        final Context dp = context.createDeviceProtectedStorageContext();
        mPrefs = dp.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE);
        mWorker.start();
        mHandler = new Handler(mWorker.getLooper());

        // First-run channel: prefer the persisted value, fall back to the
        // ro.circleos.channel prop (set by vendor/circle/config/common.mk),
        // fall back to "stable".
        if (!mPrefs.contains(KEY_CHANNEL)) {
            final String fromProp = SystemProperties.get("ro.circleos.channel", DEFAULT_CHANNEL);
            mPrefs.edit().putString(KEY_CHANNEL,
                    TextUtils.isEmpty(fromProp) ? DEFAULT_CHANNEL : fromProp).apply();
        }
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
    }

    // ------------------------------------------------------------------
    //  Binder impl
    // ------------------------------------------------------------------

    private final class UpdateBinder extends ICircleUpdateService.Stub {

        @Override
        public int getState() {
            enforceQueryOta();
            return mPrefs.getInt(KEY_STATE, STATE_IDLE);
        }

        @Override
        public String getAvailableVersion() {
            enforceQueryOta();
            return mPrefs.getString(KEY_AVAILABLE, "");
        }

        @Override
        public int getDownloadProgress() {
            enforceQueryOta();
            return mDownloadProgress;
        }

        @Override
        public long getLastCheckTime() {
            enforceQueryOta();
            return mPrefs.getLong(KEY_LAST_CHECK, 0L);
        }

        @Override
        public String getChannel() {
            enforceQueryOta();
            return mPrefs.getString(KEY_CHANNEL, DEFAULT_CHANNEL);
        }

        @Override
        public void setChannel(String channel) {
            enforceManageOta();
            if (TextUtils.isEmpty(channel)) channel = DEFAULT_CHANNEL;
            mPrefs.edit().putString(KEY_CHANNEL, channel).apply();
            Slog.i(TAG, "Channel switched -> " + channel + "; triggering check");
            // Triggering a check is part of the setChannel contract -- the
            // UI shows the latest manifest for the new channel immediately.
            scheduleCheck();
        }

        @Override
        public void checkNow() {
            enforceTriggerOta();
            scheduleCheck();
        }

        @Override
        public void applyUpdate() {
            enforceTriggerOta();
            final String payloadUrl  = mPrefs.getString(KEY_PAYLOAD_URL,  "");
            final String payloadHash = mPrefs.getString(KEY_PAYLOAD_HASH, "");
            if (TextUtils.isEmpty(payloadUrl)) {
                setState(STATE_ERROR);
                Slog.w(TAG, "applyUpdate called with no staged payload — checkNow first");
                return;
            }
            mHandler.post(() -> stagePayload(payloadUrl, payloadHash));
        }
    }

    // ------------------------------------------------------------------
    //  Worker logic
    // ------------------------------------------------------------------

    private void scheduleCheck() {
        setState(STATE_CHECKING);
        mHandler.post(this::performCheck);
    }

    /**
     * Real HTTP call to the OTA endpoint. URL pattern:
     *
     *   {ro.circleos.update.url}/api/os/check
     *       ?device={ro.product.system.device}
     *       &channel={channel}
     *       &current={ro.circle.version}
     *
     * Response (JSON):
     *
     *   {
     *     "update_available": true,
     *     "version": "0.1.1-alpha",
     *     "payload_url": "https://cdn.thegeek.co.za/circleos/0.1.1-alpha/.../payload.bin",
     *     "payload_sha256": "abc...",
     *     "min_version": "0.1.0"
     *   }
     */
    private void performCheck() {
        final String base = SystemProperties.get(
                "ro.circleos.update.url", "https://ota.circleos.co.za");
        final String device = SystemProperties.get("ro.product.system.device", "generic_arm64");
        final String channel = mPrefs.getString(KEY_CHANNEL, DEFAULT_CHANNEL);
        final String current = SystemProperties.get("ro.circle.version", "0.0.0");
        final String url = base + "/api/os/check"
                + "?device="  + device
                + "&channel=" + channel
                + "&current=" + current;

        Slog.i(TAG, "Check: " + url);

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "CircleOS-Updater/1.0");
            conn.setRequestProperty("Accept", "application/json");
            final int code = conn.getResponseCode();
            if (code != 200) {
                Slog.w(TAG, "OTA check HTTP " + code);
                setState(STATE_ERROR);
                return;
            }
            final StringBuilder body = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    body.append(line);
                    if (body.length() > 65536) {
                        // Server should never send us > 64 KB for a check
                        // response; cap to avoid OOM from a runaway origin.
                        Slog.w(TAG, "OTA check body > 64 KB, truncating");
                        break;
                    }
                }
            }
            final JSONObject json = new JSONObject(body.toString());

            final SharedPreferences.Editor e = mPrefs.edit();
            e.putLong(KEY_LAST_CHECK, System.currentTimeMillis());
            if (json.optBoolean("update_available", false)) {
                e.putString(KEY_AVAILABLE,    json.optString("version", ""));
                e.putString(KEY_PAYLOAD_URL,  json.optString("payload_url", ""));
                e.putString(KEY_PAYLOAD_HASH, json.optString("payload_sha256", ""));
                e.putInt(KEY_STATE,           STATE_STAGED);
                Slog.i(TAG, "Update available: " + json.optString("version"));
            } else {
                e.putString(KEY_AVAILABLE, "");
                e.putInt(KEY_STATE,        STATE_IDLE);
                Slog.i(TAG, "No update available on channel " + channel);
            }
            e.apply();
        } catch (IOException | JSONException ex) {
            Slog.w(TAG, "OTA check failed", ex);
            setState(STATE_ERROR);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Stage the payload into the inactive A/B slot via Android's
     * {@code update_engine}. update_engine handles download, hash
     * verification against the property file, and slot switching.
     *
     * <p>For alpha-1: update_engine integration is the bridge between
     * our cached payload URL and Android's standard A/B OTA. The
     * UpdateEngine binder is at SystemProperties default location
     * but accessed via reflection because the public AIDL isn't in
     * services.core's static_libs by default; using reflection keeps
     * this service buildable without dragging in IUpdateEngine.aidl.
     */
    private void stagePayload(String payloadUrl, String expectedHash) {
        mDownloadProgress = 0;
        setState(STATE_DOWNLOADING);
        try {
            final IBinder b = ServiceManager.getService("android.os.IUpdateEngine");
            if (b == null) {
                Slog.w(TAG, "update_engine binder unavailable -- cannot stage "
                        + payloadUrl);
                setState(STATE_ERROR);
                mDownloadProgress = -1;
                return;
            }
            // Build the standard update_engine properties array. Hash + size
            // come from the OTA manifest; for alpha-1 we pass the URL through
            // and let update_engine fetch + verify.
            // applyPayload signature: void applyPayload(String url, long offset,
            //                                            long size, String[] keyValuePairs);
            // Properties: at minimum PAYLOAD_HASH + PAYLOAD_SIZE; for now we pass
            // FILE_HASH if we have it.
            final String[] props = TextUtils.isEmpty(expectedHash)
                    ? new String[0]
                    : new String[]{"PAYLOAD_HASH=" + expectedHash};

            // Reflective dispatch to avoid AIDL coupling for the scaffold —
            // when IUpdateEngine.Stub is on services.core's classpath we can
            // call directly. android.os.IUpdateEngine.Stub.asInterface(b)
            // .applyPayload(payloadUrl, 0, 0, props)
            Class<?> stub = Class.forName("android.os.IUpdateEngine$Stub");
            Object eng = stub.getMethod("asInterface", IBinder.class).invoke(null, b);
            eng.getClass().getMethod("applyPayload",
                            String.class, long.class, long.class, String[].class)
                    .invoke(eng, payloadUrl, 0L, 0L, props);
            Slog.i(TAG, "applyPayload submitted to update_engine: " + payloadUrl);
            // update_engine will progress asynchronously. Real wiring of
            // IUpdateEngineCallback for live progress -> mDownloadProgress
            // lands when we add the callback AIDL to services.core
            // static_libs in the next CL. Until then progress stays at 0 in
            // STATE_DOWNLOADING and flips to STATE_STAGED via a check.
        } catch (ClassNotFoundException | NoSuchMethodException
                 | IllegalAccessException | java.lang.reflect.InvocationTargetException ex) {
            Slog.w(TAG, "update_engine dispatch failed", ex);
            setState(STATE_ERROR);
            mDownloadProgress = -1;
        }
    }

    private void setState(int state) {
        mPrefs.edit().putInt(KEY_STATE, state).apply();
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    private void enforceQueryOta() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.QUERY_OTA once declared.
    }

    private void enforceTriggerOta() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.TRIGGER_OTA once declared.
    }

    private void enforceManageOta() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.MANAGE_OTA once declared.
    }
}
