/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.mesh.ICircleMeshService;
import za.co.circleos.update.ICircleUpdateService;

import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 * CircleOS OTA update system service.
 *
 * Service name: {@value #SERVICE_NAME}
 *
 * Pipeline:
 *   onBootCompleted() → (60 s delay) → triggerCheck()
 *     → UpdateChecker.check() → no update → IDLE
 *                              → update found → UpdateDownloader.download()
 *                                → success → READY_TO_INSTALL + notification
 *                                → failure → FAILED + notification
 *   applyUpdate() → UpdateInstaller.install() → reboot (inside UpdateInstaller)
 *
 * Channel preference is persisted to {@value #PREFS_FILE}.
 */
public class CircleUpdateService extends SystemService {

    private static final String TAG = "CircleUpdateService";

    public static final String SERVICE_NAME = "circle.update";

    private static final String UPDATE_DIR = "/data/system/circleos_update";
    private static final String PREFS_FILE = UPDATE_DIR + "/prefs.json";

    private static final long   FIRST_CHECK_DELAY_MS = 60_000L; // 60 seconds after boot

    // ── Singleton reference for static triggerCheck() ─────────────────────────
    private static volatile CircleUpdateService sInstance;

    // ── Instance fields ───────────────────────────────────────────────────────
    private HandlerThread mHandlerThread;
    private Handler       mHandler;

    private UpdateChecker             mChecker;
    private UpdateDownloader          mDownloader;
    private MeshOtaDownloader        mMeshDownloader;
    private UpdateInstaller           mInstaller;
    private UpdateNotificationManager mNotifManager;
    private UpdateScheduler.UpdateCheckReceiver mCheckReceiver;

    private volatile int    mState           = UpdateState.IDLE;
    private volatile String mAvailableVersion;
    private volatile int    mDownloadProgress = -1;
    private volatile long   mLastCheckTime    = 0L;

    /** Currently downloaded OTA file, ready to install. */
    private volatile File   mDownloadedFile;

    /** User-persisted channel override; null means use build property. */
    private volatile String mChannelOverride;

    // ── Constructor ───────────────────────────────────────────────────────────

    public CircleUpdateService(Context context) {
        super(context);
        sInstance = this;
    }

    // ── SystemService lifecycle ───────────────────────────────────────────────

    @Override
    public void onStart() {
        Log.i(TAG, "Starting CircleUpdateService");

        mHandlerThread = new HandlerThread("CircleUpdate");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        mChecker        = new UpdateChecker(getContext());
        mDownloader     = new UpdateDownloader(getContext());
        mMeshDownloader = new MeshOtaDownloader(getContext());
        mInstaller      = new UpdateInstaller(getContext());
        mNotifManager   = new UpdateNotificationManager(getContext());

        // Ensure update directory exists
        new File(UPDATE_DIR).mkdirs();

        // Load persisted preferences
        loadPrefs();

        publishBinderService(SERVICE_NAME, mBinder);
        Log.i(TAG, "Published as " + SERVICE_NAME);
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            onBootCompleted();
        }
    }

    // ── Boot handling ─────────────────────────────────────────────────────────

    void onBootCompleted() {
        Log.i(TAG, "Boot completed — scheduling update checks");

        // Register the alarm receiver programmatically
        mCheckReceiver = new UpdateScheduler.UpdateCheckReceiver();
        getContext().registerReceiver(
                mCheckReceiver,
                UpdateScheduler.buildIntentFilter(),
                Context.RECEIVER_NOT_EXPORTED);

        // Schedule the 12-hour repeating alarm
        UpdateScheduler.schedule(getContext());

        // Trigger first check after a short delay to not burden early boot
        mHandler.postDelayed(this::runCheck, FIRST_CHECK_DELAY_MS);
    }

    // ── Package-private: called by UpdateScheduler ───────────────────────────

    /**
     * Static entry point called by {@link UpdateScheduler.UpdateCheckReceiver}.
     * Delegates to the live singleton instance, if one exists.
     */
    static void triggerCheck() {
        CircleUpdateService svc = sInstance;
        if (svc == null) {
            Log.w(TAG, "triggerCheck() called before service started");
            return;
        }
        svc.mHandler.post(svc::runCheck);
    }

    // ── Core pipeline ─────────────────────────────────────────────────────────

    private void runCheck() {
        if (mState == UpdateState.CHECKING
                || mState == UpdateState.DOWNLOADING
                || mState == UpdateState.INSTALLING) {
            Log.d(TAG, "Check skipped — already in state " + UpdateState.name(mState));
            return;
        }

        Log.i(TAG, "Running update check");
        setState(UpdateState.CHECKING);

        // Apply current channel override to checker
        mChecker.setChannelOverride(mChannelOverride);

        UpdateChecker.UpdateInfo info;
        try {
            info = mChecker.check();
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during update check", e);
            info = null;
        }

        mLastCheckTime = System.currentTimeMillis();

        if (info == null) {
            Log.i(TAG, "Update check failed or returned null — going IDLE");
            setState(UpdateState.IDLE);
            return;
        }

        if (!info.hasUpdate) {
            Log.i(TAG, "Device is up to date");
            setState(UpdateState.IDLE);
            return;
        }

        Log.i(TAG, "Update available: " + info.version + " from " + info.manifestUrl);
        mAvailableVersion = info.version;
        startDownload(info);
    }

    private void startDownload(final UpdateChecker.UpdateInfo info) {
        setState(UpdateState.DOWNLOADING);
        mDownloadProgress = 0;
        mNotifManager.showDownloading(0);

        // Determine active channel for mesh manifest query
        final String channel = (mChannelOverride != null)
                ? mChannelOverride
                : SystemProperties.get("ro.circleos.channel", "stable");

        mHandler.post(() -> {
            File downloaded = null;

            // ── Phase 4: attempt mesh P2P chunk delivery first ────────────────
            if (isMeshAvailable()) {
                Log.i(TAG, "Mesh is active — attempting mesh chunk delivery for v"
                        + info.version);
                try {
                    downloaded = mMeshDownloader.download(
                            info.version,
                            channel,
                            percent -> {
                                mDownloadProgress = percent;
                                mNotifManager.showDownloading(percent);
                            });
                    Log.i(TAG, "Mesh delivery succeeded: " + downloaded.getAbsolutePath());
                } catch (Exception e) {
                    Log.w(TAG, "Mesh delivery failed, falling back to direct CDN: "
                            + e.getMessage());
                    downloaded = null;
                }
            }

            // ── Fallback: direct CDN download via DownloadManager ─────────────
            if (downloaded == null) {
                Log.i(TAG, "Using direct CDN download for v" + info.version);
                try {
                    downloaded = mDownloader.download(
                            info.manifestUrl,
                            info.version,
                            percent -> {
                                mDownloadProgress = percent;
                                mNotifManager.showDownloading(percent);
                            });
                } catch (Exception e) {
                    Log.e(TAG, "CDN download failed", e);
                    mDownloadProgress = -1;
                    setState(UpdateState.FAILED);
                    mNotifManager.showFailed(e.getMessage() != null
                            ? e.getMessage() : "Download error");
                    return;
                }
            }

            mDownloadedFile = downloaded;
            mDownloadProgress = 100;
            setState(UpdateState.READY_TO_INSTALL);
            mNotifManager.showReadyToInstall(info.version);
            Log.i(TAG, "Download complete: " + downloaded.getAbsolutePath());
        });
    }

    /**
     * Returns true when the CircleMeshService is reachable and reports at least
     * one peer — a prerequisite for useful mesh chunk delivery.
     */
    private boolean isMeshAvailable() {
        try {
            IBinder binder = ServiceManager.getService("circle.mesh");
            if (binder == null) return false;
            ICircleMeshService mesh = ICircleMeshService.Stub.asInterface(binder);
            return mesh.isRunning() && mesh.getPeerCount() > 0;
        } catch (Exception e) {
            Log.d(TAG, "Mesh availability check failed: " + e.getMessage());
            return false;
        }
    }

    private void applyUpdateInternal() {
        File file = mDownloadedFile;
        if (file == null || !file.exists()) {
            Log.e(TAG, "applyUpdate() called but no downloaded file found");
            setState(UpdateState.FAILED);
            mNotifManager.showFailed("Update file not found");
            return;
        }

        setState(UpdateState.INSTALLING);
        mNotifManager.cancel();
        // Stop serving chunks to peers — we're about to install
        mMeshDownloader.stopChunkServer();

        mHandler.post(() -> {
            try {
                mInstaller.install(file, null /* callback — reboot handled inside installer */);
            } catch (IOException e) {
                Log.e(TAG, "Install failed", e);
                setState(UpdateState.FAILED);
                mNotifManager.showFailed(e.getMessage() != null
                        ? e.getMessage() : "Install error");
            }
        });
    }

    // ── State helpers ─────────────────────────────────────────────────────────

    private void setState(int newState) {
        Log.d(TAG, "State: " + UpdateState.name(mState) + " -> " + UpdateState.name(newState));
        mState = newState;
    }

    // ── Preferences ───────────────────────────────────────────────────────────

    private void loadPrefs() {
        File prefsFile = new File(PREFS_FILE);
        if (!prefsFile.exists()) return;
        try (FileReader reader = new FileReader(prefsFile)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[1024];
            int n;
            while ((n = reader.read(buf)) > 0) sb.append(buf, 0, n);
            JSONObject obj = new JSONObject(sb.toString());
            mChannelOverride = obj.optString("channel", null);
            Log.d(TAG, "Loaded channel override: " + mChannelOverride);
        } catch (Exception e) {
            Log.w(TAG, "Failed to load prefs", e);
        }
    }

    private void savePrefs() {
        new File(UPDATE_DIR).mkdirs();
        File prefsFile = new File(PREFS_FILE);
        try (FileWriter writer = new FileWriter(prefsFile)) {
            JSONObject obj = new JSONObject();
            if (mChannelOverride != null) {
                obj.put("channel", mChannelOverride);
            }
            writer.write(obj.toString());
            Log.d(TAG, "Saved prefs: " + obj);
        } catch (Exception e) {
            Log.w(TAG, "Failed to save prefs", e);
        }
    }

    // ── Binder implementation ─────────────────────────────────────────────────

    final ICircleUpdateService.Stub mBinder = new ICircleUpdateService.Stub() {

        @Override
        public boolean checkNow() {
            Log.i(TAG, "checkNow() requested via binder");
            if (mState == UpdateState.CHECKING
                    || mState == UpdateState.DOWNLOADING
                    || mState == UpdateState.INSTALLING) {
                return false;
            }
            mHandler.post(CircleUpdateService.this::runCheck);
            return true;
        }

        @Override
        public int getState() {
            return mState;
        }

        @Override
        public String getAvailableVersion() {
            return mAvailableVersion;
        }

        @Override
        public int getDownloadProgress() {
            return mDownloadProgress;
        }

        @Override
        public long getLastCheckTime() {
            return mLastCheckTime;
        }

        @Override
        public void applyUpdate() {
            Log.i(TAG, "applyUpdate() requested via binder");
            if (mState != UpdateState.READY_TO_INSTALL) {
                Log.w(TAG, "applyUpdate() ignored — state is " + UpdateState.name(mState));
                return;
            }
            applyUpdateInternal();
        }

        @Override
        public String getChannel() {
            if (mChannelOverride != null) return mChannelOverride;
            return SystemProperties.get("ro.circleos.channel", "stable");
        }

        @Override
        public void setChannel(String channel) {
            Log.i(TAG, "setChannel: " + channel);
            mChannelOverride = channel;
            savePrefs();
            // Trigger a fresh check on channel change (in background)
            mHandler.post(CircleUpdateService.this::runCheck);
        }
    };

    // ── Lifecycle wrapper ─────────────────────────────────────────────────────

    /**
     * SystemService lifecycle wrapper registered in SystemServer.
     * Pattern mirrors {@code CircleInferenceService.Lifecycle}.
     */
    public static final class Lifecycle extends SystemService {
        private CircleUpdateService mService;

        public Lifecycle(Context context) { super(context); }

        @Override
        public void onStart() {
            mService = new CircleUpdateService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            if (phase == PHASE_BOOT_COMPLETED) {
                mService.onBootCompleted();
            }
        }
    }
}
