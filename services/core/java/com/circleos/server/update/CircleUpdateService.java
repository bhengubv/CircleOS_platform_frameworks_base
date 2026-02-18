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
    private DeltaChecker              mDeltaChecker;
    private OtaPolicyManager          mPolicyManager;
    private UpdateTelemetry           mTelemetry;
    private RemoteCommandProcessor    mCommandProcessor;
    private MaintenanceWindowChecker  mMaintenanceChecker;
    private BootVerifier              mBootVerifier;
    private DeviceEnrollment          mDeviceEnrollment;
    private CrashReporter             mCrashReporter;
    private UpdateDownloader          mDownloader;
    private MeshOtaDownloader        mMeshDownloader;
    private UpdateInstaller           mInstaller;
    private UpdateNotificationManager mNotifManager;
    private UpdateScheduler.UpdateCheckReceiver mCheckReceiver;

    /** Last policy result; may be null before first successful policy fetch. */
    private volatile OtaPolicyManager.PolicyResult mLastPolicy;

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
        mDeltaChecker   = new DeltaChecker();
        mPolicyManager  = new OtaPolicyManager();
        mTelemetry      = new UpdateTelemetry();
        mCommandProcessor = new RemoteCommandProcessor(getContext(),
                new RemoteCommandProcessor.CommandCallback() {
                    @Override public void onForceUpdate() {
                        mHandler.post(CircleUpdateService.this::runCheck);
                    }
                    @Override public void onChangeChannel(String newChannel) {
                        mBinder.setChannel(newChannel);
                    }
                });
        mMaintenanceChecker = new MaintenanceWindowChecker();
        mBootVerifier       = new BootVerifier(getContext());
        mDeviceEnrollment   = new DeviceEnrollment();
        mCrashReporter      = new CrashReporter();
        mDownloader     = new UpdateDownloader(getContext());
        mMeshDownloader = new MeshOtaDownloader(getContext());
        mInstaller      = new UpdateInstaller(getContext());
        mNotifManager   = new UpdateNotificationManager(getContext());

        // Log A/B slot state at startup
        AbSlotManager.logSlotState();

        // Detect and clear any stuck update from a previous run
        String stuck = AbSlotManager.checkForStuckUpdate();
        if (stuck != null) {
            Log.w(TAG, "Previous update to v" + stuck + " appears stuck — clearing record");
            AbSlotManager.clearUpdateRecord();
        }

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

        // Phase 8: run boot verification in background (non-blocking)
        final String bootChannel = (mChannelOverride != null)
                ? mChannelOverride
                : SystemProperties.get("ro.circleos.channel", "stable");
        mHandler.post(() -> mBootVerifier.verifyAndReport(bootChannel));

        // Phase 9: install crash/ANR reporter (synchronous, installs handler on calling thread)
        mCrashReporter.install(bootChannel);
        // Phase 9: enrol / refresh device in fleet registry (network call — run in background)
        mHandler.post(() -> mDeviceEnrollment.enrol(bootChannel));

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

        // Report CHECKING state to telemetry
        final String channel = (mChannelOverride != null)
                ? mChannelOverride
                : SystemProperties.get("ro.circleos.channel", "stable");
        mTelemetry.report(channel, Build.VERSION.RELEASE, UpdateState.name(UpdateState.CHECKING));

        // Fetch and apply central policy (min_version, force_update_by, feature flags)
        mLastPolicy = mPolicyManager.fetchAndApply(channel);
        Log.i(TAG, "Policy result: " + mLastPolicy);

        // Phase 7: process any pending remote commands before the update check
        mCommandProcessor.processPendingCommands(channel);

        // Phase 8: refresh maintenance window
        mMaintenanceChecker.refresh(channel);

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

        final String channel = (mChannelOverride != null)
                ? mChannelOverride
                : SystemProperties.get("ro.circleos.channel", "stable");
        final String currentVersion = Build.VERSION.RELEASE;

        mHandler.post(() -> {
            File downloaded = null;

            // ── Check for delta package (smaller download) ─────────────────────
            DeltaChecker.DeltaInfo delta =
                    mDeltaChecker.checkDelta(currentVersion, info.version, channel);

            if (delta != null) {
                Log.i(TAG, "Delta available: " + delta);

                // Priority 1: delta via mesh
                if (isMeshAvailable()) {
                    Log.i(TAG, "Trying delta via mesh");
                    try {
                        downloaded = mMeshDownloader.downloadDelta(
                                delta.fromVersion, delta.toVersion, channel,
                                percent -> {
                                    mDownloadProgress = percent;
                                    mNotifManager.showDownloading(percent);
                                });
                        Log.i(TAG, "Mesh delta delivery succeeded");
                    } catch (Exception e) {
                        Log.w(TAG, "Mesh delta failed: " + e.getMessage());
                        downloaded = null;
                    }
                }

                // Priority 2: delta via CDN (direct download via DownloadManager)
                if (downloaded == null) {
                    Log.i(TAG, "Trying delta via CDN: " + delta.deltaUrl);
                    try {
                        downloaded = mDownloader.download(
                                delta.deltaUrl, info.version + "-delta",
                                percent -> {
                                    mDownloadProgress = percent;
                                    mNotifManager.showDownloading(percent);
                                });
                        Log.i(TAG, "CDN delta download succeeded");
                    } catch (Exception e) {
                        Log.w(TAG, "CDN delta failed: " + e.getMessage()
                                + " — will try full package");
                        downloaded = null;
                    }
                }
            }

            // ── Priority 3: full package via mesh ─────────────────────────────
            if (downloaded == null && isMeshAvailable()) {
                Log.i(TAG, "Trying full OTA via mesh for v" + info.version);
                try {
                    downloaded = mMeshDownloader.download(
                            info.version, channel,
                            percent -> {
                                mDownloadProgress = percent;
                                mNotifManager.showDownloading(percent);
                            });
                    Log.i(TAG, "Mesh full delivery succeeded");
                } catch (Exception e) {
                    Log.w(TAG, "Mesh full delivery failed: " + e.getMessage());
                    downloaded = null;
                }
            }

            // ── Priority 4: full package via CDN (DownloadManager) ────────────
            if (downloaded == null) {
                Log.i(TAG, "Using direct CDN download for v" + info.version);
                try {
                    downloaded = mDownloader.download(
                            info.manifestUrl, info.version,
                            percent -> {
                                mDownloadProgress = percent;
                                mNotifManager.showDownloading(percent);
                            });
                } catch (Exception e) {
                    Log.e(TAG, "All download strategies failed", e);
                    mDownloadProgress = -1;
                    setState(UpdateState.FAILED);
                    String errMsg = e.getMessage() != null ? e.getMessage() : "Download error";
                    mNotifManager.showFailed(errMsg);
                    // Report failure with error detail
                    final String failChannel = (mChannelOverride != null)
                            ? mChannelOverride
                            : SystemProperties.get("ro.circleos.channel", "stable");
                    mTelemetry.report(failChannel, Build.VERSION.RELEASE,
                            UpdateState.name(UpdateState.FAILED), errMsg);
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

        // Phase 8: enforce maintenance window
        if (!mMaintenanceChecker.isInstallAllowed()) {
            Log.i(TAG, "Outside maintenance window — deferring install");
            mNotifManager.showReadyToInstall(mAvailableVersion); // keep notification visible
            return;
        }

        setState(UpdateState.INSTALLING);
        mNotifManager.cancel();
        // Record update start for stuck-update detection on next boot
        AbSlotManager.recordUpdateStart(mAvailableVersion);
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
        // Report state change to telemetry (best-effort, no error propagation)
        if (mTelemetry != null) {
            final String ch = (mChannelOverride != null)
                    ? mChannelOverride
                    : SystemProperties.get("ro.circleos.channel", "stable");
            mTelemetry.report(ch, Build.VERSION.RELEASE, UpdateState.name(newState));
        }
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
