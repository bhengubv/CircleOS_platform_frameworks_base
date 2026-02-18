/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.circleos.AppPrivacyPolicy;
import android.circleos.ICirclePermissionService;
import android.circleos.ICirclePrivacyManager;
import android.content.ComponentName;
import android.content.Context;
import android.hardware.SensorPrivacyManager;
import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Slog;

import com.android.server.SystemService;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * System service managing Circle OS custom permissions.
 *
 * Registered in SystemServer as "circle.permission".
 *
 * Manages:
 *   com.circleos.permission.NETWORK      — delegated to NetworkPermissionEnforcer
 *   com.circleos.permission.ACCELEROMETER
 *   com.circleos.permission.GYROSCOPE
 *   com.circleos.permission.BAROMETER
 *   com.circleos.permission.MAGNETOMETER — delegated to SensorPrivacyManager (AOSP)
 *
 * Schedules an auto-revoke JobScheduler job every 7 days.
 */
public class CirclePermissionService extends SystemService {

    private static final String TAG            = "CirclePermissionService";
    public  static final String SERVICE_NAME   = "circle.permission";
    private static final int    AUTOREVOKE_JOB = 0xC1C1E001; // unique Circle job ID

    private static final long AUTOREVOKE_INTERVAL_MS = TimeUnit.DAYS.toMillis(7);

    private final NetworkPermissionEnforcer mNetworkEnforcer;
    private final PrivacyLogger             mLogger;
    private       SensorPrivacyManager      mSensorPrivacyManager;

    public CirclePermissionService(Context context,
                                   NetworkPermissionEnforcer networkEnforcer,
                                   PrivacyLogger logger) {
        super(context);
        mNetworkEnforcer = networkEnforcer;
        mLogger          = logger;
    }

    // ---- SystemService lifecycle ----

    /**
     * Lifecycle wrapper required by SystemServiceManager.
     * Constructed via reflection; dependencies are injected after boot.
     */
    public static class Lifecycle extends SystemService {
        private CirclePermissionService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            // Dependencies will be set by CirclePrivacyManagerService.onStart()
            // before this service binds. For standalone startup, create defaults.
            PrivacyLogger logger = new PrivacyLogger(getContext());
            NetworkPermissionEnforcer enforcer =
                    new NetworkPermissionEnforcer(getContext(), logger);
            mService = new CirclePermissionService(getContext(), enforcer, logger);
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            if (mService != null) mService.onBootPhase(phase);
        }
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinder);
        Slog.i(TAG, "CirclePermissionService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            // Re-apply all persisted network grants after full boot.
            mNetworkEnforcer.reapplyAllGrants();
            // Acquire SensorPrivacyManager — available after boot completed.
            mSensorPrivacyManager = getContext().getSystemService(SensorPrivacyManager.class);
            scheduleAutoRevokeJob();
            Slog.i(TAG, "Boot phase BOOT_COMPLETED: grants re-applied, auto-revoke scheduled");
        }
    }

    // ---- Binder implementation ----

    private final IBinder mBinder = new ICirclePermissionService.Stub() {

        @Override
        public boolean checkNetworkPermission(String packageName) {
            enforceManagePrivacyPermission();
            return mNetworkEnforcer.hasNetworkPermission(packageName);
        }

        @Override
        public void grantNetworkPermission(String packageName) {
            enforceManagePrivacyPermission();
            mNetworkEnforcer.grantNetworkPermission(packageName);
        }

        @Override
        public void revokeNetworkPermission(String packageName) {
            enforceManagePrivacyPermission();
            mNetworkEnforcer.revokeNetworkPermission(packageName);
        }

        @Override
        public boolean checkSensorPermission(String packageName, String sensorType) {
            enforceManagePrivacyPermission();

            // 1. Hardware sensor privacy kill-switch (user toggled sensors off globally)
            if (mSensorPrivacyManager != null
                    && mSensorPrivacyManager.isSensorPrivacyEnabled()) {
                Slog.d(TAG, "checkSensorPermission: hardware kill-switch active → deny");
                return false;
            }

            // 2. Per-app policy from CirclePrivacyManagerService
            try {
                IBinder binder = ServiceManager.checkService(
                        CirclePrivacyManagerService.SERVICE_NAME);
                if (binder != null) {
                    ICirclePrivacyManager mgr = ICirclePrivacyManager.Stub.asInterface(binder);
                    AppPrivacyPolicy policy = mgr.getPolicy(packageName);
                    if (policy != null && policy.allowedSensors != null) {
                        boolean allowed = policy.allowedSensors.contains(sensorType);
                        Slog.d(TAG, "checkSensorPermission: " + packageName + "/" + sensorType
                                + " → " + (allowed ? "allow" : "deny") + " (policy)");
                        return allowed;
                    }
                }
            } catch (RemoteException | SecurityException e) {
                Slog.w(TAG, "checkSensorPermission: policy lookup failed: " + e.getMessage());
            }

            Slog.d(TAG, "checkSensorPermission: " + packageName + "/" + sensorType
                    + " → deny (no policy)");
            return false;
        }

        @Override
        public List<String> getPackagesWithNetworkPermission() {
            enforceManagePrivacyPermission();
            return mNetworkEnforcer.getGrantedPackages();
        }
    };

    // ---- Private ----

    /** Requires the caller to hold MANAGE_APP_OPS_MODES or MANAGE_PRIVACY. */
    private void enforceManagePrivacyPermission() {
        getContext().enforceCallingOrSelfPermission(
                "com.circleos.permission.MANAGE_PRIVACY",
                "Requires com.circleos.permission.MANAGE_PRIVACY");
    }

    /**
     * Schedules the auto-revoke job to run every 7 days (periodic).
     * Uses JobScheduler to survive reboots.
     */
    private void scheduleAutoRevokeJob() {
        JobScheduler js = getContext().getSystemService(JobScheduler.class);
        if (js == null) {
            Slog.w(TAG, "JobScheduler not available; auto-revoke not scheduled");
            return;
        }
        // ComponentName points to a service in CircleSettings APK (Phase 3).
        ComponentName component = new ComponentName(
                "com.circleos.settings",
                "com.circleos.settings.AutoRevokeJobService");

        JobInfo job = new JobInfo.Builder(AUTOREVOKE_JOB, component)
                .setRequiresCharging(false)
                .setRequiresDeviceIdle(true)
                .setPeriodic(AUTOREVOKE_INTERVAL_MS)
                .setPersisted(true)
                .build();

        int result = js.schedule(job);
        if (result == JobScheduler.RESULT_SUCCESS) {
            Slog.i(TAG, "Auto-revoke job scheduled (every 7 days)");
        } else {
            Slog.w(TAG, "Auto-revoke job scheduling failed: " + result);
        }
    }
}
