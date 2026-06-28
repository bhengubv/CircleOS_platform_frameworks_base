/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.camera;

import android.content.Context;
import android.hardware.camera2.CameraManager;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.camera.ICircleCameraPrivacyService;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Circle OS Camera Privacy Service.
 *
 * <p>Drives the camera-use indicator (the Circle equivalent of iOS's
 * green dot) by listening to {@link CameraManager.AvailabilityCallback}.
 * When a camera transitions to "unavailable" while not in a closed
 * lifecycle state, some process has it open -- we surface that to the
 * status bar through {@link #isAnyCameraInUse()}.
 *
 * <p>The implementation runs on a dedicated worker thread so the
 * callback never blocks the camera HAL's notify path.
 *
 * <p>Per-package attribution is best-effort. CameraService does not
 * expose the caller package on the AvailabilityCallback surface; we
 * track the last-observed transition timestamp and let UI layers
 * cross-reference with foreground app via UsageStatsManager. That
 * works well enough for the dashboard line "Camera last used by X 30s
 * ago" without requiring privileged hooks deeper into CameraService.
 */
public final class CircleCameraPrivacyService extends SystemService {

    private static final String TAG = "CircleCameraPrivacy";

    public static final String SERVICE_NAME = "circle.camera_privacy";

    private final Context mContext;
    private final CameraBinder mBinder = new CameraBinder();
    private final HandlerThread mWorker = new HandlerThread("CircleCameraPrivacy");
    private Handler mHandler;
    private CameraManager mCameraManager;

    /** Camera IDs currently reported as unavailable -> someone has them open. */
    private final Set<String> mInUse =
            Collections.synchronizedSet(new HashSet<String>());

    private final AtomicInteger mSessionCount = new AtomicInteger(0);
    private final AtomicLong    mLastInUseMs  = new AtomicLong(0L);

    public CircleCameraPrivacyService(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);

        mWorker.start();
        mHandler = new Handler(mWorker.getLooper());
        mHandler.post(this::attachCameraCallback);
    }

    private void attachCameraCallback() {
        mCameraManager = mContext.getSystemService(CameraManager.class);
        if (mCameraManager == null) {
            Slog.w(TAG, "CameraManager unavailable -- camera indicator disabled");
            return;
        }
        try {
            mCameraManager.registerAvailabilityCallback(
                    new CameraManager.AvailabilityCallback() {
                        @Override
                        public void onCameraAvailable(String cameraId) {
                            if (mInUse.remove(cameraId)) {
                                // in-use -> available transition. Bump
                                // session count once per closed session.
                                mSessionCount.incrementAndGet();
                            }
                        }

                        @Override
                        public void onCameraUnavailable(String cameraId) {
                            mInUse.add(cameraId);
                            mLastInUseMs.set(System.currentTimeMillis());
                        }
                    }, mHandler);
            Slog.i(TAG, "Registered camera availability callback");
        } catch (Throwable t) {
            Slog.w(TAG, "registerAvailabilityCallback failed", t);
        }
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class CameraBinder extends ICircleCameraPrivacyService.Stub {

        @Override
        public boolean isAnyCameraInUse() {
            enforceQuery();
            return !mInUse.isEmpty();
        }

        @Override
        public String getMostRecentCameraUser(long sinceMs) {
            enforceQuery();
            // CameraService doesn't expose the caller package on the
            // AvailabilityCallback. Returning the last-known in-use
            // timestamp lets UI cross-reference foreground app via
            // CircleAnalyticsService.getTopForegroundPackages without
            // us peeking into camera internals.
            final long ts = mLastInUseMs.get();
            return (ts >= sinceMs) ? Long.toString(ts) : "";
        }

        @Override
        public int getCameraSessionCount() {
            enforceQuery();
            return mSessionCount.get();
        }
    }

    private void enforceQuery() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // Allow system + any platform-signed Circle app; otherwise require the permission.
        if (getContext().getPackageManager().checkSignatures(
                android.os.Binder.getCallingUid(), android.os.Process.SYSTEM_UID)
                        == android.content.pm.PackageManager.SIGNATURE_MATCH) return;
        getContext().enforceCallingOrSelfPermission("za.co.circleos.permission.QUERY_PRIVACY", "circle-api");
    }
}
