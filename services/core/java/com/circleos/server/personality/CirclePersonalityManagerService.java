/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.android.server.SystemService;

import java.util.List;

import za.co.circleos.personality.ICirclePersonalityManager;
import za.co.circleos.personality.IPersonalityCallback;
import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.personality.SwitchResult;

/**
 * System service that manages CircleOS personality modes (profiles).
 *
 * <p>Registered as {@code "circle.personality"} in SystemServer. Apps acquire
 * the Binder via {@code ServiceManager.getService("circle.personality")} or the
 * {@code CirclePersonalityClient} helper library (Phase 4).</p>
 *
 * <p>Phase 1 delivers: mode switching, Tier-1 mode definitions, basic
 * notification rules, emergency bypass, and a QS tile hook.</p>
 */
public class CirclePersonalityManagerService extends SystemService {

    private static final String TAG         = "CirclePersonality";
    private static final String SERVICE_NAME = "circle.personality";
    static final int SERVICE_VERSION = 1;

    private HandlerThread mHandlerThread;
    private Handler       mHandler;
    private ModeManager   mModeManager;

    // -------------------------------------------------------------------------
    // Lifecycle wrapper — mirrors all existing Circle services
    // -------------------------------------------------------------------------

    public static class Lifecycle extends SystemService {
        private CirclePersonalityManagerService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new CirclePersonalityManagerService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public CirclePersonalityManagerService(Context context) {
        super(context);
    }

    // -------------------------------------------------------------------------
    // SystemService lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void onStart() {
        mHandlerThread = new HandlerThread("CirclePersonality");
        mHandlerThread.start();
        mHandler     = new Handler(mHandlerThread.getLooper());
        mModeManager = new ModeManager(getContext());

        publishBinderService(SERVICE_NAME, mBinder);
        Log.i(TAG, "CirclePersonalityManagerService started (v" + SERVICE_VERSION + ")");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mHandler.post(() -> {
                mModeManager.init();
                Log.i(TAG, "Boot complete — mode restored: "
                        + mModeManager.getActiveModeId());
            });
        }
    }

    // -------------------------------------------------------------------------
    // Binder implementation
    // -------------------------------------------------------------------------

    private final ICirclePersonalityManager.Stub mBinder =
            new ICirclePersonalityManager.Stub() {

        @Override
        public PersonalityMode getActiveMode() {
            return mModeManager.getActiveMode();
        }

        @Override
        public List<PersonalityMode> getAvailableModes() {
            return mModeManager.getAvailableModes();
        }

        @Override
        public String getActiveModeId() {
            return mModeManager.getActiveModeId();
        }

        @Override
        public boolean isModeActive(String modeId) {
            return mModeManager.isModeActive(modeId);
        }

        @Override
        public int getServiceVersion() {
            return SERVICE_VERSION;
        }

        @Override
        public SwitchResult activateMode(String modeId) {
            final SwitchResult[] result = new SwitchResult[1];
            mHandler.post(() -> result[0] = mModeManager.activateMode(modeId));
            // Brief wait for synchronous-ish response on the handler
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return result[0] != null ? result[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public SwitchResult activatePreviousMode() {
            final SwitchResult[] result = new SwitchResult[1];
            mHandler.post(() -> result[0] = mModeManager.activatePreviousMode());
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return result[0] != null ? result[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public void registerCallback(IPersonalityCallback callback) {
            mModeManager.mCallbacks.register(callback);
        }

        @Override
        public void unregisterCallback(IPersonalityCallback callback) {
            mModeManager.mCallbacks.unregister(callback);
        }

        @Override
        public void triggerEmergencyBypass() {
            mHandler.post(mModeManager::triggerEmergencyBypass);
        }

        @Override
        public void clearEmergencyBypass() {
            mHandler.post(mModeManager::clearEmergencyBypass);
        }

        @Override
        public boolean isEmergencyBypassActive() {
            return mModeManager.isEmergencyBypassActive();
        }
    };
}
