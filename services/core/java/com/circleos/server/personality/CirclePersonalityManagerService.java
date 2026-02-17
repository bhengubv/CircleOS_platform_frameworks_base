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
import za.co.circleos.personality.TriggerRule;

/**
 * System service that manages CircleOS personality modes (profiles).
 *
 * <p>Registered as {@code "circle.personality"} in SystemServer. Apps acquire
 * the Binder via {@code ServiceManager.getService("circle.personality")}.</p>
 *
 * <p>Phase 1: mode switching, Tier-1 mode definitions, notification rules,
 * emergency bypass, QS tile hook.</p>
 * <p>Phase 2: auto-switch triggers, conflict resolver, notification broker,
 * state preservation.</p>
 */
public class CirclePersonalityManagerService extends SystemService {

    private static final String TAG          = "CirclePersonality";
    private static final String SERVICE_NAME = "circle.personality";
    static final int SERVICE_VERSION = 2;

    private HandlerThread            mHandlerThread;
    private Handler                  mHandler;
    private ModeManager              mModeManager;
    private ConflictResolver         mConflictResolver;
    private AutoSwitchManager        mAutoSwitchManager;
    private NotificationBroker       mNotifBroker;
    private StatePreservationManager mStatePreservation;

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
        mHandler = new Handler(mHandlerThread.getLooper());

        // Phase 2 components
        mConflictResolver  = new ConflictResolver();
        mNotifBroker       = new NotificationBroker(getContext());
        mStatePreservation = new StatePreservationManager(getContext());
        mAutoSwitchManager = new AutoSwitchManager();

        // Core manager
        mModeManager = new ModeManager(getContext());
        mModeManager.setPhase2Components(mNotifBroker, mStatePreservation);

        publishBinderService(SERVICE_NAME, mBinder);
        Log.i(TAG, "CirclePersonalityManagerService started (v" + SERVICE_VERSION + ")");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mHandler.post(() -> {
                mModeManager.init();
                mAutoSwitchManager.init(getContext(), mModeManager,
                        mConflictResolver, mHandler);
                Log.i(TAG, "Boot complete — mode: " + mModeManager.getActiveModeId()
                        + ", auto-switch enabled: " + mAutoSwitchManager.isEnabled());
            });
        }
    }

    // -------------------------------------------------------------------------
    // Binder implementation
    // -------------------------------------------------------------------------

    private final ICirclePersonalityManager.Stub mBinder =
            new ICirclePersonalityManager.Stub() {

        // ---- Phase 1 --------------------------------------------------------

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

        // ---- Phase 2: auto-switch -------------------------------------------

        @Override
        public void addTriggerRule(TriggerRule rule) {
            if (rule == null) return;
            mHandler.post(() -> mAutoSwitchManager.addRule(rule));
        }

        @Override
        public void removeTriggerRule(String ruleId) {
            if (ruleId == null) return;
            mHandler.post(() -> mAutoSwitchManager.removeRule(ruleId));
        }

        @Override
        public List<TriggerRule> getTriggerRules() {
            return mAutoSwitchManager.getRules();
        }

        @Override
        public void setAutoSwitchEnabled(boolean enabled) {
            mHandler.post(() -> mAutoSwitchManager.setEnabled(enabled));
        }

        @Override
        public boolean isAutoSwitchEnabled() {
            return mAutoSwitchManager.isEnabled();
        }

        // ---- Phase 2: notification broker -----------------------------------

        @Override
        public void dismissBrokerNotifications() {
            mNotifBroker.dismissBrokerNotifications();
        }
    };
}
