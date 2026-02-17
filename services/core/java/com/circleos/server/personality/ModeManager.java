/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.content.Context;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.util.ArrayMap;
import android.util.Log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import za.co.circleos.personality.IPersonalityCallback;
import za.co.circleos.personality.ModeConfig;
import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.personality.SwitchResult;

/**
 * Core mode management logic: atomic switching, mode stack, emergency bypass,
 * callback dispatch. Runs on the CirclePersonality HandlerThread.
 */
class ModeManager {

    private static final String TAG = "CirclePersonality";

    /** Maximum depth of the mode history stack. */
    private static final int MAX_STACK_DEPTH = 10;

    private final Context                     mContext;
    private final ModeStateStore              mStateStore;
    private final NotificationRulesEngine     mNotifEngine;
    private final Map<String, PersonalityMode> mModes = new ArrayMap<>();

    private String              mActiveModeId;
    private Deque<String>       mModeStack;
    private boolean             mEmergencyBypassActive = false;

    final RemoteCallbackList<IPersonalityCallback> mCallbacks =
            new RemoteCallbackList<>();

    ModeManager(Context context) {
        mContext     = context;
        mStateStore  = new ModeStateStore(context);
        mNotifEngine = new NotificationRulesEngine(context);
    }

    /** Called once on boot to restore persisted state. */
    void init() {
        for (PersonalityMode mode : Tier1Modes.all()) {
            mModes.put(mode.id, mode);
        }

        mModeStack    = mStateStore.loadModeStack();
        mActiveModeId = mStateStore.loadActiveMode();

        if (!mModes.containsKey(mActiveModeId)) {
            mActiveModeId = ModeStateStore.DEFAULT_MODE;
        }

        Log.i(TAG, "Restored mode: " + mActiveModeId);
        applyCurrentModeConfig();
    }

    PersonalityMode getActiveMode() {
        return mModes.get(mActiveModeId);
    }

    List<PersonalityMode> getAvailableModes() {
        return new ArrayList<>(mModes.values());
    }

    String getActiveModeId() {
        return mActiveModeId;
    }

    boolean isModeActive(String modeId) {
        return mActiveModeId != null && mActiveModeId.equals(modeId);
    }

    SwitchResult activateMode(String modeId) {
        if (!mModes.containsKey(modeId)) {
            return SwitchResult.fail("Unknown mode: " + modeId);
        }

        String previous = mActiveModeId;

        // Push current onto stack (cap depth)
        if (previous != null) {
            mModeStack.addLast(previous);
            while (mModeStack.size() > MAX_STACK_DEPTH) {
                mModeStack.removeFirst();
            }
        }

        mActiveModeId = modeId;
        mStateStore.saveActiveMode(modeId);
        mStateStore.saveModeStack(mModeStack);

        applyCurrentModeConfig();
        dispatchModeChanged(mModes.get(previous), mModes.get(modeId));

        Log.i(TAG, "Mode switched: " + previous + " -> " + modeId);
        return SwitchResult.ok(previous, modeId);
    }

    SwitchResult activatePreviousMode() {
        if (mModeStack.isEmpty()) {
            return SwitchResult.fail("No previous mode");
        }

        String previous = mActiveModeId;
        String target   = mModeStack.removeLast();

        mActiveModeId = target;
        mStateStore.saveActiveMode(target);
        mStateStore.saveModeStack(mModeStack);

        applyCurrentModeConfig();
        dispatchModeChanged(mModes.get(previous), mModes.get(target));

        Log.i(TAG, "Restored previous mode: " + previous + " -> " + target);
        return SwitchResult.ok(previous, target);
    }

    void triggerEmergencyBypass() {
        if (!mEmergencyBypassActive) {
            mEmergencyBypassActive = true;
            // Restore full notifications so starred contacts can reach user
            mNotifEngine.reset();
            dispatchEmergencyBypassChanged(true);
            Log.i(TAG, "Emergency bypass activated");
        }
    }

    void clearEmergencyBypass() {
        if (mEmergencyBypassActive) {
            mEmergencyBypassActive = false;
            applyCurrentModeConfig();
            dispatchEmergencyBypassChanged(false);
            Log.i(TAG, "Emergency bypass cleared");
        }
    }

    boolean isEmergencyBypassActive() {
        return mEmergencyBypassActive;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void applyCurrentModeConfig() {
        PersonalityMode mode = mModes.get(mActiveModeId);
        if (mode == null || mode.config == null) return;

        if (!mEmergencyBypassActive) {
            mNotifEngine.applyModeRules(mode.config);
        }
    }

    private void dispatchModeChanged(PersonalityMode prev, PersonalityMode next) {
        int n = mCallbacks.beginBroadcast();
        for (int i = 0; i < n; i++) {
            try {
                mCallbacks.getBroadcastItem(i).onModeChanged(prev, next);
            } catch (RemoteException ignored) {}
        }
        mCallbacks.finishBroadcast();
    }

    private void dispatchEmergencyBypassChanged(boolean active) {
        int n = mCallbacks.beginBroadcast();
        for (int i = 0; i < n; i++) {
            try {
                mCallbacks.getBroadcastItem(i).onEmergencyBypassChanged(active);
            } catch (RemoteException ignored) {}
        }
        mCallbacks.finishBroadcast();
    }
}
