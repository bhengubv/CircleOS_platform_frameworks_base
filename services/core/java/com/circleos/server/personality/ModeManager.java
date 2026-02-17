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
 * Core mode management: switching, stack, emergency bypass, callbacks,
 * Phase 2 (notification broker, state preservation),
 * Phase 3 (custom modes, import/export, app visibility),
 * Phase 4 (Tier-2 bundle gating).
 */
class ModeManager {

    private static final String TAG           = "CirclePersonality";
    private static final int    MAX_STACK_DEPTH = 10;

    private final Context                      mContext;
    private final ModeStateStore               mStateStore;
    private final NotificationRulesEngine      mNotifEngine;
    private final Map<String, PersonalityMode> mModes = new ArrayMap<>();

    // Phase 2
    private NotificationBroker       mNotifBroker;
    private StatePreservationManager mStatePreservation;

    // Phase 3
    private CustomModeStore     mCustomStore;
    private AppVisibilityManager mAppVisibility;

    // Phase 4
    private BundleDownloadManager mBundleDownloadManager;

    private String        mActiveModeId;
    private Deque<String> mModeStack;
    private boolean       mEmergencyBypassActive = false;

    final RemoteCallbackList<IPersonalityCallback> mCallbacks = new RemoteCallbackList<>();

    ModeManager(Context context) {
        mContext     = context;
        mStateStore  = new ModeStateStore(context);
        mNotifEngine = new NotificationRulesEngine(context);
    }

    void setPhase2Components(NotificationBroker broker, StatePreservationManager sp) {
        mNotifBroker       = broker;
        mStatePreservation = sp;
    }

    void setPhase3Components(CustomModeStore store, AppVisibilityManager appVis) {
        mCustomStore   = store;
        mAppVisibility = appVis;
    }

    void setPhase4Components(BundleDownloadManager bundleMgr) {
        mBundleDownloadManager = bundleMgr;
    }

    void init() {
        // Load Tier-1 built-in modes
        for (PersonalityMode mode : Tier1Modes.all()) {
            mModes.put(mode.id, mode);
        }

        // Load Tier-2 lifestyle modes (Phase 4) — gated by bundle download
        for (PersonalityMode mode : Tier2Modes.allModes()) {
            mModes.put(mode.id, mode);
        }

        // Load persisted custom modes (Phase 3)
        if (mCustomStore != null) {
            for (PersonalityMode m : mCustomStore.loadCustomModes()) {
                mModes.put(m.id, m);
            }
            mAppVisibility.init();
        }

        mModeStack    = mStateStore.loadModeStack();
        mActiveModeId = mStateStore.loadActiveMode();
        if (!mModes.containsKey(mActiveModeId)) mActiveModeId = ModeStateStore.DEFAULT_MODE;

        Log.i(TAG, "Restored mode: " + mActiveModeId + " (" + mModes.size() + " modes)");
        applyCurrentModeConfig();
    }

    // ---- Queries ------------------------------------------------------------

    PersonalityMode getActiveMode()              { return mModes.get(mActiveModeId); }
    List<PersonalityMode> getAvailableModes()    { return new ArrayList<>(mModes.values()); }
    String getActiveModeId()                     { return mActiveModeId; }
    boolean isModeActive(String id)              { return mActiveModeId != null && mActiveModeId.equals(id); }
    boolean isEmergencyBypassActive()            { return mEmergencyBypassActive; }

    // ---- Switching ----------------------------------------------------------

    SwitchResult activateMode(String modeId) {
        if (!mModes.containsKey(modeId)) return SwitchResult.fail("Unknown mode: " + modeId);

        // Phase 4: Tier-2 modes require bundle download before activation
        PersonalityMode requested = mModes.get(modeId);
        if (requested != null && requested.tier == 2
                && mBundleDownloadManager != null
                && !mBundleDownloadManager.isBundleDownloaded(modeId)) {
            Log.i(TAG, "Mode " + modeId + " requires bundle download");
            return SwitchResult.requiresBundle(modeId);
        }

        String previous = mActiveModeId;
        PersonalityMode prevMode = mModes.get(previous);
        PersonalityMode nextMode = mModes.get(modeId);

        if (mStatePreservation != null && previous != null)
            mStatePreservation.captureStateForMode(previous);
        if (mNotifBroker != null && prevMode != null)
            mNotifBroker.onModeDeactivated(prevMode);

        if (previous != null) {
            mModeStack.addLast(previous);
            while (mModeStack.size() > MAX_STACK_DEPTH) mModeStack.removeFirst();
        }
        mActiveModeId = modeId;
        mStateStore.saveActiveMode(modeId);
        mStateStore.saveModeStack(mModeStack);
        applyCurrentModeConfig();

        if (mNotifBroker != null && nextMode != null)  mNotifBroker.onModeActivated(nextMode);
        if (mStatePreservation != null)                mStatePreservation.restoreStateForMode(modeId);
        if (mAppVisibility != null)                    mAppVisibility.applyForMode(modeId);

        dispatchModeChanged(prevMode, nextMode);
        Log.i(TAG, "Mode: " + previous + " -> " + modeId);
        return SwitchResult.ok(previous, modeId);
    }

    SwitchResult activatePreviousMode() {
        if (mModeStack.isEmpty()) return SwitchResult.fail("No previous mode");

        String previous = mActiveModeId;
        String target   = mModeStack.removeLast();
        PersonalityMode prevMode = mModes.get(previous);
        PersonalityMode nextMode = mModes.get(target);

        if (mStatePreservation != null && previous != null)
            mStatePreservation.captureStateForMode(previous);
        if (mNotifBroker != null && prevMode != null) mNotifBroker.onModeDeactivated(prevMode);

        mActiveModeId = target;
        mStateStore.saveActiveMode(target);
        mStateStore.saveModeStack(mModeStack);
        applyCurrentModeConfig();

        if (mNotifBroker != null && nextMode != null)  mNotifBroker.onModeActivated(nextMode);
        if (mStatePreservation != null)                mStatePreservation.restoreStateForMode(target);
        if (mAppVisibility != null)                    mAppVisibility.applyForMode(target);

        dispatchModeChanged(prevMode, nextMode);
        Log.i(TAG, "Previous mode: " + previous + " -> " + target);
        return SwitchResult.ok(previous, target);
    }

    // ---- Emergency bypass ---------------------------------------------------

    void triggerEmergencyBypass() {
        if (!mEmergencyBypassActive) {
            mEmergencyBypassActive = true;
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

    // ---- Phase 3: Custom mode CRUD ------------------------------------------

    SwitchResult createCustomMode(PersonalityMode mode) {
        if (mode == null || mode.id == null || mode.id.isEmpty())
            return SwitchResult.fail("Invalid mode");
        if (mModes.containsKey(mode.id))
            return SwitchResult.fail("Mode id already exists: " + mode.id);
        mode.isCustom = true;
        mModes.put(mode.id, mode);
        persistCustomModes();
        Log.i(TAG, "Created custom mode: " + mode.id);
        return SwitchResult.ok(null, mode.id);
    }

    SwitchResult updateMode(PersonalityMode mode) {
        if (mode == null || mode.id == null) return SwitchResult.fail("Invalid mode");
        PersonalityMode existing = mModes.get(mode.id);
        if (existing == null) return SwitchResult.fail("Mode not found: " + mode.id);
        if (!existing.isCustom)  return SwitchResult.fail("Cannot edit built-in mode");
        mModes.put(mode.id, mode);
        persistCustomModes();
        Log.i(TAG, "Updated mode: " + mode.id);
        return SwitchResult.ok(mode.id, mode.id);
    }

    SwitchResult deleteMode(String modeId) {
        PersonalityMode m = mModes.get(modeId);
        if (m == null)         return SwitchResult.fail("Mode not found: " + modeId);
        if (!m.isCustom)       return SwitchResult.fail("Cannot delete built-in mode");
        if (modeId.equals(mActiveModeId)) activateMode(ModeStateStore.DEFAULT_MODE);
        mModes.remove(modeId);
        persistCustomModes();
        Log.i(TAG, "Deleted mode: " + modeId);
        return SwitchResult.ok(modeId, null);
    }

    SwitchResult cloneMode(String sourceId, String newId, String newName) {
        PersonalityMode src = mModes.get(sourceId);
        if (src == null) return SwitchResult.fail("Source mode not found: " + sourceId);
        if (newId == null || newId.isEmpty()) return SwitchResult.fail("Invalid new id");
        if (mModes.containsKey(newId)) return SwitchResult.fail("Mode id already exists: " + newId);

        PersonalityMode clone = new PersonalityMode();
        clone.id          = newId;
        clone.name        = newName != null ? newName : src.name + " (copy)";
        clone.description = src.description;
        clone.tier        = src.tier;
        clone.isCustom    = true;
        clone.config      = src.config; // shared reference; ModeConfig is Parcelable so safe for reads
        mModes.put(clone.id, clone);
        persistCustomModes();
        Log.i(TAG, "Cloned " + sourceId + " -> " + newId);
        return SwitchResult.ok(sourceId, newId);
    }

    // ---- Phase 3: Import / export -------------------------------------------

    String exportModesJson() {
        return ModeSerializer.encodeExport(new ArrayList<>(mModes.values()));
    }

    SwitchResult importModesJson(String json) {
        try {
            List<PersonalityMode> imported = ModeSerializer.decodeModeList(json);
            if (imported == null || imported.isEmpty())
                return SwitchResult.fail("No valid modes in JSON");
            int count = 0;
            for (PersonalityMode m : imported) {
                if (m.id == null || m.id.isEmpty()) continue;
                // Skip built-in ids
                if (Tier1Modes.all().stream().anyMatch(t -> t.id.equals(m.id))) continue;
                m.isCustom = true;
                mModes.put(m.id, m);
                count++;
            }
            persistCustomModes();
            Log.i(TAG, "Imported " + count + " modes");
            return SwitchResult.ok(null, "imported:" + count);
        } catch (Exception e) {
            Log.e(TAG, "importModesJson failed: " + e.getMessage());
            return SwitchResult.fail("Parse error: " + e.getMessage());
        }
    }

    // ---- Phase 3: App visibility --------------------------------------------

    void setModeHiddenApps(String modeId, List<String> packages) {
        if (mAppVisibility != null) mAppVisibility.setHiddenApps(modeId, packages);
    }

    List<String> getModeHiddenApps(String modeId) {
        if (mAppVisibility == null) return new ArrayList<>();
        return mAppVisibility.getHiddenApps(modeId);
    }

    // ---- Private helpers ----------------------------------------------------

    private void applyCurrentModeConfig() {
        PersonalityMode mode = mModes.get(mActiveModeId);
        if (mode == null || mode.config == null) return;
        if (!mEmergencyBypassActive) mNotifEngine.applyModeRules(mode.config);
    }

    private void persistCustomModes() {
        if (mCustomStore != null) mCustomStore.saveCustomModes(new ArrayList<>(mModes.values()));
    }

    private void dispatchModeChanged(PersonalityMode prev, PersonalityMode next) {
        int n = mCallbacks.beginBroadcast();
        for (int i = 0; i < n; i++) {
            try { mCallbacks.getBroadcastItem(i).onModeChanged(prev, next); }
            catch (RemoteException ignored) {}
        }
        mCallbacks.finishBroadcast();
    }

    private void dispatchEmergencyBypassChanged(boolean active) {
        int n = mCallbacks.beginBroadcast();
        for (int i = 0; i < n; i++) {
            try { mCallbacks.getBroadcastItem(i).onEmergencyBypassChanged(active); }
            catch (RemoteException ignored) {}
        }
        mCallbacks.finishBroadcast();
    }
}
