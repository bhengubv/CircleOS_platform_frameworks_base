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

import za.co.circleos.personality.IBundleCallback;
import za.co.circleos.personality.ICirclePersonalityManager;
import za.co.circleos.personality.IPersonalityCallback;
import za.co.circleos.personality.LearningSuggestion;
import za.co.circleos.personality.ManagedModePolicy;
import za.co.circleos.personality.ModeBundle;
import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.personality.SwitchResult;
import za.co.circleos.personality.TriggerRule;

/**
 * System service that manages CircleOS personality modes.
 *
 * Phase 1: mode switching, Tier-1 modes, notification rules, emergency bypass.
 * Phase 2: auto-switch triggers, conflict resolver, notification broker, state preservation.
 * Phase 3: custom mode CRUD, import/export, per-mode app visibility.
 * Phase 4: Tier-2 lifestyle modes, download-on-activation bundle flow.
 * Phase 5: Managed modes, auto-switch learning, Tier-3 modes, community sharing.
 */
public class CirclePersonalityManagerService extends SystemService {

    private static final String TAG          = "CirclePersonality";
    private static final String SERVICE_NAME = "circle.personality";
    static final int SERVICE_VERSION = 5;

    private HandlerThread            mHandlerThread;
    private Handler                  mHandler;
    private ModeManager              mModeManager;
    // Phase 2
    private ConflictResolver         mConflictResolver;
    private AutoSwitchManager        mAutoSwitchManager;
    private NotificationBroker       mNotifBroker;
    private StatePreservationManager mStatePreservation;
    // Phase 3
    private CustomModeStore          mCustomStore;
    private AppVisibilityManager     mAppVisibility;
    // Phase 4
    private BundleStateStore         mBundleStateStore;
    private BundleDownloadManager    mBundleDownloadManager;
    // Phase 5
    private ManagedModeManager       mManagedModeManager;
    private AutoSwitchLearner        mLearner;
    private CommunityShareManager    mCommunityShare;

    // ---- Lifecycle wrapper --------------------------------------------------

    public static class Lifecycle extends SystemService {
        private CirclePersonalityManagerService mService;
        public Lifecycle(Context context) { super(context); }

        @Override public void onStart() {
            mService = new CirclePersonalityManagerService(getContext());
            mService.onStart();
        }
        @Override public void onBootPhase(int phase) { mService.onBootPhase(phase); }
    }

    public CirclePersonalityManagerService(Context context) { super(context); }

    // ---- SystemService lifecycle --------------------------------------------

    @Override
    public void onStart() {
        mHandlerThread = new HandlerThread("CirclePersonality");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        // Phase 2
        mConflictResolver  = new ConflictResolver();
        mNotifBroker       = new NotificationBroker(getContext());
        mStatePreservation = new StatePreservationManager(getContext());
        mAutoSwitchManager = new AutoSwitchManager();

        // Phase 3
        mCustomStore   = new CustomModeStore();
        mCustomStore.init();
        mAppVisibility = new AppVisibilityManager(getContext(), mCustomStore);

        // Phase 4
        mBundleStateStore      = new BundleStateStore();
        mBundleDownloadManager = new BundleDownloadManager(mBundleStateStore);

        // Phase 5
        mManagedModeManager = new ManagedModeManager();
        mLearner            = new AutoSwitchLearner();
        mCommunityShare     = new CommunityShareManager();

        // Core manager — inject all components
        mModeManager = new ModeManager(getContext());
        mModeManager.setPhase2Components(mNotifBroker, mStatePreservation);
        mModeManager.setPhase3Components(mCustomStore, mAppVisibility);
        mModeManager.setPhase4Components(mBundleDownloadManager);
        mModeManager.setPhase5Components(mManagedModeManager, mLearner, mCommunityShare);

        publishBinderService(SERVICE_NAME, mBinder);
        Log.i(TAG, "CirclePersonalityManagerService started (v" + SERVICE_VERSION + ")");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            mHandler.post(() -> {
                mModeManager.init();
                mAutoSwitchManager.setLearner(mLearner); // Phase 5
                mAutoSwitchManager.init(getContext(), mModeManager, mConflictResolver, mHandler);
                Log.i(TAG, "Boot complete — mode: " + mModeManager.getActiveModeId());
            });
        }
    }

    // ---- Binder implementation ----------------------------------------------

    private final ICirclePersonalityManager.Stub mBinder =
            new ICirclePersonalityManager.Stub() {

        // Phase 1 ----

        @Override public PersonalityMode getActiveMode()       { return mModeManager.getActiveMode(); }
        @Override public List<PersonalityMode> getAvailableModes() { return mModeManager.getAvailableModes(); }
        @Override public String getActiveModeId()              { return mModeManager.getActiveModeId(); }
        @Override public boolean isModeActive(String id)       { return mModeManager.isModeActive(id); }
        @Override public int getServiceVersion()               { return SERVICE_VERSION; }

        @Override
        public SwitchResult activateMode(String modeId) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.activateMode(modeId));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public SwitchResult activatePreviousMode() {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.activatePreviousMode());
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override public void registerCallback(IPersonalityCallback cb)   { mModeManager.mCallbacks.register(cb); }
        @Override public void unregisterCallback(IPersonalityCallback cb) { mModeManager.mCallbacks.unregister(cb); }
        @Override public void triggerEmergencyBypass()  { mHandler.post(mModeManager::triggerEmergencyBypass); }
        @Override public void clearEmergencyBypass()    { mHandler.post(mModeManager::clearEmergencyBypass); }
        @Override public boolean isEmergencyBypassActive() { return mModeManager.isEmergencyBypassActive(); }

        // Phase 2 ----

        @Override public void addTriggerRule(TriggerRule rule)    { if (rule != null) mHandler.post(() -> mAutoSwitchManager.addRule(rule)); }
        @Override public void removeTriggerRule(String ruleId)    { if (ruleId != null) mHandler.post(() -> mAutoSwitchManager.removeRule(ruleId)); }
        @Override public List<TriggerRule> getTriggerRules()      { return mAutoSwitchManager.getRules(); }
        @Override public void setAutoSwitchEnabled(boolean en)    { mHandler.post(() -> mAutoSwitchManager.setEnabled(en)); }
        @Override public boolean isAutoSwitchEnabled()            { return mAutoSwitchManager.isEnabled(); }
        @Override public void dismissBrokerNotifications()        { mNotifBroker.dismissBrokerNotifications(); }

        // Phase 3 ----

        @Override
        public SwitchResult createCustomMode(PersonalityMode mode) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.createCustomMode(mode));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public SwitchResult updateMode(PersonalityMode mode) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.updateMode(mode));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public SwitchResult deleteMode(String modeId) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.deleteMode(modeId));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public SwitchResult cloneMode(String sourceId, String newId, String newName) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.cloneMode(sourceId, newId, newName));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override public String exportModesJson()                   { return mModeManager.exportModesJson(); }

        @Override
        public SwitchResult importModesJson(String json) {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.importModesJson(json));
            try { Thread.sleep(200); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public void setModeHiddenApps(String modeId, List<String> packages) {
            mHandler.post(() -> mModeManager.setModeHiddenApps(modeId, packages));
        }

        @Override public List<String> getModeHiddenApps(String modeId) {
            return mModeManager.getModeHiddenApps(modeId);
        }

        // Phase 4 ----

        @Override public ModeBundle getBundleInfo(String modeId) {
            return mBundleDownloadManager.getBundleInfo(modeId);
        }

        @Override public List<ModeBundle> getAvailableBundles() {
            return mBundleDownloadManager.getAvailableBundles();
        }

        @Override public void downloadBundle(String modeId, IBundleCallback callback) {
            if (modeId != null) mBundleDownloadManager.downloadBundle(modeId, callback);
        }

        @Override public void cancelBundleDownload(String modeId) {
            if (modeId != null) mBundleDownloadManager.cancelBundleDownload(modeId);
        }

        @Override public boolean isBundleDownloaded(String modeId) {
            return modeId != null && mBundleDownloadManager.isBundleDownloaded(modeId);
        }

        @Override public List<String> getBundleApps(String modeId) {
            if (modeId == null) return new java.util.ArrayList<>();
            return mBundleDownloadManager.getBundleApps(modeId);
        }

        // Phase 5: Managed modes ----

        @Override
        public SwitchResult setManagedModePolicy(ManagedModePolicy policy) {
            if (policy == null) return SwitchResult.fail("Null policy");
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.setManagedModePolicy(policy));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public void clearManagedModePolicy(String modeId) {
            if (modeId != null) mHandler.post(() -> mModeManager.clearManagedModePolicy(modeId));
        }

        @Override
        public ManagedModePolicy getManagedModePolicy(String modeId) {
            return modeId != null ? mModeManager.getManagedModePolicy(modeId) : null;
        }

        @Override
        public SwitchResult activateManagedMode(String modeId, String pin) {
            if (modeId == null) return SwitchResult.fail("Null modeId");
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.activateManagedMode(modeId, pin));
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public boolean isManagedModeActive() {
            return mModeManager.isManagedModeActive();
        }

        // Phase 5: Auto-switch learning ----

        @Override
        public List<LearningSuggestion> getLearningSuggestions() {
            return mModeManager.getLearningSuggestions();
        }

        @Override
        public void acceptLearningSuggestion(String suggestionId) {
            if (suggestionId == null) return;
            // Capture rule before accepting so we can add it as a trigger rule
            List<LearningSuggestion> suggestions = mModeManager.getLearningSuggestions();
            for (LearningSuggestion sug : suggestions) {
                if (suggestionId.equals(sug.id) && sug.suggestedRule != null) {
                    mHandler.post(() -> mAutoSwitchManager.addRule(sug.suggestedRule));
                    break;
                }
            }
            mHandler.post(() -> mModeManager.acceptLearningSuggestion(suggestionId));
        }

        @Override
        public void dismissLearningSuggestion(String suggestionId) {
            if (suggestionId != null) mHandler.post(() -> mModeManager.dismissLearningSuggestion(suggestionId));
        }

        @Override
        public SwitchResult undoLastSwitch() {
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.undoLastSwitch());
            try { Thread.sleep(50); } catch (InterruptedException ignored) {}
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        // Phase 5: Community sharing ----

        @Override
        public String getModeShareUrl(String modeId) {
            return modeId != null ? mModeManager.getModeShareUrl(modeId) : null;
        }

        @Override
        public SwitchResult importModeFromUrl(String url) {
            if (url == null) return SwitchResult.fail("Null URL");
            final SwitchResult[] r = new SwitchResult[1];
            mHandler.post(() -> r[0] = mModeManager.importModeFromUrl(url));
            try { Thread.sleep(5000); } catch (InterruptedException ignored) {} // network call
            return r[0] != null ? r[0] : SwitchResult.fail("Timeout");
        }

        @Override
        public List<PersonalityMode> fetchCommunityModes() {
            return mModeManager.fetchCommunityModes();
        }
    };
}
