/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.personality.SwitchResult;
import za.co.circleos.personality.TriggerRule;
import za.co.circleos.personality.AppRule;
import za.co.circleos.personality.IPersonalityCallback;
import za.co.circleos.personality.ModeBundle;
import za.co.circleos.personality.IBundleCallback;
import za.co.circleos.personality.ManagedModePolicy;
import za.co.circleos.personality.LearningSuggestion;

interface ICirclePersonalityManager {
    // Query
    PersonalityMode getActiveMode();
    List<PersonalityMode> getAvailableModes();
    String getActiveModeId();
    boolean isModeActive(String modeId);
    int getServiceVersion();

    // Switching
    SwitchResult activateMode(String modeId);
    SwitchResult activatePreviousMode();

    // Callbacks
    void registerCallback(IPersonalityCallback callback);
    void unregisterCallback(IPersonalityCallback callback);

    // Emergency bypass — starred contacts always reachable, SOS bypasses all modes
    void triggerEmergencyBypass();
    void clearEmergencyBypass();
    boolean isEmergencyBypassActive();

    // Phase 2: Auto-switch intelligence
    void addTriggerRule(in TriggerRule rule);
    void removeTriggerRule(String ruleId);
    List<TriggerRule> getTriggerRules();
    void setAutoSwitchEnabled(boolean enabled);
    boolean isAutoSwitchEnabled();

    // Phase 2: Notification broker
    void dismissBrokerNotifications();

    // Phase 3: Custom mode management
    SwitchResult createCustomMode(in PersonalityMode mode);
    SwitchResult updateMode(in PersonalityMode mode);
    SwitchResult deleteMode(String modeId);
    SwitchResult cloneMode(String sourceModeId, String newModeId, String newName);

    // Phase 3: Import / export
    String exportModesJson();
    SwitchResult importModesJson(String json);

    // Phase 3: Per-mode app visibility
    void setModeHiddenApps(String modeId, in List<String> packageNames);
    List<String> getModeHiddenApps(String modeId);

    // Phase 4: Lifestyle mode bundle management
    ModeBundle getBundleInfo(String modeId);
    List<ModeBundle> getAvailableBundles();
    void downloadBundle(String modeId, IBundleCallback callback);
    void cancelBundleDownload(String modeId);
    boolean isBundleDownloaded(String modeId);
    List<String> getBundleApps(String modeId);

    // Phase 5: Managed modes (parental / enterprise PIN-lock)
    SwitchResult setManagedModePolicy(in ManagedModePolicy policy);
    void clearManagedModePolicy(String modeId);
    ManagedModePolicy getManagedModePolicy(String modeId);
    SwitchResult activateManagedMode(String modeId, String pin);
    boolean isManagedModeActive();

    // Phase 5: Auto-switch learning
    List<LearningSuggestion> getLearningSuggestions();
    void acceptLearningSuggestion(String suggestionId);
    void dismissLearningSuggestion(String suggestionId);
    SwitchResult undoLastSwitch();

    // Phase 5: Community sharing
    String getModeShareUrl(String modeId);
    SwitchResult importModeFromUrl(String url);
    List<PersonalityMode> fetchCommunityModes();
}
