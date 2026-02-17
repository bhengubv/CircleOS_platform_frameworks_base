/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import za.co.circleos.personality.PersonalityMode;
import za.co.circleos.personality.SwitchResult;
import za.co.circleos.personality.TriggerRule;
import za.co.circleos.personality.IPersonalityCallback;

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
}
