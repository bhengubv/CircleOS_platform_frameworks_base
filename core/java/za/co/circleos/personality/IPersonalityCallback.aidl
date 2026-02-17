/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import za.co.circleos.personality.PersonalityMode;

oneway interface IPersonalityCallback {
    void onModeChanged(in PersonalityMode previousMode, in PersonalityMode newMode);
    void onEmergencyBypassChanged(boolean active);
}
