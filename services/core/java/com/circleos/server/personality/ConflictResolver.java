/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.util.Log;

import java.util.List;

import za.co.circleos.personality.TriggerRule;

/**
 * Resolves conflicts when multiple auto-switch triggers fire simultaneously.
 *
 * <p>Priority hierarchy (highest first):
 * <ol>
 *   <li>Emergency bypass (100) — always wins, never stored as a rule</li>
 *   <li>Manual user selection (90)</li>
 *   <li>Calendar trigger (70)</li>
 *   <li>Time-based trigger (50)</li>
 *   <li>Battery trigger (30)</li>
 *   <li>Charging state trigger (20)</li>
 * </ol>
 */
class ConflictResolver {

    private static final String TAG = "CirclePersonality";

    static final int PRIORITY_EMERGENCY = 100;
    static final int PRIORITY_MANUAL    = TriggerRule.PRIORITY_MANUAL;
    static final int PRIORITY_CALENDAR  = TriggerRule.PRIORITY_CALENDAR;
    static final int PRIORITY_TIME      = TriggerRule.PRIORITY_TIME;
    static final int PRIORITY_BATTERY   = TriggerRule.PRIORITY_BATTERY;
    static final int PRIORITY_CHARGING  = TriggerRule.PRIORITY_CHARGING;

    /**
     * Result of conflict resolution.
     */
    static final class Resolution {
        /** Mode to activate. */
        final String targetModeId;
        /** Priority of the winning rule. */
        final int    priority;
        /** Human-readable source label for logging. */
        final String resolvedBy;

        Resolution(String targetModeId, int priority, String resolvedBy) {
            this.targetModeId = targetModeId;
            this.priority     = priority;
            this.resolvedBy   = resolvedBy;
        }
    }

    /**
     * Resolves the winning action from the given context.
     *
     * @param manualModeId     non-null if the user manually requested a mode
     * @param pendingRules     auto-switch rules that have just fired
     * @param emergencyBypass  true if emergency bypass is active
     * @return winning resolution, or null if nothing should change
     */
    Resolution resolve(String manualModeId,
                       List<TriggerRule> pendingRules,
                       boolean emergencyBypass) {

        if (emergencyBypass) {
            // Emergency bypass always clears; the bypass itself is not a mode switch
            Log.d(TAG, "ConflictResolver: emergency bypass active, no auto-switch");
            return null;
        }

        if (manualModeId != null) {
            return new Resolution(manualModeId, PRIORITY_MANUAL, "manual");
        }

        if (pendingRules == null || pendingRules.isEmpty()) {
            return null;
        }

        TriggerRule winner = null;
        int          best  = -1;
        for (TriggerRule rule : pendingRules) {
            if (!rule.enabled) continue;
            int p = rule.effectivePriority();
            if (p > best) {
                best   = p;
                winner = rule;
            }
        }

        if (winner == null) return null;

        Log.d(TAG, "ConflictResolver: winner rule=" + winner.id
                + " priority=" + best + " target=" + winner.targetModeId);
        return new Resolution(winner.targetModeId, best, "rule:" + winner.id);
    }
}
