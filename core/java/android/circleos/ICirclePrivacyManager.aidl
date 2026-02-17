/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * AIDL interface for the Circle OS Privacy Manager.
 * Service name: "circle.privacy"
 */
package android.circleos;

import android.circleos.AppPrivacyPolicy;
import android.circleos.PermissionUsageRecord;

/**
 * Binder interface for CirclePrivacyManagerService.
 *
 * Callers require android.Manifest.permission.MANAGE_APP_OPS_MODES or
 * com.circleos.permission.MANAGE_PRIVACY (defined in AndroidManifest.xml).
 */
interface ICirclePrivacyManager {

    /**
     * Returns the active privacy policy for the given package.
     * Returns a default (deny-all) policy if none has been set.
     */
    AppPrivacyPolicy getPolicy(String packageName);

    /**
     * Persists a privacy policy for the given package.
     * Immediately applies network firewall rules and sensor blocks.
     */
    void setPolicy(String packageName, in AppPrivacyPolicy policy);

    /**
     * Returns the audit log entries for the given package recorded after
     * {@code since} (Unix epoch millis). Returns at most 1000 records.
     */
    List<PermissionUsageRecord> getUsageLog(String packageName, long since);

    /**
     * Computes a 0–100 privacy score for the package based on its requested
     * permissions, granted permissions, and usage patterns.
     * Higher score = more privacy-preserving.
     */
    int getPrivacyScore(String packageName);

    /**
     * Revokes permissions for apps that have not used them in 90+ days.
     * Intended to be called by the auto-revoke JobScheduler job.
     */
    void revokeUnusedPermissions();
}
