/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.circleos.ICirclePrivacyManager;
import android.circleos.PermissionUsageRecord;
import android.circleos.privacy.ICirclePrivacyManagerService;
import android.content.Context;
import android.os.Binder;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import java.util.ArrayList;
import java.util.List;

/**
 * Circle OS Privacy Engine.
 *
 * <p>Owns the per-package privacy policy + permission-use audit log +
 * the system-wide privacy counters that the CircleOsSettings dashboard
 * surfaces.
 *
 * <p>Publishes two binder surfaces, mirroring the two AIDLs in
 * {@code vendor/circle/aidl/}:
 *
 * <ul>
 *   <li>{@code circle.privacy} — system-wide counters
 *       ({@link ICirclePrivacyManagerService}).
 *   <li>{@code circle_privacy} — per-package CRUD
 *       ({@link ICirclePrivacyManager}).
 * </ul>
 *
 * <p>Persistence is in {@link PrivacyDatabase} (SQLite under
 * {@code /data/system/circle/privacy.db}, device-protected storage so
 * the service is usable from PHASE_LOCK_SETTINGS_READY onward).
 *
 * <p>Default-deny: a package with no row in the {@code policy} table
 * gets a freshly-constructed {@link AppPrivacyPolicy} — every flag
 * false, empty sensor list. That's the same constructor used by
 * upstream {@code AppPrivacyPolicy()} so caller and storage agree.
 */
public final class CirclePrivacyManagerService extends SystemService {

    private static final String TAG = "CirclePrivacy";

    /** Service name used by {@link ICirclePrivacyManagerService}. */
    public static final String SERVICE_SYSTEM  = "circle.privacy";

    /** Service name used by {@link ICirclePrivacyManager}. */
    public static final String SERVICE_PER_APP = "circle_privacy";

    /** Default usage-log lookback when caller passes {@code since == 0}. */
    private static final long DEFAULT_USAGE_LOOKBACK_MS = 30L * 24 * 60 * 60 * 1000;

    /** Max rows returned from a single {@code getUsageLog} call. */
    private static final int  MAX_USAGE_ROWS = 500;

    private final PrivacyDatabase mDb;
    private final SystemBinder    mSystemBinder = new SystemBinder();
    private final PerAppBinder    mPerAppBinder = new PerAppBinder();

    public CirclePrivacyManagerService(Context context) {
        super(context);
        mDb = new PrivacyDatabase(context);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_SYSTEM + " (system counters) + "
                + SERVICE_PER_APP + " (per-app CRUD) binders");
        publishBinderService(SERVICE_SYSTEM,  mSystemBinder);
        publishBinderService(SERVICE_PER_APP, mPerAppBinder);
    }

    // ------------------------------------------------------------------
    //  System-wide counters (ICirclePrivacyManagerService)
    // ------------------------------------------------------------------

    private final class SystemBinder extends ICirclePrivacyManagerService.Stub {

        @Override
        public int getDeniedPermissionCount() {
            enforceQueryPrivacy();
            return mDb.getCounter(PrivacyDatabase.COUNTER_DENIED_PERMISSIONS);
        }

        @Override
        public int getFakedIdentifierCount() {
            enforceQueryPrivacy();
            return mDb.getCounter(PrivacyDatabase.COUNTER_FAKED_IDENTIFIERS);
        }

        @Override
        public int getNetworkGrantCount() {
            enforceQueryPrivacy();
            // Authoritative: count over the policy table (the counter row is
            // an upper bound; this is the live truth).
            return mDb.countNetworkGrants();
        }
    }

    // ------------------------------------------------------------------
    //  Per-package CRUD (ICirclePrivacyManager)
    // ------------------------------------------------------------------

    private final class PerAppBinder extends ICirclePrivacyManager.Stub {

        @Override
        public int getPrivacyScore(String packageName) {
            enforceQueryPrivacy();
            if (TextUtils.isEmpty(packageName)) return 0;
            return computeScore(mDb.getPolicy(packageName));
        }

        @Override
        public AppPrivacyPolicy getPolicy(String packageName) {
            enforceQueryPrivacy();
            return mDb.getPolicy(packageName);
        }

        @Override
        public void setPolicy(String packageName, AppPrivacyPolicy policy) {
            enforceManagePrivacy();
            if (TextUtils.isEmpty(packageName) || policy == null) return;
            mDb.setPolicy(packageName, policy);

            // Log the policy change so the dashboard timeline shows it.
            final PermissionUsageRecord rec = new PermissionUsageRecord();
            rec.timestamp  = System.currentTimeMillis();
            rec.permission = "circle.policy.changed";
            rec.action     = "granted";
            rec.extra      = summarise(policy);
            mDb.appendUsage(rec, packageName);

            Slog.i(TAG, "Policy updated for " + packageName + ": " + rec.extra);
            // TODO: NetworkPermissionEnforcer.refresh(packageName) once that
            //       lands — until then setPolicy persists the user's wish but
            //       the kernel netfilter rules don't move.
        }

        @Override
        public List<PermissionUsageRecord> getUsageLog(String packageName, long since) {
            enforceQueryPrivacy();
            if (TextUtils.isEmpty(packageName)) return new ArrayList<>();
            final long effectiveSince = since <= 0
                    ? System.currentTimeMillis() - DEFAULT_USAGE_LOOKBACK_MS
                    : since;
            return mDb.getUsageLog(packageName, effectiveSince, MAX_USAGE_ROWS);
        }

        @Override
        public int revokeUnusedPermissions() {
            enforceManagePrivacy();
            // TODO: requires PackageManager + PermissionManager integration —
            //       walk every installed package, check whether each runtime
            //       permission has been used in the last 90d (via our
            //       usage_log + AppOpsManager.getOpsForPackage cross-ref),
            //       revoke unused, log. Returns count.
            //       Tracked under task #5 (Week 2).
            Slog.i(TAG, "revokeUnusedPermissions() — not yet implemented");
            return 0;
        }
    }

    // ------------------------------------------------------------------
    //  Score derivation
    // ------------------------------------------------------------------

    /**
     * Composite 0..100 score from an {@link AppPrivacyPolicy}. Higher is
     * better. Simple weighted sum for alpha — the real formula will fold
     * in usage-frequency (a network-allowed app that uses it once a week
     * scores higher than one that beacons every minute) and Traffic Lobby
     * verdicts once those land.
     *
     * <p>Weights match the user-perceived sensitivity of each surface:
     * network=40, contacts=25, storage=15, every sensor=2 (cap 20).
     * Total possible penalty 100. Score = 100 - penalty.
     */
    static int computeScore(AppPrivacyPolicy p) {
        if (p == null) return 100;
        int penalty = 0;
        if (p.networkAllowed)  penalty += 40;
        if (p.contactsAllowed) penalty += 25;
        if (p.storageAllowed)  penalty += 15;
        if (p.allowedSensors != null) {
            penalty += Math.min(20, p.allowedSensors.size() * 2);
        }
        return Math.max(0, 100 - penalty);
    }

    private static String summarise(AppPrivacyPolicy p) {
        if (p == null) return "null";
        final StringBuilder sb = new StringBuilder();
        sb.append("net=").append(p.networkAllowed ? "1" : "0");
        sb.append(",contacts=").append(p.contactsAllowed ? "1" : "0");
        sb.append(",storage=").append(p.storageAllowed ? "1" : "0");
        sb.append(",lobby=").append(p.lobbyMode ? "1" : "0");
        sb.append(",sensors=").append(p.allowedSensors == null ? 0 : p.allowedSensors.size());
        return sb.toString();
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    /**
     * Read access requires {@code za.co.circleos.permission.QUERY_PRIVACY}.
     * SYSTEM_UID and ROOT_UID are always permitted (the dashboard runs
     * under system_server's identity for some reads).
     */
    private void enforceQueryPrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) {
            return;
        }
        // TODO: enforce once the permission is declared in CircleSettings
        //       AndroidManifest.xml. Until then permit-all so the UI can
        //       wire up during development without crashing.
        // getContext().enforceCallingOrSelfPermission(
        //         "za.co.circleos.permission.QUERY_PRIVACY",
        //         "Need QUERY_PRIVACY to read Circle privacy state");
    }

    /**
     * Write access requires {@code za.co.circleos.permission.MANAGE_PRIVACY}.
     */
    private void enforceManagePrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) {
            return;
        }
        // TODO: see enforceQueryPrivacy().
        // getContext().enforceCallingOrSelfPermission(
        //         "za.co.circleos.permission.MANAGE_PRIVACY",
        //         "Need MANAGE_PRIVACY to change Circle privacy state");
    }
}
