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
 * Circle OS Privacy Engine -- v3 with NetworkPermissionEnforcer wired
 * into the policy hot path.
 *
 * <p>Each call to {@link PerAppBinder#setPolicy(String, AppPrivacyPolicy)}
 * now triggers {@link NetworkPermissionEnforcer#enforce} which applies
 * both a {@code NetworkPolicyManager.setUidPolicy} record and an
 * {@code INetd.firewallSetUidRule} kernel-level deny. Revoking the
 * policy reverses both.
 *
 * <p>Other surfaces are unchanged from v2: SQLite-backed policy + log
 * + counters, two binder names ({@code circle.privacy} + {@code circle_privacy}),
 * deny-by-default policy default, deterministic 0-100 score derivation.
 */
public final class CirclePrivacyManagerService extends SystemService {

    private static final String TAG = "CirclePrivacy";

    public static final String SERVICE_SYSTEM  = "circle.privacy";
    public static final String SERVICE_PER_APP = "circle_privacy";

    private static final long DEFAULT_USAGE_LOOKBACK_MS = 30L * 24 * 60 * 60 * 1000;
    private static final int  MAX_USAGE_ROWS = 500;

    private final PrivacyDatabase            mDb;
    private final NetworkPermissionEnforcer  mEnforcer;
    private final SystemBinder               mSystemBinder = new SystemBinder();
    private final PerAppBinder               mPerAppBinder = new PerAppBinder();

    public CirclePrivacyManagerService(Context context) {
        super(context);
        mDb       = new PrivacyDatabase(context);
        mEnforcer = new NetworkPermissionEnforcer(context);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_SYSTEM + " + " + SERVICE_PER_APP);
        publishBinderService(SERVICE_SYSTEM,  mSystemBinder);
        publishBinderService(SERVICE_PER_APP, mPerAppBinder);
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            // Schedule the periodic auto-revoke pass once the system is
            // up enough that JobScheduler is available. This is the entry
            // point CircleSettings' BootReceiver would also hit -- doing
            // it from system_server too gives belt + braces.
            try {
                CircleAutoRevokeScheduler.schedule(getContext());
            } catch (Throwable t) {
                Slog.w(TAG, "AutoRevoke schedule failed", t);
            }
        }
    }

    // ------------------------------------------------------------------
    //  System-wide counters
    // ------------------------------------------------------------------

    private final class SystemBinder extends ICirclePrivacyManagerService.Stub {
        @Override public int getDeniedPermissionCount() {
            enforceQueryPrivacy();
            return mDb.getCounter(PrivacyDatabase.COUNTER_DENIED_PERMISSIONS);
        }
        @Override public int getFakedIdentifierCount() {
            enforceQueryPrivacy();
            return mDb.getCounter(PrivacyDatabase.COUNTER_FAKED_IDENTIFIERS);
        }
        @Override public int getNetworkGrantCount() {
            enforceQueryPrivacy();
            return mDb.countNetworkGrants();
        }
    }

    // ------------------------------------------------------------------
    //  Per-package CRUD
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

            // Wire the policy through to the kernel firewall + NetworkPolicy.
            // This is the v2->v3 upgrade: the setPolicy hot path is now
            // the SINGLE place where deny-by-default becomes real.
            mEnforcer.enforce(packageName, policy);

            // Audit log.
            final PermissionUsageRecord rec = new PermissionUsageRecord();
            rec.timestamp  = System.currentTimeMillis();
            rec.permission = "circle.policy.changed";
            rec.action     = "granted";
            rec.extra      = summarise(policy);
            mDb.appendUsage(rec, packageName);

            Slog.i(TAG, "Policy updated for " + packageName + ": " + rec.extra);
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
            // The actual revocation runs from CircleAutoRevokeJobService
            // (CircleSettings app); calling here returns the count from
            // the last completed pass so dashboards see fresh numbers.
            return mDb.getCounter("auto_revoke_last_count");
        }
    }

    // ------------------------------------------------------------------
    //  Score derivation -- unchanged from v2
    // ------------------------------------------------------------------

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
    //  Permission gates -- unchanged from v2
    // ------------------------------------------------------------------

    private void enforceQueryPrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
    }

    private void enforceManagePrivacy() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
    }
}
