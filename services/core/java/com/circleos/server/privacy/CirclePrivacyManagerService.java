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
 *       ({@link ICirclePrivacyManagerService}). Apps call this through
 *       {@code ServiceManager.getService("circle.privacy")} and need the
 *       {@code za.co.circleos.permission.QUERY_PRIVACY} permission.
 *   <li>{@code circle_privacy} — per-package CRUD
 *       ({@link ICirclePrivacyManager}). Settings UIs call this through
 *       {@code ServiceManager.getService("circle_privacy")} and need
 *       {@code QUERY_PRIVACY} to read,
 *       {@code za.co.circleos.permission.MANAGE_PRIVACY} to write.
 * </ul>
 *
 * <p><b>NAMING NOTE:</b> the two service names ({@code circle.privacy}
 * dot vs {@code circle_privacy} underscore) come from the existing
 * AIDL comments in vendor/circle/. The SELinux service_contexts file
 * currently declares only the dot variant — the underscore variant
 * also needs an entry there once this service is wired in (or the two
 * names need to be harmonised). Scaffold registers BOTH so the
 * decision can be made without further code changes.
 *
 * <p>This is a SCAFFOLD. Storage, real policy enforcement, and
 * integration with NetworkPermissionEnforcer / PackageManager all land
 * in subsequent CLs. The skeleton compiles, registers, returns
 * deny-by-default policy for every package, and logs every call so
 * downstream wiring (CircleSettings, AutoRevokeJobService) has a real
 * binder to talk to during development.
 */
public final class CirclePrivacyManagerService extends SystemService {

    private static final String TAG = "CirclePrivacy";

    /** Service name used by {@link ICirclePrivacyManagerService} (system-wide counters). */
    public static final String SERVICE_SYSTEM = "circle.privacy";

    /** Service name used by {@link ICirclePrivacyManager} (per-package CRUD). */
    public static final String SERVICE_PER_APP = "circle_privacy";

    private final SystemBinder mSystemBinder = new SystemBinder();
    private final PerAppBinder mPerAppBinder = new PerAppBinder();

    public CirclePrivacyManagerService(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_SYSTEM + " (system counters) + "
                + SERVICE_PER_APP + " (per-app CRUD) binders");
        publishBinderService(SERVICE_SYSTEM, mSystemBinder);
        publishBinderService(SERVICE_PER_APP, mPerAppBinder);
    }

    // ------------------------------------------------------------------
    //  System-wide counters (ICirclePrivacyManagerService)
    // ------------------------------------------------------------------

    private final class SystemBinder extends ICirclePrivacyManagerService.Stub {

        @Override
        public int getDeniedPermissionCount() throws RemoteException {
            enforceQueryPrivacy();
            // TODO: read from PrivacyDatabase counters table.
            return 0;
        }

        @Override
        public int getFakedIdentifierCount() throws RemoteException {
            enforceQueryPrivacy();
            // TODO: read from PrivacyDatabase counters table.
            return 0;
        }

        @Override
        public int getNetworkGrantCount() throws RemoteException {
            enforceQueryPrivacy();
            // TODO: count packages whose AppPrivacyPolicy.networkAllowed = true.
            return 0;
        }
    }

    // ------------------------------------------------------------------
    //  Per-package CRUD (ICirclePrivacyManager)
    // ------------------------------------------------------------------

    private final class PerAppBinder extends ICirclePrivacyManager.Stub {

        @Override
        public int getPrivacyScore(String packageName) throws RemoteException {
            enforceQueryPrivacy();
            // TODO: derive from AppPrivacyPolicy + recent PermissionUsageRecord
            //       + TrafficLobby verdicts. Until then everything is "perfect"
            //       because deny-by-default leaks nothing.
            return 100;
        }

        @Override
        public AppPrivacyPolicy getPolicy(String packageName) throws RemoteException {
            enforceQueryPrivacy();
            // TODO: SELECT from PrivacyDatabase.policy WHERE package=?
            //       Until storage lands, return a fresh deny-by-default policy
            //       (constructor sets every flag false + empty sensor list).
            return new AppPrivacyPolicy();
        }

        @Override
        public void setPolicy(String packageName, AppPrivacyPolicy policy)
                throws RemoteException {
            enforceManagePrivacy();
            // TODO: INSERT OR REPLACE INTO PrivacyDatabase.policy + invalidate
            //       NetworkPermissionEnforcer cache + emit a PermissionUsageRecord
            //       with action="policy_changed".
            Slog.i(TAG, "setPolicy(" + packageName + ") — stub, not yet persisted");
        }

        @Override
        public List<PermissionUsageRecord> getUsageLog(String packageName, long since)
                throws RemoteException {
            enforceQueryPrivacy();
            // TODO: SELECT FROM PrivacyDatabase.usage_log WHERE package=? AND ts>=?
            //       ORDER BY ts DESC.
            return new ArrayList<>();
        }

        @Override
        public int revokeUnusedPermissions() throws RemoteException {
            enforceManagePrivacy();
            // TODO: scan installed packages, find those with no usage record
            //       in last 90 days (per master plan), revoke runtime perms via
            //       PermissionManager, log + return count.
            Slog.i(TAG, "revokeUnusedPermissions() — stub, not implemented");
            return 0;
        }
    }

    // ------------------------------------------------------------------
    //  Permission gates
    // ------------------------------------------------------------------

    /**
     * Callers reading privacy state need {@code QUERY_PRIVACY}. Throws
     * {@link SecurityException} on failure (binder translates to
     * RemoteException on the other side).
     */
    private void enforceQueryPrivacy() {
        // TODO: actual enforcement once the permission is declared in the
        //       Circle manifest (vendor/circle/apps/CircleSettings/AndroidManifest.xml).
        //       Until then we permit everything so CircleSettings can connect
        //       during development without crashing.
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) {
            return;
        }
        // getContext().enforceCallingOrSelfPermission(
        //         "za.co.circleos.permission.QUERY_PRIVACY",
        //         "Need QUERY_PRIVACY to read Circle privacy state");
    }

    /**
     * Callers writing privacy state need {@code MANAGE_PRIVACY}.
     */
    private void enforceManagePrivacy() {
        // TODO: see enforceQueryPrivacy().
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) {
            return;
        }
        // getContext().enforceCallingOrSelfPermission(
        //         "za.co.circleos.permission.MANAGE_PRIVACY",
        //         "Need MANAGE_PRIVACY to change Circle privacy state");
    }
}
