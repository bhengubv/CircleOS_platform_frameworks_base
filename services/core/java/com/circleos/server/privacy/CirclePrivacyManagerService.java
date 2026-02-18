/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.circleos.ICirclePrivacyManager;
import android.circleos.PermissionUsageRecord;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.Slog;

import com.android.server.SystemService;

import java.io.File;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Circle OS Privacy Manager — the central coordinator of all privacy subsystems.
 *
 * Registered in SystemServer as {@value #SERVICE_NAME}.
 *
 * Architecture:
 *   CirclePrivacyManagerService  (this class — Binder service "circle.privacy")
 *   ├── NetworkPermissionEnforcer  (per-UID netfilter rules via INetd)
 *   ├── CirclePermissionService    (Circle-specific permission management)
 *   ├── ScopedContactsProvider     (per-app contact visibility)
 *   ├── ScopedStorageProvider      (SAF enforcement)
 *   ├── PrivacyLogger              (encrypted SQLite audit trail)
 *   └── PrivacyRulesEngine         (Allow/Deny/Fake/Ask/Log policy evaluation)
 *
 * Pattern: extends SystemService, uses Lifecycle inner class — same as ClipboardService.
 * Background work: HandlerThread + Handler — same as NetworkPolicyManagerService.
 */
public class CirclePrivacyManagerService extends SystemService {

    private static final String TAG          = "CirclePrivacyManager";
    public  static final String SERVICE_NAME = "circle.privacy";

    // Policy persistence
    private static final String POLICY_DB_PATH = "/data/circle/privacy/policies.db";
    private static final int    POLICY_DB_VER  = 1;
    private static final String POLICY_TABLE   = "app_policies";

    /** Revoke grants for apps unused for this long (30 days). */
    private static final long REVOKE_IDLE_WINDOW_MS = TimeUnit.DAYS.toMillis(30);

    // ---- Policy DB helper ----

    private static class PolicyDbHelper extends SQLiteOpenHelper {
        PolicyDbHelper(Context ctx) {
            super(ctx, POLICY_DB_PATH, null, POLICY_DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS " + POLICY_TABLE + " (" +
                "package_name   TEXT PRIMARY KEY, " +
                "network        INTEGER DEFAULT 0, " +
                "wifi_only      INTEGER DEFAULT 0, " +
                "mobile_only    INTEGER DEFAULT 0, " +
                "lobby_mode     INTEGER DEFAULT 0, " +
                "contacts       INTEGER DEFAULT 0, " +
                "storage        INTEGER DEFAULT 0, " +
                "allowed_domains TEXT, " +    // JSON array
                "allowed_sensors TEXT, " +    // JSON array
                "updated_at     INTEGER" +
                ")"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int old, int ver) {}
    }

    // ---- Fields ----

    private final HandlerThread mThread;
    private final Handler       mHandler;

    // Sub-components
    final PrivacyLogger            mLogger;
    final PrivacyRulesEngine       mRulesEngine;
    final NetworkPermissionEnforcer mNetworkEnforcer;
    final ScopedContactsProvider   mContactsProvider;
    final ScopedStorageProvider    mStorageProvider;
    private final PolicyDbHelper   mPolicyDb;

    // ---- Lifecycle ----

    /**
     * Lifecycle wrapper — required for SystemServiceManager.startService(Lifecycle.class).
     */
    public static class Lifecycle extends SystemService {
        private CirclePrivacyManagerService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new CirclePrivacyManagerService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            if (mService != null) mService.onBootPhase(phase);
        }
    }

    // ---- Constructor ----

    public CirclePrivacyManagerService(Context context) {
        super(context);
        ensureDataDirs();

        mThread = new HandlerThread("CirclePrivacyManager");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());

        mLogger          = new PrivacyLogger(context);
        mRulesEngine     = new PrivacyRulesEngine();
        mNetworkEnforcer = new NetworkPermissionEnforcer(context, mLogger);
        mContactsProvider = new ScopedContactsProvider();
        mStorageProvider = new ScopedStorageProvider(context);
        mPolicyDb        = new PolicyDbHelper(context);
    }

    // ---- SystemService ----

    @Override
    public void onStart() {
        publishBinderService(SERVICE_NAME, mBinderImpl);
        Slog.i(TAG, "CirclePrivacyManagerService started");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            mNetworkEnforcer.reapplyAllGrants();
            Slog.i(TAG, "Boot completed — network grants re-applied");
        }
    }

    // ---- Binder implementation ----

    private final IBinder mBinderImpl = new ICirclePrivacyManager.Stub() {

        @Override
        public AppPrivacyPolicy getPolicy(String packageName) {
            enforceManagePrivacy();
            return loadPolicy(packageName);
        }

        @Override
        public void setPolicy(String packageName, AppPrivacyPolicy policy) {
            enforceManagePrivacy();
            mHandler.post(() -> {
                persistPolicy(packageName, policy);
                applyPolicy(packageName, policy);
                mLogger.log(packageName, "POLICY", "UPDATED", null);
                Slog.i(TAG, "Policy updated for " + packageName);
            });
        }

        @Override
        public List<PermissionUsageRecord> getUsageLog(String packageName, long since) {
            enforceManagePrivacy();
            return mLogger.query(packageName, since);
        }

        @Override
        public int getPrivacyScore(String packageName) {
            enforceManagePrivacy();
            return computePrivacyScore(packageName);
        }

        @Override
        public void revokeUnusedPermissions() {
            enforceManagePrivacy();
            mHandler.post(() -> {
                Slog.i(TAG, "revokeUnusedPermissions: scanning all packages…");
                long cutoff = System.currentTimeMillis() - REVOKE_IDLE_WINDOW_MS;
                PackageManager pm = getContext().getPackageManager();
                List<ApplicationInfo> apps;
                try {
                    apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
                } catch (Exception e) {
                    Slog.e(TAG, "revokeUnusedPermissions: PackageManager failed", e);
                    return;
                }
                int revoked = 0;
                for (ApplicationInfo app : apps) {
                    String pkg = app.packageName;
                    AppPrivacyPolicy policy = loadPolicy(pkg);
                    // Only act if the app has been granted at least one non-default permission
                    if (!policy.networkAllowed && !policy.contactsAllowed
                            && !policy.storageAllowed && policy.allowedSensors.isEmpty()) {
                        continue;
                    }
                    // Check for any usage record since the cutoff
                    List<PermissionUsageRecord> recent = mLogger.query(pkg, cutoff);
                    if (!recent.isEmpty()) continue; // still active — leave it

                    // No usage since cutoff: revoke network, contacts, storage, sensors
                    AppPrivacyPolicy stripped = new AppPrivacyPolicy();
                    stripped.networkAllowed  = false;
                    stripped.contactsAllowed = false;
                    stripped.storageAllowed  = false;
                    stripped.allowedSensors  = new java.util.ArrayList<>();
                    // Preserve static settings that aren't usage-gated
                    stripped.wifiOnly   = policy.wifiOnly;
                    stripped.mobileOnly = policy.mobileOnly;
                    stripped.lobbyMode  = policy.lobbyMode;
                    stripped.allowedDomains = policy.allowedDomains;

                    persistPolicy(pkg, stripped);
                    applyPolicy(pkg, stripped);
                    mLogger.log("system", pkg, "AUTO_REVOKE",
                            "idle >" + (REVOKE_IDLE_WINDOW_MS / 86400000L) + "d");
                    Slog.i(TAG, "Auto-revoked: " + pkg);
                    revoked++;
                }
                mLogger.log("system", "ALL_PERMISSIONS", "AUTO_REVOKE_SCAN",
                        "revoked=" + revoked + "/" + apps.size());
                Slog.i(TAG, "Auto-revoke scan complete: " + revoked + "/" + apps.size()
                        + " packages stripped");
            });
        }
    };

    // ---- Private helpers ----

    /** Loads the stored policy for a package, or returns a default deny-all policy. */
    private AppPrivacyPolicy loadPolicy(String packageName) {
        AppPrivacyPolicy policy = new AppPrivacyPolicy();
        try {
            SQLiteDatabase db = mPolicyDb.getReadableDatabase();
            try (Cursor c = db.query(POLICY_TABLE, null,
                    "package_name=?", new String[]{packageName},
                    null, null, null)) {
                if (c.moveToFirst()) {
                    policy.networkAllowed = c.getInt(c.getColumnIndexOrThrow("network"))  == 1;
                    policy.wifiOnly       = c.getInt(c.getColumnIndexOrThrow("wifi_only")) == 1;
                    policy.mobileOnly     = c.getInt(c.getColumnIndexOrThrow("mobile_only")) == 1;
                    policy.lobbyMode      = c.getInt(c.getColumnIndexOrThrow("lobby_mode")) == 1;
                    policy.contactsAllowed = c.getInt(c.getColumnIndexOrThrow("contacts")) == 1;
                    policy.storageAllowed  = c.getInt(c.getColumnIndexOrThrow("storage"))  == 1;
                    // allowedDomains and allowedSensors deserialization (JSON → List) omitted for brevity
                }
            }
        } catch (Exception e) {
            Slog.e(TAG, "loadPolicy failed for " + packageName, e);
        }
        return policy; // default: all false = deny-all
    }

    private void persistPolicy(String packageName, AppPrivacyPolicy policy) {
        try {
            SQLiteDatabase db = mPolicyDb.getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put("package_name",   packageName);
            cv.put("network",        policy.networkAllowed ? 1 : 0);
            cv.put("wifi_only",      policy.wifiOnly       ? 1 : 0);
            cv.put("mobile_only",    policy.mobileOnly     ? 1 : 0);
            cv.put("lobby_mode",     policy.lobbyMode      ? 1 : 0);
            cv.put("contacts",       policy.contactsAllowed ? 1 : 0);
            cv.put("storage",        policy.storageAllowed  ? 1 : 0);
            cv.put("updated_at",     System.currentTimeMillis());
            db.insertWithOnConflict(POLICY_TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
        } catch (Exception e) {
            Slog.e(TAG, "persistPolicy failed for " + packageName, e);
        }
    }

    /**
     * Applies a policy change immediately: updates network firewall rules,
     * sensor privacy, etc.
     */
    private void applyPolicy(String packageName, AppPrivacyPolicy policy) {
        // Network permission
        if (policy.networkAllowed) {
            mNetworkEnforcer.grantNetworkPermission(packageName);
        } else {
            mNetworkEnforcer.revokeNetworkPermission(packageName);
        }
        // Sensor and contacts enforcement handled at access time by rule engine.
    }

    /**
     * Computes a 0–100 privacy score.
     * Higher = more privacy-preserving.
     * Simple heuristic: deduct points for each risky permission granted.
     */
    private int computePrivacyScore(String packageName) {
        AppPrivacyPolicy policy = loadPolicy(packageName);
        int score = 100;
        if (policy.networkAllowed && policy.allowedDomains.isEmpty()) score -= 20;
        if (policy.contactsAllowed) score -= 15;
        if (policy.storageAllowed)  score -= 10;
        if (!policy.allowedSensors.isEmpty()) score -= (5 * policy.allowedSensors.size());
        if (policy.lobbyMode) score += 10; // Lobby mode = extra restrictive = bonus
        return Math.max(0, Math.min(100, score));
    }

    /** Requires caller to hold com.circleos.permission.MANAGE_PRIVACY. */
    private void enforceManagePrivacy() {
        getContext().enforceCallingOrSelfPermission(
                "com.circleos.permission.MANAGE_PRIVACY",
                "Requires com.circleos.permission.MANAGE_PRIVACY");
    }

    private static void ensureDataDirs() {
        for (String path : new String[]{"/data/circle", "/data/circle/privacy"}) {
            File dir = new File(path);
            if (!dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
        }
    }
}
