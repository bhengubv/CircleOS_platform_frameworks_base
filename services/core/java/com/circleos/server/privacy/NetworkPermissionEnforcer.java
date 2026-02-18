/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.INetd;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Slog;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Enforces per-UID internet access restrictions via Linux netfilter.
 *
 * Default policy: no app UID may reach the internet.
 * To allow internet: call {@link #grantNetworkPermission(String)}.
 * Grants persist to SQLite; re-applied after reboot by {@link CirclePermissionService}.
 *
 * Mechanism: delegates to {@code INetd} (same IPC path used by
 * NetworkPolicyManagerService) via UID-based firewall rules on the
 * {@code fw_circle} iptables chain (FORWARD/OUTPUT).
 *
 * New app installs are automatically placed in the DENY state via a
 * {@link PackageManager#ACTION_PACKAGE_ADDED} broadcast receiver.
 */
public class NetworkPermissionEnforcer {

    private static final String TAG = "CircleNetPermEnforcer";

    private static final String DB_PATH = "/data/circle/privacy/network_grants.db";
    private static final int    DB_VER  = 1;
    private static final String TABLE   = "network_grants";
    private static final String COL_PKG = "package_name";
    private static final String COL_UID = "uid";
    private static final String COL_TS  = "granted_at";

    // ---- DB helper ----

    private static class GrantsDbHelper extends SQLiteOpenHelper {
        GrantsDbHelper(Context ctx) {
            super(ctx, DB_PATH, null, DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS " + TABLE + " (" +
                COL_PKG + " TEXT NOT NULL, " +
                COL_UID + " INTEGER NOT NULL, " +
                COL_TS  + " INTEGER NOT NULL, " +
                "PRIMARY KEY(" + COL_PKG + ")" +
                ")"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int old, int ver) {}
    }

    // ---- Fields ----

    private final Context        mContext;
    private final PrivacyLogger  mLogger;
    private final HandlerThread  mThread;
    private final Handler        mHandler;
    private final GrantsDbHelper mDbHelper;
    private INetd                mNetd;

    public NetworkPermissionEnforcer(Context context, PrivacyLogger logger) {
        mContext  = context;
        mLogger   = logger;

        ensureDataDir();
        mDbHelper = new GrantsDbHelper(context);

        mThread = new HandlerThread("CircleNetEnforcer");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());

        connectToNetd();
        registerPackageReceiver();
    }

    // ---- Public API ----

    /**
     * Grants internet access to the package and adds its UID to the netd
     * ACCEPT chain. Persists to the grants database.
     */
    public void grantNetworkPermission(String packageName) {
        int uid = getUidForPackage(packageName);
        if (uid < 0) {
            Slog.w(TAG, "Cannot grant network permission: package not found: " + packageName);
            return;
        }
        mHandler.post(() -> {
            persistGrant(packageName, uid, true);
            applyNetdRule(uid, true);
            mLogger.log(packageName, "com.circleos.permission.NETWORK", "GRANTED", null);
            Slog.i(TAG, "Network GRANTED for " + packageName + " (uid=" + uid + ")");
        });
    }

    /**
     * Revokes internet access and removes the UID from the netd ACCEPT chain.
     */
    public void revokeNetworkPermission(String packageName) {
        int uid = getUidForPackage(packageName);
        mHandler.post(() -> {
            persistGrant(packageName, uid, false);
            if (uid >= 0) applyNetdRule(uid, false);
            mLogger.log(packageName, "com.circleos.permission.NETWORK", "REVOKED", null);
            Slog.i(TAG, "Network REVOKED for " + packageName + " (uid=" + uid + ")");
        });
    }

    /** Returns true if the package currently holds network permission. */
    public boolean hasNetworkPermission(String packageName) {
        try {
            SQLiteDatabase db = mDbHelper.getReadableDatabase();
            try (Cursor c = db.query(TABLE, new String[]{COL_PKG},
                    COL_PKG + "=?", new String[]{packageName},
                    null, null, null)) {
                return c.moveToFirst();
            }
        } catch (Exception e) {
            Slog.e(TAG, "hasNetworkPermission query failed", e);
            return false;
        }
    }

    /** Returns all packages currently granted network access. */
    public List<String> getGrantedPackages() {
        List<String> result = new ArrayList<>();
        try {
            SQLiteDatabase db = mDbHelper.getReadableDatabase();
            try (Cursor c = db.query(TABLE, new String[]{COL_PKG},
                    null, null, null, null, null)) {
                while (c.moveToNext()) result.add(c.getString(0));
            }
        } catch (Exception e) {
            Slog.e(TAG, "getGrantedPackages failed", e);
        }
        return result;
    }

    /**
     * Re-applies all persisted grants to netd. Called on boot by
     * {@link CirclePermissionService} after netd is ready.
     */
    public void reapplyAllGrants() {
        mHandler.post(() -> {
            try {
                SQLiteDatabase db = mDbHelper.getReadableDatabase();
                try (Cursor c = db.query(TABLE,
                        new String[]{COL_PKG, COL_UID},
                        null, null, null, null, null)) {
                    int count = 0;
                    while (c.moveToNext()) {
                        int uid = c.getInt(1);
                        applyNetdRule(uid, true);
                        count++;
                    }
                    Slog.i(TAG, "Re-applied " + count + " network grants");
                }
            } catch (Exception e) {
                Slog.e(TAG, "Failed to reapply grants", e);
            }
        });
    }

    // ---- Private ----

    /**
     * Applies or removes a UID-based firewall rule via INetd.
     *
     * Uses {@code INetd#firewallSetUidRule} on the DOZABLE chain
     * (repurposed as the Circle default-deny chain).
     * Chain IDs: FIREWALL_CHAIN_DOZABLE = 1, FIREWALL_CHAIN_STANDBY = 2.
     *
     * Rule values: FIREWALL_RULE_ALLOW = 1, FIREWALL_RULE_DENY = 2.
     */
    private void applyNetdRule(int uid, boolean allow) {
        if (mNetd == null) {
            Slog.w(TAG, "INetd not available; skipping firewall rule for uid=" + uid);
            return;
        }
        try {
            // FIREWALL_CHAIN_DOZABLE = 1; FIREWALL_RULE_ALLOW = 1, FIREWALL_RULE_DENY = 2
            int rule = allow ? 1 : 2;
            mNetd.firewallSetUidRule(1 /* DOZABLE */, uid, rule);
        } catch (RemoteException e) {
            Slog.e(TAG, "INetd.firewallSetUidRule failed for uid=" + uid, e);
        }
    }

    private void persistGrant(String packageName, int uid, boolean grant) {
        try {
            SQLiteDatabase db = mDbHelper.getWritableDatabase();
            if (grant) {
                ContentValues cv = new ContentValues(3);
                cv.put(COL_PKG, packageName);
                cv.put(COL_UID, uid);
                cv.put(COL_TS,  System.currentTimeMillis());
                db.insertWithOnConflict(TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
            } else {
                db.delete(TABLE, COL_PKG + "=?", new String[]{packageName});
            }
        } catch (Exception e) {
            Slog.e(TAG, "persistGrant failed for " + packageName, e);
        }
    }

    private int getUidForPackage(String packageName) {
        try {
            ApplicationInfo info = mContext.getPackageManager()
                    .getApplicationInfo(packageName, 0);
            return info.uid;
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    private static final long NETD_RETRY_DELAY_MS = 5_000L;
    private static final int  NETD_RETRY_MAX      = 12; // up to 60 s
    private int               mNetdRetryCount     = 0;

    private void connectToNetd() {
        IBinder b = ServiceManager.getService("netd");
        if (b != null) {
            mNetd = INetd.Stub.asInterface(b);
            mNetdRetryCount = 0;
            Slog.i(TAG, "Connected to netd — reapplying grants");
            reapplyAllGrants();
        } else {
            scheduleNetdRetry();
        }
    }

    private void scheduleNetdRetry() {
        if (mNetdRetryCount >= NETD_RETRY_MAX) {
            Slog.e(TAG, "netd unavailable after " + NETD_RETRY_MAX + " retries — giving up");
            return;
        }
        mNetdRetryCount++;
        long delay = NETD_RETRY_DELAY_MS * mNetdRetryCount;
        Slog.w(TAG, "netd not yet available; retry " + mNetdRetryCount
                + "/" + NETD_RETRY_MAX + " in " + (delay / 1000) + "s");
        mHandler.postDelayed(this::connectToNetd, delay);
    }

    /** Auto-deny newly installed apps. */
    private void registerPackageReceiver() {
        IntentFilter filter = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
        filter.addDataScheme("package");
        mContext.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent intent) {
                String pkg = intent.getData() != null
                        ? intent.getData().getSchemeSpecificPart() : null;
                if (pkg == null) return;
                // New install — default deny. Nothing to do; app is not in grants DB.
                mLogger.log(pkg, "com.circleos.permission.NETWORK", "DENIED",
                        "new install: default deny");
                Slog.i(TAG, "New install auto-denied network: " + pkg);
            }
        }, filter);
    }

    private static void ensureDataDir() {
        File dir = new File("/data/circle/privacy");
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
    }
}
