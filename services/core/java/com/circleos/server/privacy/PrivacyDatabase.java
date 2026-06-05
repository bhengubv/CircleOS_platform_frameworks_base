/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.circleos.PermissionUsageRecord;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Environment;
import android.text.TextUtils;
import android.util.Slog;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * SQLite-backed storage for the Privacy Engine.
 *
 * <p>Single device-wide database (not per-user — Circle privacy policies
 * apply to a package regardless of which Android user installed it; per-user
 * scoping is a v2 concern). Lives under {@code /data/system/circle/} which
 * is owned by {@code system:system} and labelled
 * {@code circle_privacy_data_file} by vendor/circle/sepolicy/file_contexts
 * (already registered).
 *
 * <p>Three tables:
 * <ul>
 *   <li>{@code policy} — per-package {@link AppPrivacyPolicy} rows
 *   <li>{@code usage_log} — append-only log of every permission decision
 *   <li>{@code counters} — system-wide tallies surfaced by
 *       {@link android.circleos.privacy.ICirclePrivacyManagerService}
 * </ul>
 *
 * <p>Allowed-sensors is stored as a comma-delimited string in the policy
 * row rather than a join table — the list is bounded (< 20 sensor names)
 * and read-mostly, so the join cost isn't worth it.
 */
final class PrivacyDatabase {

    private static final String TAG = "CirclePrivacyDB";

    private static final String DB_NAME = "privacy.db";
    private static final int    DB_VERSION = 1;

    // ---- counter names (referenced from CirclePrivacyManagerService) ----
    static final String COUNTER_DENIED_PERMISSIONS = "denied_permissions";
    static final String COUNTER_FAKED_IDENTIFIERS  = "faked_identifiers";
    static final String COUNTER_NETWORK_GRANTS     = "network_grants";

    private final Helper mHelper;

    PrivacyDatabase(Context context) {
        // Use deviceProtectedDataDir so the DB is reachable before user 0 unlocks
        // (system services start during PHASE_LOCK_SETTINGS_READY which is pre-CE).
        final Context deviceProtected = context.createDeviceProtectedStorageContext();
        final File dir = new File(deviceProtected.getDataDir(), "circle");
        if (!dir.exists() && !dir.mkdirs()) {
            Slog.w(TAG, "Failed to create " + dir + " — DB will land in default location");
        }
        mHelper = new Helper(deviceProtected, new File(dir, DB_NAME).getAbsolutePath());
    }

    // ------------------------------------------------------------------
    //  Policy CRUD
    // ------------------------------------------------------------------

    AppPrivacyPolicy getPolicy(String packageName) {
        if (TextUtils.isEmpty(packageName)) return new AppPrivacyPolicy();
        final SQLiteDatabase db = mHelper.getReadableDatabase();
        try (Cursor c = db.query("policy",
                new String[]{"network_allowed", "contacts_allowed", "storage_allowed",
                             "lobby_mode", "allowed_sensors"},
                "package_name = ?", new String[]{packageName},
                null, null, null, "1")) {
            if (!c.moveToFirst()) {
                // Default-deny — every flag false, empty sensor list
                return new AppPrivacyPolicy();
            }
            final AppPrivacyPolicy p = new AppPrivacyPolicy();
            p.networkAllowed  = c.getInt(0) != 0;
            p.contactsAllowed = c.getInt(1) != 0;
            p.storageAllowed  = c.getInt(2) != 0;
            p.lobbyMode       = c.getInt(3) != 0;
            final String sensorsCsv = c.getString(4);
            if (!TextUtils.isEmpty(sensorsCsv)) {
                p.allowedSensors = new ArrayList<>(Arrays.asList(sensorsCsv.split(",")));
            }
            return p;
        }
    }

    void setPolicy(String packageName, AppPrivacyPolicy policy) {
        if (TextUtils.isEmpty(packageName) || policy == null) return;
        final SQLiteDatabase db = mHelper.getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("package_name",     packageName);
        v.put("network_allowed",  policy.networkAllowed  ? 1 : 0);
        v.put("contacts_allowed", policy.contactsAllowed ? 1 : 0);
        v.put("storage_allowed",  policy.storageAllowed  ? 1 : 0);
        v.put("lobby_mode",       policy.lobbyMode       ? 1 : 0);
        v.put("allowed_sensors",  policy.allowedSensors == null
                ? ""
                : TextUtils.join(",", policy.allowedSensors));
        v.put("updated_ms",       System.currentTimeMillis());
        // INSERT OR REPLACE — package_name is PK
        db.insertWithOnConflict("policy", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    // ------------------------------------------------------------------
    //  Usage log
    // ------------------------------------------------------------------

    void appendUsage(PermissionUsageRecord rec, String packageName) {
        if (rec == null || TextUtils.isEmpty(packageName)) return;
        final SQLiteDatabase db = mHelper.getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("package_name", packageName);
        v.put("timestamp",    rec.timestamp == 0 ? System.currentTimeMillis() : rec.timestamp);
        v.put("permission",   rec.permission != null ? rec.permission : "");
        v.put("action",       rec.action     != null ? rec.action     : "");
        v.put("extra",        rec.extra);
        db.insert("usage_log", null, v);
    }

    List<PermissionUsageRecord> getUsageLog(String packageName, long sinceMs, int limit) {
        if (TextUtils.isEmpty(packageName)) return new ArrayList<>();
        final SQLiteDatabase db = mHelper.getReadableDatabase();
        final List<PermissionUsageRecord> out = new ArrayList<>();
        try (Cursor c = db.query("usage_log",
                new String[]{"timestamp", "permission", "action", "extra"},
                "package_name = ? AND timestamp >= ?",
                new String[]{packageName, Long.toString(sinceMs)},
                null, null, "timestamp DESC",
                Integer.toString(Math.max(1, limit)))) {
            while (c.moveToNext()) {
                final PermissionUsageRecord r = new PermissionUsageRecord();
                r.timestamp  = c.getLong(0);
                r.permission = c.getString(1);
                r.action     = c.getString(2);
                r.extra      = c.getString(3);
                out.add(r);
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    //  System-wide counters
    // ------------------------------------------------------------------

    int getCounter(String name) {
        final SQLiteDatabase db = mHelper.getReadableDatabase();
        try (Cursor c = db.query("counters", new String[]{"value"},
                "name = ?", new String[]{name}, null, null, null, "1")) {
            return c.moveToFirst() ? c.getInt(0) : 0;
        }
    }

    void incrementCounter(String name) {
        final SQLiteDatabase db = mHelper.getWritableDatabase();
        // SQLite UPSERT — bump if exists, insert with 1 otherwise
        db.execSQL(
            "INSERT INTO counters(name, value) VALUES(?, 1) "
            + "ON CONFLICT(name) DO UPDATE SET value = value + 1",
            new Object[]{name}
        );
    }

    /** Count packages whose policy currently grants network. O(table-scan). */
    int countNetworkGrants() {
        final SQLiteDatabase db = mHelper.getReadableDatabase();
        try (Cursor c = db.rawQuery(
                "SELECT COUNT(*) FROM policy WHERE network_allowed = 1", null)) {
            return c.moveToFirst() ? c.getInt(0) : 0;
        }
    }

    // ------------------------------------------------------------------
    //  Maintenance
    // ------------------------------------------------------------------

    /** Drop usage_log rows older than {@code keepMs} ago. Call from a job. */
    int pruneUsageLog(long keepMs) {
        final SQLiteDatabase db = mHelper.getWritableDatabase();
        return db.delete("usage_log", "timestamp < ?",
                new String[]{Long.toString(System.currentTimeMillis() - keepMs)});
    }

    // ------------------------------------------------------------------
    //  SQLiteOpenHelper
    // ------------------------------------------------------------------

    private static final class Helper extends SQLiteOpenHelper {
        Helper(Context ctx, String path) {
            super(ctx, path, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE policy ("
                + "  package_name     TEXT    PRIMARY KEY,"
                + "  network_allowed  INTEGER NOT NULL DEFAULT 0,"
                + "  contacts_allowed INTEGER NOT NULL DEFAULT 0,"
                + "  storage_allowed  INTEGER NOT NULL DEFAULT 0,"
                + "  lobby_mode       INTEGER NOT NULL DEFAULT 0,"
                + "  allowed_sensors  TEXT    NOT NULL DEFAULT '',"
                + "  updated_ms       INTEGER NOT NULL DEFAULT 0"
                + ")"
            );
            db.execSQL(
                "CREATE TABLE usage_log ("
                + "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "  package_name TEXT    NOT NULL,"
                + "  timestamp    INTEGER NOT NULL,"
                + "  permission   TEXT    NOT NULL DEFAULT '',"
                + "  action       TEXT    NOT NULL DEFAULT '',"
                + "  extra        TEXT"
                + ")"
            );
            db.execSQL("CREATE INDEX usage_pkg_ts ON usage_log (package_name, timestamp DESC)");
            db.execSQL(
                "CREATE TABLE counters ("
                + "  name  TEXT    PRIMARY KEY,"
                + "  value INTEGER NOT NULL DEFAULT 0"
                + ")"
            );
            // Seed the counters so getCounter never returns -1
            db.execSQL("INSERT INTO counters(name, value) VALUES('"
                    + COUNTER_DENIED_PERMISSIONS + "', 0)");
            db.execSQL("INSERT INTO counters(name, value) VALUES('"
                    + COUNTER_FAKED_IDENTIFIERS  + "', 0)");
            db.execSQL("INSERT INTO counters(name, value) VALUES('"
                    + COUNTER_NETWORK_GRANTS     + "', 0)");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int from, int to) {
            // v1 → v2 migrations live here when we cut alpha-2.
            Slog.w(TAG, "onUpgrade from " + from + " to " + to + " — no migrations yet");
        }
    }
}
