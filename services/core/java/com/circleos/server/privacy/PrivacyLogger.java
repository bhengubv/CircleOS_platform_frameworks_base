/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Slog;

import android.circleos.PermissionUsageRecord;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Async writer for the Circle OS privacy audit log.
 *
 * All writes are dispatched to a dedicated HandlerThread so callers
 * (e.g. PrivacyRulesEngine) are never blocked.
 *
 * Database: /data/circle/privacy/audit.db
 * Retention: 30 days (cleaned up on open and via scheduled job).
 *
 * NOTE: Production builds should replace SQLiteDatabase with SQLCipher
 * (net.zetetic:android-database-sqlcipher) for at-rest encryption.
 */
public class PrivacyLogger {

    private static final String TAG = "CirclePrivacyLogger";

    private static final String DB_PATH  = "/data/circle/privacy/audit.db";
    private static final String DB_NAME  = "audit";
    private static final int    DB_VER   = 1;

    private static final long RETENTION_MS = TimeUnit.DAYS.toMillis(30);

    // Database schema
    private static final String TABLE = "audit_log";
    private static final String COL_ID      = "id";
    private static final String COL_TS      = "timestamp";
    private static final String COL_PKG     = "package_name";
    private static final String COL_PERM    = "permission";
    private static final String COL_ACTION  = "action";
    private static final String COL_EXTRA   = "extra";

    private static final String CREATE_TABLE =
            "CREATE TABLE IF NOT EXISTS " + TABLE + " (" +
            COL_ID     + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
            COL_TS     + " INTEGER NOT NULL, " +
            COL_PKG    + " TEXT NOT NULL, " +
            COL_PERM   + " TEXT NOT NULL, " +
            COL_ACTION + " TEXT NOT NULL, " +
            COL_EXTRA  + " TEXT" +
            ")";

    private static final String IDX_TS  =
            "CREATE INDEX IF NOT EXISTS idx_ts  ON " + TABLE + "(" + COL_TS  + ")";
    private static final String IDX_PKG =
            "CREATE INDEX IF NOT EXISTS idx_pkg ON " + TABLE + "(" + COL_PKG + ")";

    // ---- Helper ----

    private static class AuditDbHelper extends SQLiteOpenHelper {
        AuditDbHelper(Context ctx) {
            super(ctx, DB_PATH, null, DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(CREATE_TABLE);
            db.execSQL(IDX_TS);
            db.execSQL(IDX_PKG);
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            // Future migrations go here.
        }
    }

    // ---- Fields ----

    private final HandlerThread mThread;
    private final Handler       mHandler;
    private final AuditDbHelper mHelper;

    public PrivacyLogger(Context context) {
        ensureDataDir();

        mHelper = new AuditDbHelper(context);

        mThread = new HandlerThread("CirclePrivacyLogger");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());

        // Purge old records asynchronously on startup.
        mHandler.post(this::purgeOldRecords);
    }

    // ---- Public API ----

    /**
     * Asynchronously appends a record to the audit log.
     * Returns immediately; never blocks the caller.
     */
    public void log(String packageName, String permission, String action, String extra) {
        final long now = System.currentTimeMillis();
        mHandler.post(() -> {
            try {
                SQLiteDatabase db = mHelper.getWritableDatabase();
                ContentValues cv = new ContentValues(5);
                cv.put(COL_TS,     now);
                cv.put(COL_PKG,    packageName);
                cv.put(COL_PERM,   permission);
                cv.put(COL_ACTION, action);
                cv.put(COL_EXTRA,  extra);
                db.insertOrThrow(TABLE, null, cv);
            } catch (Exception e) {
                Slog.e(TAG, "Failed to write audit record", e);
            }
        });
    }

    /**
     * Synchronously reads audit records for a package newer than {@code sinceMs}.
     * Returns at most 1000 records, ordered by timestamp descending.
     * Safe to call from a binder thread.
     */
    public List<PermissionUsageRecord> query(String packageName, long sinceMs) {
        List<PermissionUsageRecord> results = new ArrayList<>();
        try {
            SQLiteDatabase db = mHelper.getReadableDatabase();
            try (Cursor c = db.query(
                    TABLE,
                    new String[]{COL_TS, COL_PKG, COL_PERM, COL_ACTION, COL_EXTRA},
                    COL_PKG + "=? AND " + COL_TS + ">?",
                    new String[]{packageName, String.valueOf(sinceMs)},
                    null, null,
                    COL_TS + " DESC",
                    "1000")) {
                while (c.moveToNext()) {
                    PermissionUsageRecord r = new PermissionUsageRecord();
                    r.timestamp   = c.getLong(0);
                    r.packageName = c.getString(1);
                    r.permission  = c.getString(2);
                    r.action      = c.getString(3);
                    r.extra       = c.getString(4);
                    results.add(r);
                }
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to query audit log", e);
        }
        return results;
    }

    // ---- Private ----

    /** Deletes records older than RETENTION_MS. */
    private void purgeOldRecords() {
        try {
            SQLiteDatabase db = mHelper.getWritableDatabase();
            long cutoff = System.currentTimeMillis() - RETENTION_MS;
            int deleted = db.delete(TABLE, COL_TS + "<?", new String[]{String.valueOf(cutoff)});
            if (deleted > 0) {
                Slog.i(TAG, "Purged " + deleted + " audit records older than 30 days");
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to purge old audit records", e);
        }
    }

    private static void ensureDataDir() {
        File dir = new File("/data/circle/privacy");
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
    }
}
