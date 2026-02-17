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
import android.net.Uri;
import android.os.Binder;
import android.util.Slog;

import java.io.File;

/**
 * Enforces Storage Access Framework restrictions for Circle OS.
 *
 * Key policies:
 *  1. {@code MANAGE_EXTERNAL_STORAGE} is disabled — never granted.
 *  2. {@code ACTION_OPEN_DOCUMENT_TREE} for root paths (/, /sdcard) is blocked.
 *  3. Per-app file grants are tracked in SQLite; access outside explicit grants
 *     is denied at the provider level.
 *
 * This class is instantiated by CirclePrivacyManagerService and called by hooks
 * in MediaProvider and ExternalStorageProvider (patched in frameworks/base fork).
 *
 * Schema (/data/circle/privacy/storage_grants.db):
 *   CREATE TABLE file_grants (
 *       package_name TEXT NOT NULL,
 *       uri          TEXT NOT NULL,
 *       granted_at   INTEGER NOT NULL,
 *       PRIMARY KEY(package_name, uri)
 *   );
 */
public class ScopedStorageProvider {

    private static final String TAG     = "CircleScopedStorage";
    private static final String DB_PATH = "/data/circle/privacy/storage_grants.db";
    private static final int    DB_VER  = 1;
    private static final String TABLE   = "file_grants";
    private static final String COL_PKG = "package_name";
    private static final String COL_URI = "uri";
    private static final String COL_TS  = "granted_at";

    // Root paths that are never grantable via ACTION_OPEN_DOCUMENT_TREE.
    private static final String[] BLOCKED_ROOTS = {"/", "/sdcard", "/storage/emulated/0"};

    // ---- DB helper ----

    private static class StorageGrantsDbHelper extends SQLiteOpenHelper {
        StorageGrantsDbHelper(Context ctx) {
            super(ctx, DB_PATH, null, DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS " + TABLE + " (" +
                COL_PKG + " TEXT NOT NULL, " +
                COL_URI + " TEXT NOT NULL, " +
                COL_TS  + " INTEGER NOT NULL, " +
                "PRIMARY KEY(" + COL_PKG + ", " + COL_URI + ")" +
                ")"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int old, int ver) {}
    }

    private final Context              mContext;
    private final StorageGrantsDbHelper mDbHelper;

    public ScopedStorageProvider(Context context) {
        mContext = context;
        ensureDataDir();
        mDbHelper = new StorageGrantsDbHelper(context);
    }

    // ---- Public API ----

    /**
     * Returns true if the calling UID may access the given URI.
     * Called from MediaProvider and ExternalStorageProvider hooks.
     */
    public boolean checkAccess(int callingUid, Uri uri) {
        String pkg = resolvePackage(callingUid);
        if (pkg == null) return false;

        if (isBlockedRoot(uri)) {
            Slog.d(TAG, "checkAccess: blocked root URI for " + pkg + ": " + uri);
            return false;
        }

        return hasGrant(pkg, uri.toString());
    }

    /**
     * Grants file/directory access to a package for the given URI.
     * Called when the user grants access via the SAF picker.
     */
    public void grantUri(String packageName, Uri uri) {
        if (isBlockedRoot(uri)) {
            Slog.w(TAG, "grantUri: attempt to grant blocked root " + uri + " to " + packageName);
            return;
        }
        try {
            SQLiteDatabase db = mDbHelper.getWritableDatabase();
            ContentValues cv = new ContentValues(3);
            cv.put(COL_PKG, packageName);
            cv.put(COL_URI, uri.toString());
            cv.put(COL_TS,  System.currentTimeMillis());
            db.insertWithOnConflict(TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
            Slog.i(TAG, "Storage grant: " + packageName + " → " + uri);
        } catch (Exception e) {
            Slog.e(TAG, "grantUri failed", e);
        }
    }

    /** Revokes a previously granted URI for the package. */
    public void revokeUri(String packageName, Uri uri) {
        try {
            SQLiteDatabase db = mDbHelper.getWritableDatabase();
            db.delete(TABLE, COL_PKG + "=? AND " + COL_URI + "=?",
                    new String[]{packageName, uri.toString()});
        } catch (Exception e) {
            Slog.e(TAG, "revokeUri failed", e);
        }
    }

    /**
     * Returns false always — MANAGE_EXTERNAL_STORAGE is permanently disabled.
     * Hook this into PackageManager permission grant to enforce.
     */
    public boolean isManageExternalStorageAllowed(String packageName) {
        Slog.d(TAG, "MANAGE_EXTERNAL_STORAGE permanently disabled for " + packageName);
        return false;
    }

    // ---- Private ----

    private boolean hasGrant(String packageName, String uriString) {
        try {
            SQLiteDatabase db = mDbHelper.getReadableDatabase();
            try (Cursor c = db.query(TABLE, new String[]{COL_PKG},
                    COL_PKG + "=? AND " + COL_URI + "=?",
                    new String[]{packageName, uriString},
                    null, null, null)) {
                return c.moveToFirst();
            }
        } catch (Exception e) {
            Slog.e(TAG, "hasGrant query failed", e);
            return false;
        }
    }

    private static boolean isBlockedRoot(Uri uri) {
        if (uri == null) return false;
        String path = uri.getPath();
        if (path == null) return false;
        for (String root : BLOCKED_ROOTS) {
            if (path.equals(root) || path.equals(root + "/")) return true;
        }
        return false;
    }

    private String resolvePackage(int uid) {
        String[] pkgs = mContext.getPackageManager().getPackagesForUid(uid);
        return (pkgs != null && pkgs.length > 0) ? pkgs[0] : null;
    }

    private static void ensureDataDir() {
        File dir = new File("/data/circle/privacy");
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
    }
}
