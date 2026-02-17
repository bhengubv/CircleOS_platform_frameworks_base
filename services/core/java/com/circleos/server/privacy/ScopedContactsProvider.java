/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.privacy;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import android.os.Binder;
import android.util.Slog;

import java.io.File;

/**
 * Scoped contacts provider — wraps AOSP ContactsProvider2.
 *
 * Intercepts {@code content://com.android.contacts/} queries and filters
 * results through the contact_scopes table. An app with READ_CONTACTS only
 * sees contacts explicitly granted to it by the user or policy.
 *
 * Unscoped apps (not in contact_scopes) receive an empty cursor.
 *
 * Deployment: declared in the system process manifest alongside ContactsProvider2;
 * registered with authority "com.circleos.contacts" and wraps the standard
 * authority via a URI rewrite at the point of contact reads.
 *
 * Schema (/data/circle/privacy/contact_scopes.db):
 *   CREATE TABLE contact_scopes (
 *       package_name TEXT,
 *       contact_id   INTEGER,
 *       granted_at   INTEGER,
 *       PRIMARY KEY(package_name, contact_id)
 *   );
 */
public class ScopedContactsProvider extends ContentProvider {

    private static final String TAG     = "CircleScopedContacts";
    private static final String DB_PATH = "/data/circle/privacy/contact_scopes.db";
    private static final int    DB_VER  = 1;
    private static final String TABLE   = "contact_scopes";

    // ---- DB helper ----

    private static class ScopesDbHelper extends SQLiteOpenHelper {
        ScopesDbHelper(Context ctx) {
            super(ctx, DB_PATH, null, DB_VER);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS " + TABLE + " (" +
                "package_name TEXT NOT NULL, " +
                "contact_id   INTEGER NOT NULL, " +
                "granted_at   INTEGER NOT NULL, " +
                "PRIMARY KEY(package_name, contact_id)" +
                ")"
            );
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int old, int ver) {}
    }

    private ScopesDbHelper mDbHelper;

    // ---- ContentProvider lifecycle ----

    @Override
    public boolean onCreate() {
        ensureDataDir();
        mDbHelper = new ScopesDbHelper(getContext());
        return true;
    }

    /**
     * Filters the result of a delegated ContactsProvider2 query by the calling
     * app's contact scope.
     *
     * Steps:
     *  1. Resolve the calling app's package from its UID.
     *  2. Look up granted contact_ids in contact_scopes for that package.
     *  3. Re-query ContactsProvider2 with an IN(…) clause limiting to those IDs.
     *  4. Return the filtered cursor (or empty cursor if no grants).
     */
    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {

        int callingUid = Binder.getCallingUid();
        String callerPkg = resolvePackage(callingUid);

        if (callerPkg == null) {
            Slog.w(TAG, "query: cannot resolve calling package for uid=" + callingUid);
            return emptyCursor(projection);
        }

        long[] grantedIds = getGrantedContactIds(callerPkg);
        if (grantedIds.length == 0) {
            Slog.d(TAG, "query: no contact grants for " + callerPkg + " — returning empty");
            return emptyCursor(projection);
        }

        // Delegate to ContactsProvider2 with ID restriction
        StringBuilder inClause = new StringBuilder("_id IN (");
        for (int i = 0; i < grantedIds.length; i++) {
            if (i > 0) inClause.append(',');
            inClause.append(grantedIds[i]);
        }
        inClause.append(')');

        String combinedSelection = selection == null
                ? inClause.toString()
                : "(" + selection + ") AND " + inClause;

        return getContext().getContentResolver().query(
                toContactsUri(uri), projection, combinedSelection, selectionArgs, sortOrder);
    }

    @Override
    public String getType(Uri uri) {
        return getContext().getContentResolver().getType(toContactsUri(uri));
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new SecurityException("Circle ScopedContactsProvider is read-only via this authority");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new SecurityException("Circle ScopedContactsProvider is read-only via this authority");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new SecurityException("Circle ScopedContactsProvider is read-only via this authority");
    }

    // ---- Public scope management (called by CirclePrivacyManagerService) ----

    /** Grants access to a specific contact for a package. */
    public void grantContact(String packageName, long contactId) {
        try {
            SQLiteDatabase db = mDbHelper.getWritableDatabase();
            ContentValues cv = new ContentValues(3);
            cv.put("package_name", packageName);
            cv.put("contact_id",   contactId);
            cv.put("granted_at",   System.currentTimeMillis());
            db.insertWithOnConflict(TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
        } catch (Exception e) {
            Slog.e(TAG, "grantContact failed", e);
        }
    }

    /** Revokes access to a specific contact for a package. */
    public void revokeContact(String packageName, long contactId) {
        try {
            SQLiteDatabase db = mDbHelper.getWritableDatabase();
            db.delete(TABLE, "package_name=? AND contact_id=?",
                    new String[]{packageName, String.valueOf(contactId)});
        } catch (Exception e) {
            Slog.e(TAG, "revokeContact failed", e);
        }
    }

    // ---- Private ----

    private long[] getGrantedContactIds(String packageName) {
        try {
            SQLiteDatabase db = mDbHelper.getReadableDatabase();
            try (Cursor c = db.query(TABLE, new String[]{"contact_id"},
                    "package_name=?", new String[]{packageName},
                    null, null, null)) {
                long[] ids = new long[c.getCount()];
                int i = 0;
                while (c.moveToNext()) ids[i++] = c.getLong(0);
                return ids;
            }
        } catch (Exception e) {
            Slog.e(TAG, "getGrantedContactIds failed", e);
            return new long[0];
        }
    }

    private String resolvePackage(int uid) {
        String[] pkgs = getContext().getPackageManager().getPackagesForUid(uid);
        return (pkgs != null && pkgs.length > 0) ? pkgs[0] : null;
    }

    /** Rewrites the Circle-authority URI to the standard contacts authority. */
    private static Uri toContactsUri(Uri uri) {
        return uri.buildUpon()
                .authority("com.android.contacts")
                .build();
    }

    private static Cursor emptyCursor(String[] projection) {
        return new MatrixCursor(projection != null ? projection : new String[]{"_id"});
    }

    private static void ensureDataDir() {
        File dir = new File("/data/circle/privacy");
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
    }
}
