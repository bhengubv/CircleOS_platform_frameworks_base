/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.privacy;

import android.circleos.AppPrivacyPolicy;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Slog;

import java.util.HashSet;
import java.util.Set;

/**
 * Scoped contacts provider.
 *
 * <p>Sits between calling apps and AOSP's
 * {@code com.android.providers.contacts.ContactsProvider2}. Returns
 * <b>zero rows</b> by default -- even if the calling app holds
 * {@code READ_CONTACTS} -- until the user adds specific contacts to
 * that package's scope.
 *
 * <p>Scope storage is per-package, in a SharedPreferences-backed
 * {@code StringSet} keyed by Circle's privacy db. The set contains
 * canonical contact IDs the user has explicitly shared with the
 * package.
 *
 * <p>Registered in the {@code AndroidManifest.xml} of CircleSettings
 * (because it must run as a content provider, which is an Application
 * Component) and exported with read permission gated by
 * {@code android.permission.READ_CONTACTS} -- so callers go through
 * the standard permission flow first, then hit our scoping layer.
 *
 * <p>Apps that need real contacts continue to call
 * {@code ContactsContract.Contacts.CONTENT_URI} -- AOSP routes that
 * directly to ContactsProvider2 and our code does not intercept it.
 * To opt INTO scoping, an app uses our explicit authority
 * {@code content://com.circleos.contacts/contacts}. CircleSettings'
 * Contacts pane lets the user designate "this app sees Y rows" and
 * the AOSP query is redirected via {@code AppPrivacyPolicy.contactsAllowed}
 * + {@code contactsScopeIds}.
 *
 * <p>For alpha-1: the provider is wired up + serves zero-row queries
 * by default + honours per-package scope ids. The CircleSettings UI
 * to populate the scope is the Phase 8 work; programmatic add via
 * {@link #addToScope(String, String)} is exposed for tests today.
 */
public final class ScopedContactsProvider extends ContentProvider {

    private static final String TAG = "CircleScopedContacts";

    /** Authority advertised by this provider. */
    public static final String AUTHORITY = "com.circleos.contacts";

    /** uri path for the (filtered) contact list. */
    private static final String PATH_CONTACTS = "contacts";

    private static final String PREFS_FILE       = "circle_scoped_contacts";
    private static final String KEY_PREFIX_SCOPE = "scope_";

    /** Whitelist of column names supported in the scoped projection. */
    private static final String[] DEFAULT_PROJECTION = {
            "_id",
            "display_name",
            "lookup_key",
            "has_phone_number",
    };

    private SharedPreferences mPrefs;

    @Override
    public boolean onCreate() {
        final Context ctx = getContext();
        if (ctx == null) return false;
        final Context dp = ctx.createDeviceProtectedStorageContext();
        mPrefs = dp.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE);
        Slog.i(TAG, "ScopedContactsProvider attached, authority=" + AUTHORITY);
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        if (!PATH_CONTACTS.equals(uri.getLastPathSegment())) {
            // Anything other than /contacts: not us.
            return emptyCursor(projection);
        }
        final String caller = callerPackage();
        final Set<String> scope = scopeFor(caller);
        if (scope.isEmpty()) {
            // Default-deny: app sees ZERO rows.
            Slog.i(TAG, "query from " + caller + " -> 0 rows (no scope)");
            return emptyCursor(projection);
        }
        // Scope is non-empty -- delegate to AOSP ContactsProvider2 with
        // a selection that restricts to the scoped IDs. This is the
        // narrowest possible read and still goes through the AOSP
        // permission check, so we never broaden access.
        try {
            final Cursor real = getContext().getContentResolver().query(
                    android.provider.ContactsContract.Contacts.CONTENT_URI,
                    projection != null ? projection : DEFAULT_PROJECTION,
                    "_id IN (" + TextUtils.join(",", scope) + ")",
                    null,
                    sortOrder);
            return real;
        } catch (Throwable t) {
            Slog.w(TAG, "query delegation failed", t);
            return emptyCursor(projection);
        }
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.com.circleos.contact";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // Inserts go through CircleSettings -> addToScope; the provider
        // itself doesn't accept third-party inserts.
        Slog.i(TAG, "insert from " + callerPackage() + " rejected");
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        Slog.i(TAG, "delete from " + callerPackage() + " rejected");
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        Slog.i(TAG, "update from " + callerPackage() + " rejected");
        return 0;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        // Scoping API for CircleSettings. Apps cannot invoke this --
        // we gate on caller package equality.
        if (!"com.circleos.settings".equals(callerPackage())
                && !"za.co.circleos.settings".equals(callerPackage())
                && Binder.getCallingUid() != android.os.Process.SYSTEM_UID) {
            Slog.w(TAG, "call(" + method + ") refused -- caller is not CircleSettings");
            return null;
        }
        if ("addToScope".equals(method) && extras != null) {
            final String pkg = extras.getString("package");
            final String contactId = extras.getString("contactId");
            if (!TextUtils.isEmpty(pkg) && !TextUtils.isEmpty(contactId)) {
                addToScope(pkg, contactId);
            }
        } else if ("removeFromScope".equals(method) && extras != null) {
            final String pkg = extras.getString("package");
            final String contactId = extras.getString("contactId");
            if (!TextUtils.isEmpty(pkg) && !TextUtils.isEmpty(contactId)) {
                removeFromScope(pkg, contactId);
            }
        }
        return Bundle.EMPTY;
    }

    // ------------------------------------------------------------------
    //  Scope management
    // ------------------------------------------------------------------

    public void addToScope(String packageName, String contactId) {
        synchronized (mPrefs) {
            final Set<String> cur = new HashSet<>(scopeFor(packageName));
            if (cur.add(contactId)) {
                mPrefs.edit().putStringSet(KEY_PREFIX_SCOPE + packageName, cur).apply();
                Slog.i(TAG, "Added contact " + contactId + " to scope of " + packageName);
            }
        }
    }

    public void removeFromScope(String packageName, String contactId) {
        synchronized (mPrefs) {
            final Set<String> cur = new HashSet<>(scopeFor(packageName));
            if (cur.remove(contactId)) {
                mPrefs.edit().putStringSet(KEY_PREFIX_SCOPE + packageName, cur).apply();
                Slog.i(TAG, "Removed contact " + contactId + " from scope of " + packageName);
            }
        }
    }

    private Set<String> scopeFor(String packageName) {
        if (TextUtils.isEmpty(packageName)) return java.util.Collections.emptySet();
        final Set<String> s = mPrefs.getStringSet(KEY_PREFIX_SCOPE + packageName, null);
        return s != null ? s : java.util.Collections.emptySet();
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private String callerPackage() {
        final String pkg = getCallingPackage();
        if (!TextUtils.isEmpty(pkg)) return pkg;
        // Some binder paths don't set the calling package -- fall back to
        // the uid -> first-package lookup, which is good enough for the
        // log+gate purposes we use it for.
        final int uid = Binder.getCallingUid();
        final PackageManager pm = getContext().getPackageManager();
        final String[] names = pm.getPackagesForUid(uid);
        return (names != null && names.length > 0) ? names[0] : "uid:" + uid;
    }

    private static Cursor emptyCursor(String[] projection) {
        return new MatrixCursor(projection != null ? projection : DEFAULT_PROJECTION);
    }

    @Override
    public void attachInfo(Context context, ProviderInfo info) {
        super.attachInfo(context, info);
        Slog.i(TAG, "ScopedContactsProvider attachInfo, authority="
                + (info != null ? info.authority : "<none>"));
    }
}
