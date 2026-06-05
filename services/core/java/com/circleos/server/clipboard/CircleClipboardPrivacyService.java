/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.clipboard;

import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.clipboard.ICircleClipboardPrivacyService;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Circle OS Clipboard Privacy Service.
 *
 * <p>Observes the primary clip via {@link ClipboardManager.OnPrimaryClipChangedListener}
 * and exposes per-package "block background reads" state.
 *
 * <p><b>Why we don't intercept reads:</b> AOSP's ClipboardService
 * already gates background reads on {@code AppOpsManager.OP_READ_CLIPBOARD}
 * combined with a foreground-process check (since Android 12). We do
 * not duplicate that enforcement here -- doing so from a parallel
 * service would either be redundant (if AOSP allowed the read) or
 * impossible (we can't undeny what AOSP already denied). What we
 * provide is the per-app policy surface that the dashboard renders
 * and that future Circle hooks into ClipboardService.cpp will read.
 *
 * <p>For the alpha-1 surface this is enough: the dashboard shows
 * "Background clipboard blocked: ON" for each app, and the underlying
 * AOSP enforcement (Android 12+ default) keeps the promise true.
 */
public final class CircleClipboardPrivacyService extends SystemService {

    private static final String TAG = "CircleClipboardPrivacy";

    public static final String SERVICE_NAME = "circle.clipboard_privacy";

    private static final String PREFS_FILE      = "circle_clipboard_privacy";
    private static final String KEY_PREFIX_BLOCK = "block_";

    /** Circle policy default: block background reads for every package. */
    private static final boolean DEFAULT_BLOCKED = true;

    private final Context           mContext;
    private final ClipBinder        mBinder = new ClipBinder();
    private final SharedPreferences mPrefs;

    private final AtomicInteger mClipChangeCount = new AtomicInteger(0);
    private final AtomicLong    mLastClipChangeMs = new AtomicLong(0L);

    private ClipboardManager mClipboard;

    public CircleClipboardPrivacyService(Context context) {
        super(context);
        mContext = context;
        final Context dp = context.createDeviceProtectedStorageContext();
        mPrefs = dp.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE);
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
        attachClipboardListener();
    }

    private void attachClipboardListener() {
        try {
            mClipboard = mContext.getSystemService(ClipboardManager.class);
            if (mClipboard == null) {
                Slog.w(TAG, "ClipboardManager unavailable -- clip change tracking disabled");
                return;
            }
            mClipboard.addPrimaryClipChangedListener(this::onPrimaryClipChanged);
            Slog.i(TAG, "Attached primary clip listener");
        } catch (Throwable t) {
            Slog.w(TAG, "addPrimaryClipChangedListener failed", t);
        }
    }

    private void onPrimaryClipChanged() {
        mClipChangeCount.incrementAndGet();
        mLastClipChangeMs.set(System.currentTimeMillis());
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class ClipBinder extends ICircleClipboardPrivacyService.Stub {

        @Override
        public int getClipChangeCount() {
            enforceQuery();
            return mClipChangeCount.get();
        }

        @Override
        public long getLastClipChangeMs() {
            enforceQuery();
            return mLastClipChangeMs.get();
        }

        @Override
        public boolean isBackgroundReadBlocked(String packageName) {
            enforceQuery();
            if (TextUtils.isEmpty(packageName)) return DEFAULT_BLOCKED;
            return mPrefs.getBoolean(KEY_PREFIX_BLOCK + packageName, DEFAULT_BLOCKED);
        }

        @Override
        public void setBackgroundReadBlocked(String packageName, boolean blocked) {
            enforceManage();
            if (TextUtils.isEmpty(packageName)) return;
            mPrefs.edit().putBoolean(KEY_PREFIX_BLOCK + packageName, blocked).apply();
            Slog.i(TAG, "Background clipboard read for " + packageName
                    + (blocked ? " BLOCKED" : " ALLOWED"));
        }
    }

    private void enforceQuery() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.QUERY_PRIVACY.
    }

    private void enforceManage() {
        final int uid = Binder.getCallingUid();
        if (uid == android.os.Process.SYSTEM_UID || uid == android.os.Process.ROOT_UID) return;
        // TODO: gate on za.co.circleos.permission.MANAGE_PRIVACY.
    }
}
