/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.notification;

import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.provider.Settings;
import android.service.notification.NotificationListenerService;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.notification.ICircleNotificationPrivacyService;

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Circle OS Notification Privacy Service.
 *
 * <p>Enumerates the active {@link NotificationListenerService} bindings
 * (the highest-power "read every notification" surface on Android)
 * and provides a programmatic revoke path. The dashboard renders this
 * as a "who can read your notifications?" list and a per-row "kick"
 * button.
 *
 * <p>The underlying source-of-truth is the secure setting
 * {@code Settings.Secure.ENABLED_NOTIFICATION_LISTENERS} -- a colon-
 * separated list of {@code packageName/className} entries. We parse
 * it on every read so the dashboard is always live.
 *
 * <p>Revoking a listener mutates the same secure setting; that's the
 * exact mechanism Settings -> Apps -> Special access -> Notification
 * access uses behind its toggle. We do not call into the private
 * NotificationManagerService API for the revoke -- the public setting
 * path is enough and avoids the API drift risk on AOSP rebases.
 */
public final class CircleNotificationPrivacyService extends SystemService {

    private static final String TAG = "CircleNotificationPrivacy";

    public static final String SERVICE_NAME = "circle.notification_privacy";

    private final Context        mContext;
    private final NotifBinder    mBinder = new NotifBinder();
    private final AtomicInteger  mRevocationCount = new AtomicInteger(0);

    public CircleNotificationPrivacyService(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        Slog.i(TAG, "Publishing " + SERVICE_NAME);
        publishBinderService(SERVICE_NAME, mBinder);
    }

    // ------------------------------------------------------------------
    //  Binder
    // ------------------------------------------------------------------

    private final class NotifBinder extends ICircleNotificationPrivacyService.Stub {

        @Override
        public String getEnabledListenerPackages() {
            enforceQuery();
            final String raw = Settings.Secure.getString(
                    mContext.getContentResolver(),
                    Settings.Secure.ENABLED_NOTIFICATION_LISTENERS);
            if (TextUtils.isEmpty(raw)) return "";
            // ENABLED_NOTIFICATION_LISTENERS is a colon-separated list of
            // "pkg/ClassName" entries. We collapse to unique packages and
            // join with ';' for AIDL transport.
            final java.util.LinkedHashSet<String> pkgs = new java.util.LinkedHashSet<>();
            for (String entry : raw.split(":")) {
                if (TextUtils.isEmpty(entry)) continue;
                final ComponentName c = ComponentName.unflattenFromString(entry);
                if (c != null) pkgs.add(c.getPackageName());
            }
            return TextUtils.join(";", pkgs);
        }

        @Override
        public void revokeListener(String packageName) {
            enforceManage();
            if (TextUtils.isEmpty(packageName)) return;

            final String raw = Settings.Secure.getString(
                    mContext.getContentResolver(),
                    Settings.Secure.ENABLED_NOTIFICATION_LISTENERS);
            if (TextUtils.isEmpty(raw)) return;

            // Drop every "pkg/Class" entry whose package matches.
            final String[] parts = raw.split(":");
            final StringBuilder rewritten = new StringBuilder();
            boolean dropped = false;
            for (String entry : parts) {
                if (TextUtils.isEmpty(entry)) continue;
                final ComponentName c = ComponentName.unflattenFromString(entry);
                if (c != null && packageName.equals(c.getPackageName())) {
                    dropped = true;
                    continue;
                }
                if (rewritten.length() > 0) rewritten.append(':');
                rewritten.append(entry);
            }
            if (!dropped) {
                Slog.i(TAG, "revokeListener: " + packageName + " had no active listener");
                return;
            }
            Settings.Secure.putString(
                    mContext.getContentResolver(),
                    Settings.Secure.ENABLED_NOTIFICATION_LISTENERS,
                    rewritten.toString());
            mRevocationCount.incrementAndGet();
            Slog.i(TAG, "Revoked notification listener access for " + packageName);
        }

        @Override
        public int getRevocationCount() {
            enforceQuery();
            return mRevocationCount.get();
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
