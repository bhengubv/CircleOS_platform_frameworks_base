/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

package com.circleos.server.security;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Binder;
import android.os.IBinder;
import android.util.Slog;

import com.android.server.SystemService;

import za.co.circleos.security.ICircleQuarantine;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Circle OS security system service. Hosts the {@code circle.quarantine} binder
 * ({@link ICircleQuarantine}); the TrafficLobby VPN calls
 * {@link ICircleQuarantine#quarantineFile} when its behaviour detector decides an
 * installed app is exfiltrating data.
 *
 * <p>Quarantine moves the offending file out of any executable location into
 * {@code /data/system/circle/quarantine}, strips its execute bits, and appends a
 * tab-separated row to the security ledger so CircleSettings → Security can show
 * (and later restore) it. The user gets a follow-up notification. Calls are
 * idempotent per source path.
 */
public final class CircleSecurityService extends SystemService {

    private static final String TAG = "CircleSecurity";

    public static final String SERVICE_QUARANTINE = "circle.quarantine";

    private static final String PERM_QUARANTINE =
            "android.permission.CIRCLE_SECURITY_QUARANTINE";

    private static final File QDIR = new File("/data/system/circle/quarantine");
    private static final File LEDGER = new File(QDIR, "ledger.tsv");

    private static final String CHANNEL_ID = "circle_security";
    private static final int NOTIF_BASE = 7100;

    private final Context mContext;
    private final Object mLock = new Object();

    public CircleSecurityService(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        publishBinderService(SERVICE_QUARANTINE, mBinder);
        Slog.i(TAG, "circle.quarantine published");
    }

    private final IBinder mBinder = new ICircleQuarantine.Stub() {
        @Override
        public void quarantineFile(String sourceDir, String reason) {
            mContext.enforceCallingOrSelfPermission(PERM_QUARANTINE, "quarantineFile");
            if (sourceDir == null || sourceDir.isEmpty()) {
                Slog.w(TAG, "quarantineFile: empty sourceDir, ignoring");
                return;
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                doQuarantine(sourceDir, reason == null ? "" : reason);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    };

    private void doQuarantine(String sourceDir, String reason) {
        synchronized (mLock) {
            try {
                File src = new File(sourceDir);
                if (!QDIR.exists() && !QDIR.mkdirs()) {
                    Slog.e(TAG, "could not create quarantine dir " + QDIR);
                    return;
                }
                QDIR.setReadable(false, false);
                QDIR.setExecutable(false, false);

                // Idempotent: if we've already recorded this exact path, no-op.
                if (alreadyQuarantined(sourceDir)) {
                    Slog.i(TAG, "already quarantined, skipping: " + sourceDir);
                    return;
                }
                if (!src.exists()) {
                    // The file may already be gone (app uninstalled). Still record the event.
                    Slog.w(TAG, "source not present, recording event only: " + sourceDir);
                    record(sourceDir, "", reason);
                    notifyUser(src.getName(), reason);
                    return;
                }

                String stamp = Long.toString(System.currentTimeMillis());
                File dest = new File(QDIR, sanitize(src.getName()) + "." + stamp + ".bin");
                boolean moved = move(src, dest);
                if (!moved) {
                    Slog.e(TAG, "failed to move " + sourceDir);
                    return;
                }
                // Strip all execute bits so a quarantined apk can never run.
                dest.setExecutable(false, false);
                dest.setReadable(false, false);
                dest.setWritable(false, false);
                dest.setReadable(true, true); // owner (system) read only

                record(sourceDir, dest.getAbsolutePath(), reason);
                notifyUser(src.getName(), reason);
                Slog.i(TAG, "quarantined " + sourceDir + " -> " + dest.getAbsolutePath());
            } catch (Throwable t) {
                Slog.e(TAG, "quarantine failed for " + sourceDir, t);
            }
        }
    }

    private boolean move(File src, File dest) {
        try {
            Path s = src.toPath();
            Path d = dest.toPath();
            try {
                Files.move(s, d, StandardCopyOption.ATOMIC_MOVE);
                return true;
            } catch (IOException atomicFailed) {
                // Cross-filesystem or unsupported: fall back to copy + delete.
                Files.copy(s, d, StandardCopyOption.REPLACE_EXISTING);
                Files.deleteIfExists(s);
                return true;
            }
        } catch (Throwable t) {
            Slog.e(TAG, "move failed", t);
            return false;
        }
    }

    private boolean alreadyQuarantined(String sourceDir) {
        if (!LEDGER.exists()) return false;
        try {
            for (String line : Files.readAllLines(LEDGER.toPath(), StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab > 0 && line.indexOf('\t', tab + 1) > 0) {
                    String origin = line.substring(tab + 1, line.indexOf('\t', tab + 1));
                    if (sourceDir.equals(origin)) return true;
                }
            }
        } catch (Throwable t) {
            Slog.w(TAG, "ledger read failed", t);
        }
        return false;
    }

    /** Ledger row: time \t originalPath \t quarantinedPath \t reason */
    private void record(String origin, String dest, String reason) {
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(LEDGER, true), StandardCharsets.UTF_8))) {
            w.write(System.currentTimeMillis()
                    + "\t" + clean(origin)
                    + "\t" + clean(dest)
                    + "\t" + clean(reason));
            w.newLine();
        } catch (Throwable t) {
            Slog.e(TAG, "ledger write failed", t);
        }
        LEDGER.setReadable(true, true);
    }

    private void notifyUser(String name, String reason) {
        try {
            NotificationManager nm = mContext.getSystemService(NotificationManager.class);
            if (nm == null) return;
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                NotificationChannel ch = new NotificationChannel(
                        CHANNEL_ID, "Circle Security", NotificationManager.IMPORTANCE_HIGH);
                ch.setDescription("Quarantine and security-ledger alerts");
                nm.createNotificationChannel(ch);
            }
            Notification n = new Notification.Builder(mContext, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setContentTitle("App quarantined")
                    .setContentText(reason.isEmpty()
                            ? (name + " was isolated for suspicious behaviour")
                            : reason)
                    .setStyle(new Notification.BigTextStyle().bigText(
                            (reason.isEmpty() ? name : reason)
                            + "\n\nReview or restore in Settings → Security."))
                    .setAutoCancel(true)
                    .build();
            nm.notify(NOTIF_BASE + Math.abs(name.hashCode() % 800), n);
        } catch (Throwable t) {
            Slog.w(TAG, "notify failed", t);
        }
    }

    private static String sanitize(String name) {
        return name.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static String clean(String s) {
        return s == null ? "" : s.replace('\t', ' ').replace('\n', ' ');
    }
}
