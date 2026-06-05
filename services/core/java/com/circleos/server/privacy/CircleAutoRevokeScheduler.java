/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.circleos.server.privacy;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.util.Slog;

/**
 * Thin scheduler that posts the {@code CircleSettings AutoRevokeJobService}
 * to JobScheduler at boot. The actual auto-revoke pass runs inside the
 * CircleSettings app process (which holds REVOKE_RUNTIME_PERMISSIONS),
 * not system_server -- this class is just the trigger.
 */
final class CircleAutoRevokeScheduler {

    private static final String TAG = "CircleAutoRevoke";
    public static final int JOB_ID = 0x1C1E0001;

    private CircleAutoRevokeScheduler() { }

    static void schedule(Context context) {
        if (context == null) return;
        final JobScheduler js = context.getSystemService(JobScheduler.class);
        if (js == null) {
            Slog.w(TAG, "JobScheduler unavailable -- auto-revoke not scheduled");
            return;
        }
        // The component must point at the CircleSettings package's
        // AutoRevokeJobService. We hand-author the ComponentName to
        // avoid pulling CircleSettings onto system_server's classpath.
        final ComponentName cn = new ComponentName(
                "za.co.circleos.settings",
                "za.co.circleos.settings.AutoRevokeJobService");
        final JobInfo job = new JobInfo.Builder(JOB_ID, cn)
                .setRequiresDeviceIdle(true)
                .setPeriodic(24L * 60 * 60 * 1000)
                .setPersisted(true)
                .build();
        try {
            final int result = js.schedule(job);
            Slog.i(TAG, "AutoRevoke scheduled, result=" + result);
        } catch (IllegalArgumentException ex) {
            // CircleSettings may not be installed in some configurations
            // (engineer-only image, recovery). Log and continue -- this
            // is not fatal.
            Slog.i(TAG, "AutoRevoke schedule rejected (CircleSettings absent?): "
                    + ex.getMessage());
        }
    }
}
