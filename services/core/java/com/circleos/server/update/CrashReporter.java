/*
 * Copyright (C) 2026 Circle OS contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

package com.circleos.server.update;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.DropBoxManager;
import android.util.Slog;

import com.android.server.SystemService;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Circle OS crash reporter. Listens for {@link DropBoxManager} crash/ANR entries
 * and keeps a compact, <b>on-device</b> ledger of what crashed and when.
 *
 * <p>Blind-to-us by design: only the dropbox tag, process/package, and timestamp
 * are recorded — never the full stack trace, logs, or any payload — and nothing
 * leaves the device. The ledger backs a "Stability" view in CircleSettings and
 * lets the OTA pipeline (CircleUpdateService) know, locally, that a build is
 * unstable so a user can choose to roll back. There is no automatic upload.
 */
public final class CrashReporter extends SystemService {

    private static final String TAG = "CircleCrash";

    private static final File DIR = new File("/data/system/circle/crashes");
    private static final File LEDGER = new File(DIR, "ledger.tsv");
    private static final int MAX_ROWS = 500;

    /** Dropbox tags we treat as a stability event. */
    private static final List<String> TAGS = Arrays.asList(
            "system_server_crash", "system_server_anr", "system_server_watchdog",
            "data_app_crash", "data_app_anr", "data_app_native_crash",
            "system_app_crash", "system_app_anr");

    private final Context mContext;

    public CrashReporter(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        // Nothing to publish; this service only observes.
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase != PHASE_BOOT_COMPLETED) return;
        IntentFilter f = new IntentFilter(DropBoxManager.ACTION_DROPBOX_ENTRY_ADDED);
        mContext.registerReceiver(mReceiver, f);
        Slog.i(TAG, "watching dropbox for stability events");
    }

    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String tag = intent.getStringExtra(DropBoxManager.EXTRA_TAG);
            long time = intent.getLongExtra(DropBoxManager.EXTRA_TIME, System.currentTimeMillis());
            if (tag == null || !TAGS.contains(tag)) return;
            record(tag, time);
        }
    };

    /** Ledger row: time \t tag \t kind  (no stack, no payload). */
    private void record(String tag, long time) {
        try {
            if (!DIR.exists() && !DIR.mkdirs()) {
                Slog.e(TAG, "could not create " + DIR);
                return;
            }
            DIR.setReadable(false, false);
            String kind = tag.contains("anr") ? "anr"
                    : tag.contains("native") ? "native"
                    : tag.contains("watchdog") ? "watchdog" : "crash";
            try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(LEDGER, true), StandardCharsets.UTF_8))) {
                w.write(time + "\t" + tag + "\t" + kind);
                w.newLine();
            }
            LEDGER.setReadable(true, true);
            trim();
            Slog.i(TAG, "recorded stability event: " + tag);
        } catch (Throwable t) {
            Slog.e(TAG, "record failed", t);
        }
    }

    /** Keep the ledger bounded — drop the oldest rows past MAX_ROWS. */
    private void trim() {
        try {
            if (!LEDGER.exists()) return;
            List<String> lines = java.nio.file.Files.readAllLines(
                    LEDGER.toPath(), StandardCharsets.UTF_8);
            if (lines.size() <= MAX_ROWS) return;
            List<String> keep = lines.subList(lines.size() - MAX_ROWS, lines.size());
            try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(LEDGER, false), StandardCharsets.UTF_8))) {
                for (String l : keep) { w.write(l); w.newLine(); }
            }
        } catch (Throwable t) {
            Slog.w(TAG, "trim failed", t);
        }
    }
}
