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

import android.content.Context;
import android.util.Slog;

import com.android.server.SystemService;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Circle OS device enrollment. On first boot it mints a <b>device-rooted but
 * non-identifying</b> enrollment id — 256 random bits, <em>not</em> the IMEI,
 * serial, or ANDROID_ID — persisted on-device. This is the OS owning its own
 * identity with no Google account in the loop (the "ownership / no lock-in"
 * pillar).
 *
 * <p>From that id it derives a stable staged-rollout bucket (0-99). The OTA flow
 * (CircleUpdateService) reads {@code /data/system/circle/enrollment/bucket} so a
 * release can ramp 5% → 25% → 100% by bucket without ever learning <i>who</i> the
 * device is. The raw id never leaves the device.
 */
public final class DeviceEnrollment extends SystemService {

    private static final String TAG = "CircleEnroll";

    private static final File DIR = new File("/data/system/circle/enrollment");
    private static final File ID = new File(DIR, "id");
    private static final File BUCKET = new File(DIR, "bucket");

    public DeviceEnrollment(Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        // Observe-and-persist only; no binder surface.
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase != PHASE_BOOT_COMPLETED) return;
        try {
            enroll();
        } catch (Throwable t) {
            Slog.e(TAG, "enrollment failed", t);
        }
    }

    private void enroll() throws Exception {
        if (!DIR.exists() && !DIR.mkdirs()) {
            Slog.e(TAG, "could not create " + DIR);
            return;
        }
        DIR.setReadable(false, false);
        DIR.setExecutable(false, false);
        DIR.setReadable(true, true);
        DIR.setExecutable(true, true);

        String id = readId();
        if (id == null) {
            byte[] r = new byte[32];
            new SecureRandom().nextBytes(r);
            id = hex(r);
            write(ID, id);
            ID.setReadable(false, false);
            ID.setReadable(true, true); // owner (system_server) only
            Slog.i(TAG, "minted device-rooted enrollment id");
        }

        int bucket = bucketOf(id);
        write(BUCKET, Integer.toString(bucket));
        BUCKET.setReadable(false, false);
        BUCKET.setReadable(true, true);
        Slog.i(TAG, "enrolled; staged-rollout bucket=" + bucket);
    }

    /** Stable 0-99 bucket from the id; only the bucket — never the id — informs rollout. */
    private static int bucketOf(String id) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(id.getBytes(StandardCharsets.UTF_8));
        int v = ((h[0] & 0xFF) << 8) | (h[1] & 0xFF);
        return v % 100;
    }

    private String readId() {
        try {
            if (!ID.exists()) return null;
            String s = new String(Files.readAllBytes(ID.toPath()), StandardCharsets.UTF_8).trim();
            return s.isEmpty() ? null : s;
        } catch (Throwable t) {
            return null;
        }
    }

    private void write(File f, String s) throws IOException {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(f, false), StandardCharsets.UTF_8)) {
            w.write(s);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
