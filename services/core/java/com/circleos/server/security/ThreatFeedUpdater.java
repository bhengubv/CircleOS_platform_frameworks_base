/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.util.Log;

import java.io.File;

/**
 * Updates threat feeds from the Data Acuity network.
 *
 * Phase 1: checks feed age and reloads from disk if stale.
 * Phase 2: fetches from Data Acuity API and verifies signature.
 *
 * Feeds are written to /data/circle/security/feeds/ by the updater.
 * ThreatFeedDatabase is reloaded after each successful update.
 */
public class ThreatFeedUpdater {

    private static final String TAG        = "CircleFileDmz.FeedUpd";
    private static final String FEEDS_DIR  = "/data/circle/security/feeds/";
    /** Refresh if feeds older than 24 hours. */
    private static final long   MAX_AGE_MS = 24 * 60 * 60 * 1000L;

    private final ThreatFeedDatabase mDb;

    public ThreatFeedUpdater(ThreatFeedDatabase db) {
        mDb = db;
    }

    /** Update feeds if the on-disk files are stale (>24h). */
    public void updateIfStale() {
        File feedsDir = new File(FEEDS_DIR);
        if (!feedsDir.exists()) {
            feedsDir.mkdirs();
            Log.i(TAG, "Created feeds directory");
        }

        File ipFile = new File(FEEDS_DIR + "c2_ips.txt");
        long ageMs  = System.currentTimeMillis() - (ipFile.exists() ? ipFile.lastModified() : 0);

        if (ageMs > MAX_AGE_MS) {
            Log.i(TAG, "Feeds stale (" + ageMs / 3600000 + "h), updating...");
            forceUpdate();
        } else {
            Log.i(TAG, "Feeds fresh — reload from disk");
            mDb.reload();
        }
    }

    /** Force immediate feed update regardless of age. */
    public void forceUpdate() {
        // Phase 1: reload from disk (feeds placed by OTA or manual push)
        // Phase 2: fetch from Data Acuity API, verify Ed25519 signature, write to disk
        mDb.reload();
        Log.i(TAG, "Feed update complete (Phase 1: disk reload)");
    }
}
