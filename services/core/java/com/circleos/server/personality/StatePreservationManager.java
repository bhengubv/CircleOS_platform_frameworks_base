/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.util.ArrayMap;
import android.util.Log;

import java.util.List;
import java.util.Map;

/**
 * Captures and restores soft app state across personality mode switches.
 *
 * <p>Phase 2 preserves:
 * <ul>
 *   <li>Foreground package name (so the UX can hint what was open)</li>
 *   <li>Media playback state (resumes if interrupted by mode switch)</li>
 * </ul>
 * More state (clipboard, draft text, window layout) may be added in later phases.</p>
 */
class StatePreservationManager {

    private static final String TAG = "CirclePersonality";

    /** Snapshot of device state at the moment a mode was exited. */
    private static final class ModeSnapshot {
        String  topPackage;
        boolean mediaWasPlaying;
        long    capturedAt;
    }

    private final Context        mContext;
    private final ActivityManager mAm;
    private final AudioManager   mAudio;

    private final Map<String, ModeSnapshot> mSnapshots = new ArrayMap<>();
    private boolean mEnabled = true;

    StatePreservationManager(Context context) {
        mContext = context;
        mAm      = context.getSystemService(ActivityManager.class);
        mAudio   = context.getSystemService(AudioManager.class);
    }

    // -------------------------------------------------------------------------
    // Snapshot capture
    // -------------------------------------------------------------------------

    /**
     * Captures the current device state tagged to {@code modeId}.
     * Call this before the mode is switched away from.
     */
    void captureStateForMode(String modeId) {
        if (!mEnabled || modeId == null) return;

        ModeSnapshot snap = new ModeSnapshot();
        snap.capturedAt      = System.currentTimeMillis();
        snap.mediaWasPlaying = mAudio != null && mAudio.isMusicActive();
        snap.topPackage      = getTopPackage();

        mSnapshots.put(modeId, snap);
        Log.d(TAG, "StatePreservation: captured for " + modeId
                + " pkg=" + snap.topPackage + " media=" + snap.mediaWasPlaying);
    }

    // -------------------------------------------------------------------------
    // State restoration
    // -------------------------------------------------------------------------

    /**
     * Restores soft state for {@code modeId} if a snapshot exists.
     * Call this after the mode has been activated.
     */
    void restoreStateForMode(String modeId) {
        if (!mEnabled || modeId == null) return;

        ModeSnapshot snap = mSnapshots.get(modeId);
        if (snap == null) return;

        long age = System.currentTimeMillis() - snap.capturedAt;

        // Only restore if the snapshot is fresh (< 30 minutes)
        if (age > 30 * 60 * 1000L) {
            mSnapshots.remove(modeId);
            Log.d(TAG, "StatePreservation: snapshot for " + modeId + " is stale, skipping");
            return;
        }

        if (snap.mediaWasPlaying) {
            resumeMedia();
        }

        Log.d(TAG, "StatePreservation: restored for " + modeId
                + " (age=" + (age / 1000) + "s, media=" + snap.mediaWasPlaying + ")");
    }

    // -------------------------------------------------------------------------
    // Enable / disable
    // -------------------------------------------------------------------------

    void setEnabled(boolean enabled) {
        mEnabled = enabled;
        if (!enabled) mSnapshots.clear();
        Log.i(TAG, "StatePreservation " + (enabled ? "enabled" : "disabled"));
    }

    boolean isEnabled() {
        return mEnabled;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String getTopPackage() {
        try {
            if (mAm == null) return null;
            List<ActivityManager.RunningTaskInfo> tasks =
                    mAm.getRunningTasks(1);
            if (tasks != null && !tasks.isEmpty()
                    && tasks.get(0).topActivity != null) {
                return tasks.get(0).topActivity.getPackageName();
            }
        } catch (Exception e) {
            Log.w(TAG, "getTopPackage failed: " + e.getMessage());
        }
        return null;
    }

    private void resumeMedia() {
        try {
            // Send a media play key event so the active media session resumes
            Intent play = new Intent(Intent.ACTION_MEDIA_BUTTON);
            android.view.KeyEvent keyDown = new android.view.KeyEvent(
                    android.view.KeyEvent.ACTION_DOWN,
                    android.view.KeyEvent.KEYCODE_MEDIA_PLAY);
            android.view.KeyEvent keyUp = new android.view.KeyEvent(
                    android.view.KeyEvent.ACTION_UP,
                    android.view.KeyEvent.KEYCODE_MEDIA_PLAY);
            play.putExtra(Intent.EXTRA_KEY_EVENT, keyDown);
            mContext.sendBroadcast(play);
            play.putExtra(Intent.EXTRA_KEY_EVENT, keyUp);
            mContext.sendBroadcast(play);
            Log.d(TAG, "StatePreservation: sent media resume");
        } catch (Exception e) {
            Log.w(TAG, "resumeMedia failed: " + e.getMessage());
        }
    }
}
