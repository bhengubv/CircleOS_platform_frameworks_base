/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.os.SystemProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Utilities for querying and tracking A/B (seamless) OTA slot state.
 *
 * <h3>A/B overview</h3>
 * Android A/B devices have two firmware slots — {@code _a} and {@code _b}.
 * The bootloader boots from one slot while {@link android.os.UpdateEngine}
 * writes the new payload into the other (inactive) slot.  After a successful
 * boot into the new slot, it is marked "successful" by the boot control HAL.
 *
 * <h3>Slot properties</h3>
 * <ul>
 *   <li>{@code ro.boot.slot_suffix}  — {@code "_a"} or {@code "_b"} for A/B devices;
 *       empty on legacy (non-A/B) devices.</li>
 *   <li>{@code ro.boot.slot_additional_status} — optional extra status.</li>
 * </ul>
 *
 * <h3>Rollback detection</h3>
 * Before applying an update, {@link #recordUpdateStart(String)} writes the
 * target version to a state file.  On the next boot the service checks whether
 * the running version matches the recorded target via {@link #checkForStuckUpdate()};
 * if not, the previous attempt is considered failed and the record is cleared.
 */
public class AbSlotManager {

    private static final String TAG = "AbSlotManager";

    private static final String STATE_FILE =
            "/data/system/circleos_update/ab_update_state.json";

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Returns {@code true} if this device uses A/B seamless updates (has a
     * non-empty {@code ro.boot.slot_suffix} property).
     */
    public static boolean isAbDevice() {
        String suffix = SystemProperties.get("ro.boot.slot_suffix", "");
        return !suffix.isEmpty();
    }

    /**
     * Returns the currently-booted slot suffix ({@code "_a"}, {@code "_b"}, or
     * an empty string on non-A/B devices).
     */
    public static String getCurrentSlot() {
        return SystemProperties.get("ro.boot.slot_suffix", "");
    }

    /**
     * Returns the inactive (target-for-update) slot suffix.
     * Returns {@code "_a"} when currently on {@code "_b"} and vice-versa.
     * Returns an empty string on non-A/B devices.
     */
    public static String getInactiveSlot() {
        String current = getCurrentSlot();
        if ("_a".equals(current)) return "_b";
        if ("_b".equals(current)) return "_a";
        return "";
    }

    /**
     * Returns a human-readable status string for the inactive slot.
     *
     * <p>Reads {@code ro.boot.slot_inactive_status} or falls back to
     * {@code "unknown"} if the property is not set.
     */
    public static String getInactiveSlotStatus() {
        return SystemProperties.get("ro.boot.slot_inactive_status", "unknown");
    }

    /**
     * Returns {@code true} when the inactive slot appears healthy (status is
     * {@code "bootable"} or the property is absent / unknown, meaning it has
     * never been written to and is safe to target).
     */
    public static boolean isInactiveSlotHealthy() {
        String status = getInactiveSlotStatus();
        // "bootable" = explicitly healthy; "unknown" = never touched = safe to write
        return "bootable".equalsIgnoreCase(status)
                || "unknown".equalsIgnoreCase(status)
                || status.isEmpty();
    }

    // ── Update state tracking ─────────────────────────────────────────────────

    /**
     * Persists a record that an update to {@code targetVersion} has been started.
     * Called just before handing the OTA file to {@link UpdateInstaller}.
     *
     * @param targetVersion The version string being installed.
     */
    public static void recordUpdateStart(String targetVersion) {
        try {
            new File(STATE_FILE).getParentFile().mkdirs();
            JSONObject obj = new JSONObject();
            obj.put("target_version", targetVersion);
            obj.put("started_at", System.currentTimeMillis());
            obj.put("current_slot", getCurrentSlot());
            try (FileWriter fw = new FileWriter(STATE_FILE)) {
                fw.write(obj.toString());
            }
            Log.i(TAG, "Recorded update start: " + targetVersion
                    + " (inactive slot=" + getInactiveSlot() + ")");
        } catch (Exception e) {
            Log.w(TAG, "Failed to record update start: " + e.getMessage());
        }
    }

    /**
     * Clears the update state record, typically called after the device has
     * successfully booted into the new slot.
     */
    public static void clearUpdateRecord() {
        File f = new File(STATE_FILE);
        if (f.exists()) {
            f.delete();
            Log.i(TAG, "Cleared update state record");
        }
    }

    /**
     * Checks whether a previous update attempt appears to be stuck (the device
     * rebooted but the running version does not match the recorded target).
     *
     * <p>Returns the expected target version string if a stuck update is detected,
     * or {@code null} if everything looks normal or there is no record.
     */
    public static String checkForStuckUpdate() {
        File f = new File(STATE_FILE);
        if (!f.exists()) return null;

        try (FileReader fr = new FileReader(f)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[1024];
            int n;
            while ((n = fr.read(buf)) > 0) sb.append(buf, 0, n);

            JSONObject obj           = new JSONObject(sb.toString());
            String     targetVersion = obj.optString("target_version", null);
            String     currentSlot   = obj.optString("current_slot", "");

            if (targetVersion == null) {
                clearUpdateRecord();
                return null;
            }

            String runningVersion = SystemProperties.get(
                    "ro.build.version.release_or_codename", "");
            String nowSlot        = getCurrentSlot();

            // If slot changed, the update was applied — record is stale
            if (!currentSlot.equals(nowSlot)) {
                Log.i(TAG, "Slot changed " + currentSlot + " → " + nowSlot
                        + "; clearing update record");
                clearUpdateRecord();
                return null;
            }

            // Same slot, same version → update never completed
            if (!targetVersion.equals(runningVersion)) {
                Log.w(TAG, "Stuck update detected: expected v" + targetVersion
                        + " but running v" + runningVersion);
                return targetVersion;
            }

            // Slot unchanged and versions match — unlikely but clear the record
            clearUpdateRecord();
            return null;

        } catch (Exception e) {
            Log.w(TAG, "checkForStuckUpdate error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Logs a summary of the current A/B slot state for diagnostics.
     */
    public static void logSlotState() {
        Log.i(TAG, "A/B device=" + isAbDevice()
                + " current=" + getCurrentSlot()
                + " inactive=" + getInactiveSlot()
                + " inactiveStatus=" + getInactiveSlotStatus());
    }
}
