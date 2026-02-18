/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.update;

/**
 * Binder interface for the CircleOS OTA update service.
 * Service name: "circle.update"
 *
 * State machine:
 *   IDLE(0) -> CHECKING(1) -> IDLE(0)            [no update found]
 *   IDLE(0) -> CHECKING(1) -> DOWNLOADING(2) -> READY_TO_INSTALL(3) -> INSTALLING(4) -> IDLE(0)
 *   Any state -> FAILED(5) -> IDLE(0)             [on error]
 */
interface ICircleUpdateService {

    // ── Check ────────────────────────────────────────────────────────────────

    /** Triggers an immediate update check. Returns true if the check was enqueued. */
    boolean checkNow();

    // ── State ────────────────────────────────────────────────────────────────

    /**
     * Returns the current update pipeline state:
     *   0 = IDLE
     *   1 = CHECKING
     *   2 = DOWNLOADING
     *   3 = READY_TO_INSTALL
     *   4 = INSTALLING
     *   5 = FAILED
     */
    int getState();

    /** Returns the available version string, or null if no update has been found. */
    String getAvailableVersion();

    /** Returns download progress 0–100, or -1 if not currently downloading. */
    int getDownloadProgress();

    /** Returns the timestamp of the last successful check (epoch ms), or 0 if never checked. */
    long getLastCheckTime();

    // ── Install ──────────────────────────────────────────────────────────────

    /**
     * Applies the downloaded update immediately. Triggers a normal reboot into the new
     * A/B slot on completion. Only valid when state == READY_TO_INSTALL; no-op otherwise.
     */
    void applyUpdate();

    // ── Channel ──────────────────────────────────────────────────────────────

    /**
     * Returns the active update channel ("stable" or "beta").
     * Reflects the user-persisted preference, falling back to ro.circleos.channel.
     */
    String getChannel();

    /**
     * Sets the update channel preference. Persisted across reboots.
     * Triggers a fresh update check on channel change.
     */
    void setChannel(String channel);
}
