/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import java.util.ArrayList;
import java.util.List;

import za.co.circleos.personality.ModeConfig;
import za.co.circleos.personality.PersonalityMode;

/**
 * Static factory for all Tier-1 personality modes that ship with the OS.
 *
 * Tier 1 modes: Minimal, Daily, Work, Job Candidate, Student, Secure, Offline.
 */
class Tier1Modes {

    private Tier1Modes() {}

    static List<PersonalityMode> all() {
        List<PersonalityMode> modes = new ArrayList<>();
        modes.add(minimal());
        modes.add(daily());
        modes.add(work());
        modes.add(jobCandidate());
        modes.add(student());
        modes.add(secure());
        modes.add(offline());
        return modes;
    }

    // -------------------------------------------------------------------------
    // Minimal — stripped back, maximum battery life, full DND
    // -------------------------------------------------------------------------
    static PersonalityMode minimal() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_SILENT;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = false;
        cfg.screenBrightness  = 30;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id          = "minimal";
        m.name        = "Minimal";
        m.description = "Silent, dark, low power. No distractions.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }

    // -------------------------------------------------------------------------
    // Daily — balanced defaults for everyday use
    // -------------------------------------------------------------------------
    static PersonalityMode daily() {
        PersonalityMode m = new PersonalityMode();
        m.id          = "daily";
        m.name        = "Daily";
        m.description = "Balanced defaults for everyday use.";
        m.tier        = 1;
        m.config      = new ModeConfig(); // all defaults
        return m;
    }

    // -------------------------------------------------------------------------
    // Work — focus on work notifications; personal DND
    // -------------------------------------------------------------------------
    static PersonalityMode work() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_PRIORITY;
        cfg.themeMode         = ModeConfig.THEME_LIGHT;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id          = "work";
        m.name        = "Work";
        m.description = "Priority notifications only. Stay focused.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }

    // -------------------------------------------------------------------------
    // Job Candidate — professional, clean, interview-ready
    // -------------------------------------------------------------------------
    static PersonalityMode jobCandidate() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_PRIORITY;
        cfg.themeMode         = ModeConfig.THEME_LIGHT;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id          = "job_candidate";
        m.name        = "Job Candidate";
        m.description = "Professional appearance. No personal distractions.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }

    // -------------------------------------------------------------------------
    // Student — study focus, alarms allowed for schedule
    // -------------------------------------------------------------------------
    static PersonalityMode student() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_ALARMS;
        cfg.themeMode         = ModeConfig.THEME_AUTO;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.screenBrightness  = -1; // auto

        PersonalityMode m = new PersonalityMode();
        m.id          = "student";
        m.name        = "Student";
        m.description = "Study focus mode. Alarms on, distractions off.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }

    // -------------------------------------------------------------------------
    // Secure — maximum privacy, no cloud, VPN enforced
    // -------------------------------------------------------------------------
    static PersonalityMode secure() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = false;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.enforceVpn        = true;
        cfg.privacyLevel      = ModeConfig.PRIVACY_MAXIMUM;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id          = "secure";
        m.name        = "Secure";
        m.description = "Maximum privacy. VPN enforced, no location, no cloud.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }

    // -------------------------------------------------------------------------
    // Offline — no connectivity, cached content only
    // -------------------------------------------------------------------------
    static PersonalityMode offline() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.wifiEnabled       = false;
        cfg.dataEnabled       = false;
        cfg.bluetoothEnabled  = false;
        cfg.locationEnabled   = false;
        cfg.themeMode         = ModeConfig.THEME_AUTO;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id          = "offline";
        m.name        = "Offline";
        m.description = "No network. Cached content only. Maximum battery.";
        m.tier        = 1;
        m.config      = cfg;
        return m;
    }
}
