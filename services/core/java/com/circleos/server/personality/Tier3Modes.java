/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import java.util.*;
import za.co.circleos.personality.*;

/**
 * Static factory for Tier-3 specialist modes (download-on-activation).
 * Modes: Trader, Developer, Health, Travel, Entrepreneur, Night.
 */
class Tier3Modes {

    private static final String BASE_URL = "https://modes.circleos.za.co/bundles/";

    private Tier3Modes() {}

    static List<PersonalityMode> allModes() {
        List<PersonalityMode> list = new ArrayList<>();
        list.add(trader());
        list.add(developer());
        list.add(health());
        list.add(travel());
        list.add(entrepreneur());
        list.add(night());
        return list;
    }

    static List<ModeBundle> allBundles() {
        List<ModeBundle> list = new ArrayList<>();
        for (PersonalityMode m : allModes()) {
            ModeBundle b = bundleFor(m.id);
            if (b != null) list.add(b);
        }
        return list;
    }

    // ---- Mode definitions ---------------------------------------------------

    private static PersonalityMode trader() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_PRIORITY;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = false;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.screenBrightness  = -1;
        cfg.enforceVpn        = true;
        cfg.privacyLevel      = ModeConfig.PRIVACY_MAX;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id = "trader"; m.name = "Trader"; m.tier = 3; m.isCustom = false;
        m.description = "Finance-focused: VPN enforced, max privacy, trading alerts only.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode developer() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_SILENT;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = false;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.screenBrightness  = -1;
        cfg.enforceVpn        = false;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "developer"; m.name = "Developer"; m.tier = 3; m.isCustom = false;
        m.description = "Deep-focus coding: silent, dark, WiFi+data on, location off.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode health() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_PRIORITY;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;   // wearable sensors
        cfg.themeMode         = ModeConfig.THEME_LIGHT;
        cfg.screenBrightness  = 180;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = false;  // health data stays on-device

        PersonalityMode m = new PersonalityMode();
        m.id = "health"; m.name = "Health"; m.tier = 3; m.isCustom = false;
        m.description = "Wellness tracking: Bluetooth wearables, GPS, health alerts, on-device data.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode travel() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.themeMode         = ModeConfig.THEME_AUTO;
        cfg.screenBrightness  = 200;
        cfg.enforceVpn        = true;   // public WiFi protection
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "travel"; m.name = "Travel"; m.tier = 3; m.isCustom = false;
        m.description = "On-the-go: all connectivity, VPN for public WiFi, GPS navigation.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode entrepreneur() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.themeMode         = ModeConfig.THEME_AUTO;
        cfg.screenBrightness  = -1;
        cfg.enforceVpn        = false;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "entrepreneur"; m.name = "Entrepreneur"; m.tier = 3; m.isCustom = false;
        m.description = "Business hustle: full connectivity, calendar integration, cloud sync.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode night() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_ALARMS;
        cfg.wifiEnabled       = false;
        cfg.dataEnabled       = false;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = false;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.screenBrightness  = 20;
        cfg.enforceVpn        = false;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id = "night"; m.name = "Night"; m.tier = 3; m.isCustom = false;
        m.description = "Sleep mode: alarms only, WiFi/data off, minimum brightness, dark theme.";
        m.config = cfg;
        return m;
    }

    // ---- Bundle definitions -------------------------------------------------

    static ModeBundle bundleFor(String modeId) {
        ModeBundle b = new ModeBundle();
        b.modeId      = modeId;
        b.bundleId    = modeId + "_bundle";
        b.downloadUrl = BASE_URL + modeId + "/bundle.json";

        switch (modeId) {
            case "trader":
                b.displayName = "Trader Mode Bundle";
                b.sizeBytes   = 11_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.trader");
                b.recommendedApps = Arrays.asList("com.tradingview.tradingviewapp", "za.co.sdpkt");
                break;
            case "developer":
                b.displayName = "Developer Mode Bundle";
                b.sizeBytes   = 9_500_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.developer");
                b.recommendedApps = Arrays.asList("com.termux", "com.github.android");
                break;
            case "health":
                b.displayName = "Health Mode Bundle";
                b.sizeBytes   = 14_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.health");
                b.recommendedApps = Arrays.asList("com.google.android.apps.fitness");
                break;
            case "travel":
                b.displayName = "Travel Mode Bundle";
                b.sizeBytes   = 16_500_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.travel");
                b.recommendedApps = Arrays.asList("com.google.android.apps.maps", "com.google.android.apps.translate");
                break;
            case "entrepreneur":
                b.displayName = "Entrepreneur Mode Bundle";
                b.sizeBytes   = 20_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.entrepreneur");
                b.recommendedApps = Arrays.asList("com.microsoft.teams", "com.slack");
                break;
            case "night":
                b.displayName = "Night Mode Bundle";
                b.sizeBytes   = 3_200_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.night");
                b.recommendedApps = Collections.emptyList();
                break;
            default:
                return null;
        }
        return b;
    }
}
