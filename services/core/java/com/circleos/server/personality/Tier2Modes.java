/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import java.util.*;
import za.co.circleos.personality.*;

/**
 * Static factory for Tier-2 lifestyle modes (download-on-activation).
 * Modes: Sport, Creator, Driver, Party, Parent, Elder, Gaming.
 */
class Tier2Modes {

    private static final String BASE_URL = "https://modes.circleos.za.co/bundles/";

    private Tier2Modes() {}

    static List<PersonalityMode> allModes() {
        List<PersonalityMode> list = new ArrayList<>();
        list.add(sport());
        list.add(creator());
        list.add(driver());
        list.add(party());
        list.add(parent());
        list.add(elder());
        list.add(gaming());
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

    static ModeBundle getBundleForMode(String modeId) {
        return bundleFor(modeId);
    }

    // ---- Mode definitions ---------------------------------------------------

    private static PersonalityMode sport() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_PRIORITY;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.screenBrightness  = 200;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "sport"; m.name = "Sport"; m.tier = 2; m.isCustom = false;
        m.description = "GPS tracking, priority alerts, high brightness for outdoor activity.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode creator() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = false;
        cfg.bluetoothEnabled  = true;
        cfg.themeMode         = ModeConfig.THEME_LIGHT;
        cfg.screenBrightness  = -1;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "creator"; m.name = "Creator"; m.tier = 2; m.isCustom = false;
        m.description = "All connectivity on, light theme, cloud sync for content creation.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode driver() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_ALARMS;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.screenBrightness  = 180;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.enforceVpn        = false;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id = "driver"; m.name = "Driver"; m.tier = 2; m.isCustom = false;
        m.description = "GPS on, calls/alarms only, Bluetooth for hands-free. Drive safe.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode party() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.wifiEnabled       = true;
        cfg.dataEnabled       = true;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.screenBrightness  = 220;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "party"; m.name = "Party"; m.tier = 2; m.isCustom = false;
        m.description = "Bluetooth speakers, high brightness, location sharing, social apps.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode parent() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.themeMode         = ModeConfig.THEME_AUTO;
        cfg.privacyLevel      = ModeConfig.PRIVACY_ENHANCED;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "parent"; m.name = "Parent"; m.tier = 2; m.isCustom = false;
        m.description = "Family location sharing, child-focused apps, enhanced privacy.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode elder() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = false;
        cfg.notificationLevel = ModeConfig.NOTIF_ALL;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.screenBrightness  = 200;
        cfg.themeMode         = ModeConfig.THEME_LIGHT;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = true;

        PersonalityMode m = new PersonalityMode();
        m.id = "elder"; m.name = "Elder"; m.tier = 2; m.isCustom = false;
        m.description = "Large text, simplified UI, accessibility features, full notifications.";
        m.config = cfg;
        return m;
    }

    private static PersonalityMode gaming() {
        ModeConfig cfg = new ModeConfig();
        cfg.dndEnabled        = true;
        cfg.notificationLevel = ModeConfig.NOTIF_SILENT;
        cfg.locationEnabled   = true;
        cfg.bluetoothEnabled  = true;
        cfg.screenBrightness  = 255;
        cfg.themeMode         = ModeConfig.THEME_DARK;
        cfg.privacyLevel      = ModeConfig.PRIVACY_NORMAL;
        cfg.cloudSyncEnabled  = false;

        PersonalityMode m = new PersonalityMode();
        m.id = "gaming"; m.name = "Gaming"; m.tier = 2; m.isCustom = false;
        m.description = "Silent notifications, max brightness, dark theme, GPS for geo-games.";
        m.config = cfg;
        return m;
    }

    // ---- Bundle definitions -------------------------------------------------

    private static ModeBundle bundleFor(String modeId) {
        ModeBundle b = new ModeBundle();
        b.modeId      = modeId;
        b.bundleId    = modeId + "_bundle";
        b.downloadUrl = BASE_URL + modeId + "/bundle.json";

        switch (modeId) {
            case "sport":
                b.displayName = "Sport Mode Bundle";
                b.sizeBytes   = 8_500_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.sport");
                b.recommendedApps = Arrays.asList("com.strava", "com.garmin.android.apps.connectmobile");
                break;
            case "creator":
                b.displayName = "Creator Mode Bundle";
                b.sizeBytes   = 22_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.creator");
                b.recommendedApps = Arrays.asList("com.adobe.lightroom", "com.google.android.youtube");
                break;
            case "driver":
                b.displayName = "Driver Mode Bundle";
                b.sizeBytes   = 5_200_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.driver");
                b.recommendedApps = Arrays.asList("com.google.android.apps.maps", "com.waze");
                break;
            case "party":
                b.displayName = "Party Mode Bundle";
                b.sizeBytes   = 12_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.party");
                b.recommendedApps = Arrays.asList("com.spotify.music", "com.instagram.android");
                break;
            case "parent":
                b.displayName = "Parent Mode Bundle";
                b.sizeBytes   = 18_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.parent");
                b.recommendedApps = Arrays.asList("com.google.android.apps.family", "net.kidoz.sdk");
                break;
            case "elder":
                b.displayName = "Elder Mode Bundle";
                b.sizeBytes   = 7_800_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.elder");
                b.recommendedApps = Arrays.asList("com.google.android.apps.talkback");
                break;
            case "gaming":
                b.displayName = "Gaming Mode Bundle";
                b.sizeBytes   = 45_000_000L;
                b.requiredApps    = Arrays.asList("za.co.circleos.gaming");
                b.recommendedApps = Arrays.asList("com.discord", "com.nvidia.geforcenow");
                break;
            default:
                return null;
        }
        return b;
    }
}
