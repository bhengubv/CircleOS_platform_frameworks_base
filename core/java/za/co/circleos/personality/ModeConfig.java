/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Configuration applied when a personality mode is activated.
 */
public final class ModeConfig implements Parcelable {

    /** Notification level: 0=silent, 1=priority, 2=alarms_only, 3=all */
    public static final int NOTIF_SILENT   = 0;
    public static final int NOTIF_PRIORITY = 1;
    public static final int NOTIF_ALARMS   = 2;
    public static final int NOTIF_ALL      = 3;

    /** Theme mode: 0=auto, 1=light, 2=dark */
    public static final int THEME_AUTO  = 0;
    public static final int THEME_LIGHT = 1;
    public static final int THEME_DARK  = 2;

    /** Privacy level: 0=normal, 1=enhanced, 2=maximum */
    public static final int PRIVACY_NORMAL   = 0;
    public static final int PRIVACY_ENHANCED = 1;
    public static final int PRIVACY_MAXIMUM  = 2;

    public boolean dndEnabled;
    public int     notificationLevel;   // NOTIF_* constants
    public boolean wifiEnabled;
    public boolean dataEnabled;
    public boolean locationEnabled;
    public boolean bluetoothEnabled;
    public int     screenBrightness;    // 0-255, -1 = auto
    public int     themeMode;           // THEME_* constants
    public boolean enforceVpn;
    public int     privacyLevel;        // PRIVACY_* constants
    public boolean cloudSyncEnabled;

    public ModeConfig() {
        // Defaults match "Daily" (normal usage)
        dndEnabled       = false;
        notificationLevel = NOTIF_ALL;
        wifiEnabled      = true;
        dataEnabled      = true;
        locationEnabled  = true;
        bluetoothEnabled = true;
        screenBrightness = -1;
        themeMode        = THEME_AUTO;
        enforceVpn       = false;
        privacyLevel     = PRIVACY_NORMAL;
        cloudSyncEnabled = true;
    }

    protected ModeConfig(Parcel in) {
        dndEnabled       = in.readByte() != 0;
        notificationLevel = in.readInt();
        wifiEnabled      = in.readByte() != 0;
        dataEnabled      = in.readByte() != 0;
        locationEnabled  = in.readByte() != 0;
        bluetoothEnabled = in.readByte() != 0;
        screenBrightness = in.readInt();
        themeMode        = in.readInt();
        enforceVpn       = in.readByte() != 0;
        privacyLevel     = in.readInt();
        cloudSyncEnabled = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByte((byte) (dndEnabled       ? 1 : 0));
        dest.writeInt(notificationLevel);
        dest.writeByte((byte) (wifiEnabled      ? 1 : 0));
        dest.writeByte((byte) (dataEnabled      ? 1 : 0));
        dest.writeByte((byte) (locationEnabled  ? 1 : 0));
        dest.writeByte((byte) (bluetoothEnabled ? 1 : 0));
        dest.writeInt(screenBrightness);
        dest.writeInt(themeMode);
        dest.writeByte((byte) (enforceVpn       ? 1 : 0));
        dest.writeInt(privacyLevel);
        dest.writeByte((byte) (cloudSyncEnabled ? 1 : 0));
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<ModeConfig> CREATOR = new Creator<ModeConfig>() {
        @Override public ModeConfig createFromParcel(Parcel in) { return new ModeConfig(in); }
        @Override public ModeConfig[] newArray(int size)        { return new ModeConfig[size]; }
    };
}
