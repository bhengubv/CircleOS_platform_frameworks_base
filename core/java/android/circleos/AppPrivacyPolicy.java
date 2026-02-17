/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package android.circleos;

import android.os.Parcel;
import android.os.Parcelable;

import java.util.ArrayList;
import java.util.List;

/**
 * Parcelable describing a per-app privacy policy evaluated by
 * {@link PrivacyRulesEngine}.
 */
public final class AppPrivacyPolicy implements Parcelable {

    /** Allow unrestricted internet access. */
    public boolean networkAllowed;

    /** Restrict internet to Wi-Fi only (mobile data blocked). */
    public boolean wifiOnly;

    /** Restrict internet to mobile data only (Wi-Fi blocked). */
    public boolean mobileOnly;

    /**
     * Explicit domain allow-list. If non-empty, only connections to listed
     * domains are permitted even when {@link #networkAllowed} is true.
     */
    public List<String> allowedDomains;

    /**
     * Lobby mode: app can reach Circle OS servers for metadata/updates only.
     * All other network access is blocked.
     */
    public boolean lobbyMode;

    /** Sensor permissions: ACCELEROMETER, GYROSCOPE, BAROMETER, MAGNETOMETER. */
    public List<String> allowedSensors;

    /** Whether the app may access contacts (filtered by ScopedContactsProvider). */
    public boolean contactsAllowed;

    /** Whether the app may use Storage Access Framework for external storage. */
    public boolean storageAllowed;

    public AppPrivacyPolicy() {
        allowedDomains = new ArrayList<>();
        allowedSensors = new ArrayList<>();
    }

    // ---- Parcelable ----

    protected AppPrivacyPolicy(Parcel in) {
        networkAllowed = in.readByte() != 0;
        wifiOnly       = in.readByte() != 0;
        mobileOnly     = in.readByte() != 0;
        allowedDomains = in.createStringArrayList();
        lobbyMode      = in.readByte() != 0;
        allowedSensors = in.createStringArrayList();
        contactsAllowed = in.readByte() != 0;
        storageAllowed  = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByte((byte) (networkAllowed ? 1 : 0));
        dest.writeByte((byte) (wifiOnly       ? 1 : 0));
        dest.writeByte((byte) (mobileOnly     ? 1 : 0));
        dest.writeStringList(allowedDomains);
        dest.writeByte((byte) (lobbyMode      ? 1 : 0));
        dest.writeStringList(allowedSensors);
        dest.writeByte((byte) (contactsAllowed ? 1 : 0));
        dest.writeByte((byte) (storageAllowed  ? 1 : 0));
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<AppPrivacyPolicy> CREATOR = new Creator<>() {
        @Override
        public AppPrivacyPolicy createFromParcel(Parcel in) {
            return new AppPrivacyPolicy(in);
        }
        @Override
        public AppPrivacyPolicy[] newArray(int size) {
            return new AppPrivacyPolicy[size];
        }
    };
}
