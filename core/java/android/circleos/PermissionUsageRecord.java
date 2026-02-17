/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package android.circleos;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Parcelable representing a single entry in the Circle OS privacy audit log.
 * Written by {@link PrivacyLogger} and surfaced via
 * {@link ICirclePrivacyManager#getUsageLog}.
 */
public final class PermissionUsageRecord implements Parcelable {

    /** Unix epoch milliseconds when the event occurred. */
    public long timestamp;

    /** Package name of the app whose permission was evaluated. */
    public String packageName;

    /**
     * The permission that was checked, e.g.:
     *   com.circleos.permission.NETWORK
     *   android.permission.READ_CONTACTS
     *   SENSOR:GYROSCOPE
     */
    public String permission;

    /**
     * Outcome of the policy evaluation:
     *   GRANTED | DENIED | USED | REVOKED | FAKED | ASKED
     */
    public String action;

    /**
     * Additional context: domain name for NETWORK checks,
     * sensor type for sensor checks, etc. May be null.
     */
    public String extra;

    public PermissionUsageRecord() {}

    // ---- Parcelable ----

    protected PermissionUsageRecord(Parcel in) {
        timestamp   = in.readLong();
        packageName = in.readString();
        permission  = in.readString();
        action      = in.readString();
        extra       = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(timestamp);
        dest.writeString(packageName);
        dest.writeString(permission);
        dest.writeString(action);
        dest.writeString(extra);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<PermissionUsageRecord> CREATOR = new Creator<>() {
        @Override
        public PermissionUsageRecord createFromParcel(Parcel in) {
            return new PermissionUsageRecord(in);
        }
        @Override
        public PermissionUsageRecord[] newArray(int size) {
            return new PermissionUsageRecord[size];
        }
    };
}
