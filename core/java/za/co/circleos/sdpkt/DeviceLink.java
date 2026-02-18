/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Represents a secondary device linked to this wallet for multi-device support.
 *
 * Linked devices share the same wallet identity and can initiate NFC payments
 * from any device. Linking is performed via a NFC tap-to-pair exchange.
 */
public final class DeviceLink implements Parcelable {

    /** Primary device — the one that created the wallet. */
    public static final int ROLE_PRIMARY   = 0;
    /** Secondary device linked after initial setup. */
    public static final int ROLE_SECONDARY = 1;

    /** Unique device identifier (SHA-256 of public key, hex). */
    public String deviceId;
    /** Hex-encoded Ed25519 public key of the linked device. */
    public String pubkeyHex;
    /** User-assigned label (e.g. "Work phone", "Tablet"). */
    public String label;
    /** Role: PRIMARY or SECONDARY. */
    public int    role;
    /** Unix ms when this link was established. */
    public long   linkedAtMs;
    /** Unix ms of the most recent NFC transaction from this device. */
    public long   lastSeenMs;
    /** Maximum transaction value in satoshis this device may initiate per session (0 = unlimited). */
    public long   spendingLimitSats;

    public DeviceLink() {}

    protected DeviceLink(Parcel in) {
        deviceId          = in.readString();
        pubkeyHex         = in.readString();
        label             = in.readString();
        role              = in.readInt();
        linkedAtMs        = in.readLong();
        lastSeenMs        = in.readLong();
        spendingLimitSats = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(deviceId);
        dest.writeString(pubkeyHex);
        dest.writeString(label);
        dest.writeInt(role);
        dest.writeLong(linkedAtMs);
        dest.writeLong(lastSeenMs);
        dest.writeLong(spendingLimitSats);
    }

    @Override
    public int describeContents() { return 0; }

    public static final Creator<DeviceLink> CREATOR = new Creator<DeviceLink>() {
        @Override public DeviceLink createFromParcel(Parcel in) { return new DeviceLink(in); }
        @Override public DeviceLink[] newArray(int size)        { return new DeviceLink[size]; }
    };

    /** Returns the first 8 chars of deviceId for display. */
    public String shortId() {
        return deviceId != null && deviceId.length() >= 8 ? deviceId.substring(0, 8) : deviceId;
    }
}
