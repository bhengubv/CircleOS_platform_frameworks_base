/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Parameters for initiating an NFC transfer session.
 * Created by the sender before bringing phones together.
 */
public final class NfcTransferRequest implements Parcelable {

    public long   amountCents;         // ₷ × 100
    public String recipientPubkey;     // base64 public key (optional — filled in during handshake)
    public String memo;                // optional note (max 64 chars)
    public boolean lockScreenMode;     // true = initiated from lock screen quick pay (≤₷100 limit)
    /**
     * Device ID of the linked device initiating this payment (null = primary device, unlimited).
     * Set by companion apps or wearable integrations that act on behalf of a secondary device.
     * Used by ProtectionEngine to enforce per-device spending limits.
     */
    public String senderDeviceId;      // null = primary device

    public NfcTransferRequest() {}

    protected NfcTransferRequest(Parcel in) {
        amountCents      = in.readLong();
        recipientPubkey  = in.readString();
        memo             = in.readString();
        lockScreenMode   = in.readByte() != 0;
        senderDeviceId   = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(amountCents);
        dest.writeString(recipientPubkey);
        dest.writeString(memo);
        dest.writeByte((byte) (lockScreenMode ? 1 : 0));
        dest.writeString(senderDeviceId);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<NfcTransferRequest> CREATOR = new Creator<NfcTransferRequest>() {
        @Override public NfcTransferRequest createFromParcel(Parcel in) { return new NfcTransferRequest(in); }
        @Override public NfcTransferRequest[] newArray(int size) { return new NfcTransferRequest[size]; }
    };
}
