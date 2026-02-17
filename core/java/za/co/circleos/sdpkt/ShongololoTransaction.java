/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * A Shongololo (₷) transaction record.
 *
 * Amount is stored as long in ₷ cents (2 decimal places):
 *   ₷50.00 = 5000 cents
 *
 * Wire format (JSON, transmitted over NFC):
 * {
 *   "version": 1,
 *   "type": "transfer",
 *   "id": "uuid-v4",
 *   "timestamp": "ISO-8601",
 *   "nonce": "base64-32-bytes",
 *   "sender":   { "pubkey": "base64", "device_id": "hex" },
 *   "receiver": { "pubkey": "base64" },
 *   "amount":   { "value": 5000, "currency": "SHG", "decimals": 2 },
 *   "signature": "base64-ecdsa-sha256"
 * }
 */
public final class ShongololoTransaction implements Parcelable {

    /* ── Direction ───────────────────────────────────── */
    public static final int TYPE_SEND    = 1;
    public static final int TYPE_RECEIVE = 2;

    /* ── Status ──────────────────────────────────────── */
    public static final int STATUS_PENDING_SETTLEMENT = 1;
    public static final int STATUS_SETTLED            = 2;
    public static final int STATUS_REJECTED           = 3;
    public static final int STATUS_REVERSED           = 4;
    public static final int STATUS_FAILED             = 5;

    public String txId;              // UUID v4
    public int    type;              // TYPE_SEND or TYPE_RECEIVE
    public int    status;            // STATUS_*
    public long   amountCents;       // ₷ × 100
    public String currency;          // "SHG"
    public String senderPubkey;      // base64 encoded public key
    public String senderDeviceId;    // hex SHA-256 of sender pubkey
    public String receiverPubkey;    // base64 encoded public key
    public String nonce;             // base64 32-byte random nonce (replay protection)
    public String signature;         // base64 ECDSA-SHA256 signature by sender
    public String memo;              // optional human-readable note
    public long   createdAtMs;       // epoch ms (local clock at creation)
    public long   settledAtMs;       // epoch ms when settled (0 if pending)

    public ShongololoTransaction() {
        currency = "SHG";
        status   = STATUS_PENDING_SETTLEMENT;
    }

    /** Format amount as "₷50.00" */
    public String formattedAmount() {
        return String.format("₷%d.%02d", amountCents / 100, amountCents % 100);
    }

    protected ShongololoTransaction(Parcel in) {
        txId           = in.readString();
        type           = in.readInt();
        status         = in.readInt();
        amountCents    = in.readLong();
        currency       = in.readString();
        senderPubkey   = in.readString();
        senderDeviceId = in.readString();
        receiverPubkey = in.readString();
        nonce          = in.readString();
        signature      = in.readString();
        memo           = in.readString();
        createdAtMs    = in.readLong();
        settledAtMs    = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(txId);
        dest.writeInt(type);
        dest.writeInt(status);
        dest.writeLong(amountCents);
        dest.writeString(currency);
        dest.writeString(senderPubkey);
        dest.writeString(senderDeviceId);
        dest.writeString(receiverPubkey);
        dest.writeString(nonce);
        dest.writeString(signature);
        dest.writeString(memo);
        dest.writeLong(createdAtMs);
        dest.writeLong(settledAtMs);
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<ShongololoTransaction> CREATOR = new Creator<ShongololoTransaction>() {
        @Override public ShongololoTransaction createFromParcel(Parcel in) { return new ShongololoTransaction(in); }
        @Override public ShongololoTransaction[] newArray(int size) { return new ShongololoTransaction[size]; }
    };
}
