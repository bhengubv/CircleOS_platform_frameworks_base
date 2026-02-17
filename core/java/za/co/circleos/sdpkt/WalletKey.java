/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.sdpkt;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Wallet public key and address.
 *
 * The private key NEVER leaves the TEE (Android Keystore).
 * This parcelable carries only the public-facing identity.
 *
 * walletAddress: SHA-256(encodedPublicKey) as hex — the user's "account number"
 * encodedPublicKey: base64-encoded X.509 SubjectPublicKeyInfo (EC P-256 / secp256r1)
 *
 * Note: The spec calls for secp256k1 (Bitcoin curve). Android Keystore guarantees
 * secp256r1 (P-256) on all devices; secp256k1 is device-optional. We use P-256 for
 * portability — cryptographic security is equivalent for this application.
 */
public final class WalletKey implements Parcelable {

    public String walletAddress;      // hex SHA-256 of encodedPublicKey (40-char display: first 20 bytes)
    public String encodedPublicKey;   // base64 X.509 SubjectPublicKeyInfo
    public String deviceId;           // SHA-256(encodedPublicKey) — same as walletAddress, full 64 hex chars
    public long   createdAtMs;        // epoch ms when wallet was initialized
    public int    keystoreType;       // KEYSTORE_STRONGBOX or KEYSTORE_TEE

    public static final int KEYSTORE_STRONGBOX = 1;  // hardware secure element
    public static final int KEYSTORE_TEE       = 2;  // TrustZone TEE (software SE)
    public static final int KEYSTORE_SOFTWARE  = 3;  // fallback — not recommended

    public WalletKey() {}

    protected WalletKey(Parcel in) {
        walletAddress    = in.readString();
        encodedPublicKey = in.readString();
        deviceId         = in.readString();
        createdAtMs      = in.readLong();
        keystoreType     = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(walletAddress);
        dest.writeString(encodedPublicKey);
        dest.writeString(deviceId);
        dest.writeLong(createdAtMs);
        dest.writeInt(keystoreType);
    }

    @Override public int describeContents() { return 0; }

    /** Display-friendly short address (first 20 chars of walletAddress). */
    public String shortAddress() {
        if (walletAddress == null || walletAddress.length() < 20) return walletAddress;
        return walletAddress.substring(0, 8) + "..." + walletAddress.substring(walletAddress.length() - 8);
    }

    public static final Creator<WalletKey> CREATOR = new Creator<WalletKey>() {
        @Override public WalletKey createFromParcel(Parcel in) { return new WalletKey(in); }
        @Override public WalletKey[] newArray(int size) { return new WalletKey[size]; }
    };
}
