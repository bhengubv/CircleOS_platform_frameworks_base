/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Policy applied to a managed (PIN-locked) personality mode.
 *
 * When a policy is active for a mode:
 * - The mode can only be deactivated by providing the correct PIN.
 * - Enterprise-managed modes also set {@link #isEnterpriseManaged} and record
 *   {@link #adminPackage} for MDM audit logging.
 */
public final class ManagedModePolicy implements Parcelable {

    /** Mode this policy applies to. */
    public String  modeId;

    /**
     * SHA-256 hex digest of the user-chosen PIN.
     * Never store the plain PIN — always hash before setting this field.
     */
    public String  pinHash;

    /**
     * Package name of the MDM/EMM app that installed this policy, or null
     * for a user-created parental lock.
     */
    public String  adminPackage;

    /**
     * True if this policy was pushed by an enterprise MDM agent.
     * Enterprise policies cannot be removed without MDM authorisation.
     */
    public boolean isEnterpriseManaged;

    public ManagedModePolicy() {}

    protected ManagedModePolicy(Parcel in) {
        modeId              = in.readString();
        pinHash             = in.readString();
        adminPackage        = in.readString();
        isEnterpriseManaged = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(modeId);
        dest.writeString(pinHash);
        dest.writeString(adminPackage);
        dest.writeByte((byte) (isEnterpriseManaged ? 1 : 0));
    }

    @Override public int describeContents() { return 0; }

    public static final Creator<ManagedModePolicy> CREATOR = new Creator<ManagedModePolicy>() {
        @Override public ManagedModePolicy createFromParcel(Parcel in) { return new ManagedModePolicy(in); }
        @Override public ManagedModePolicy[] newArray(int size)        { return new ManagedModePolicy[size]; }
    };
}
