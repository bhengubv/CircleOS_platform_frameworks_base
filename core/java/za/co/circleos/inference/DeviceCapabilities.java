/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

import java.util.ArrayList;
import java.util.List;

/**
 * Hardware capabilities of the device relevant to on-device LLM inference.
 */
public final class DeviceCapabilities implements Parcelable {

    /** Total physical RAM in MB. */
    public int totalRamMb;

    /** Available (free) RAM in MB at detection time. */
    public int availableRamMb;

    /** Number of CPU cores (online). */
    public int cpuCores;

    /** CPU feature flags detected from /proc/cpuinfo (e.g., ["neon", "dotprod", "i8mm"]). */
    public List<String> cpuFeatures;

    /** True if a supported GPU is available for compute. */
    public boolean gpuAvailable;

    /** GPU type string (e.g., "adreno", "mali") or empty if none. */
    public String gpuType;

    /** Recommended device tier (1–5) for selecting model size. */
    public int recommendedTier;

    /** Inference backends available on this device. Phase 1: ["llama.cpp"]. */
    public List<String> availableBackends;

    public DeviceCapabilities() {
        cpuFeatures = new ArrayList<>();
        availableBackends = new ArrayList<>();
    }

    protected DeviceCapabilities(Parcel in) {
        totalRamMb = in.readInt();
        availableRamMb = in.readInt();
        cpuCores = in.readInt();
        cpuFeatures = new ArrayList<>();
        in.readStringList(cpuFeatures);
        gpuAvailable = in.readByte() != 0;
        gpuType = in.readString();
        recommendedTier = in.readInt();
        availableBackends = new ArrayList<>();
        in.readStringList(availableBackends);
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(totalRamMb);
        dest.writeInt(availableRamMb);
        dest.writeInt(cpuCores);
        dest.writeStringList(cpuFeatures);
        dest.writeByte((byte) (gpuAvailable ? 1 : 0));
        dest.writeString(gpuType);
        dest.writeInt(recommendedTier);
        dest.writeStringList(availableBackends);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<DeviceCapabilities> CREATOR = new Creator<DeviceCapabilities>() {
        @Override
        public DeviceCapabilities createFromParcel(Parcel in) {
            return new DeviceCapabilities(in);
        }

        @Override
        public DeviceCapabilities[] newArray(int size) {
            return new DeviceCapabilities[size];
        }
    };
}
