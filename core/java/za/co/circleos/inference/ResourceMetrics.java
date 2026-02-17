/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Runtime resource usage metrics for the inference service.
 */
public final class ResourceMetrics implements Parcelable {

    /** Memory currently used by the loaded model, in MB. */
    public int memoryUsedMb;

    /** Memory budget allocated to the inference service, in MB. */
    public int memoryBudgetMb;

    /** Current inference throughput in tokens per second. 0 if idle. */
    public float tokensPerSecond;

    /** True if a model is currently loaded in memory. */
    public boolean modelLoaded;

    /**
     * Current thermal state.
     * 0 = normal, 1 = light throttle, 2 = moderate throttle, 3 = severe throttle.
     */
    public int thermalState;

    public ResourceMetrics() {}

    protected ResourceMetrics(Parcel in) {
        memoryUsedMb = in.readInt();
        memoryBudgetMb = in.readInt();
        tokensPerSecond = in.readFloat();
        modelLoaded = in.readByte() != 0;
        thermalState = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(memoryUsedMb);
        dest.writeInt(memoryBudgetMb);
        dest.writeFloat(tokensPerSecond);
        dest.writeByte((byte) (modelLoaded ? 1 : 0));
        dest.writeInt(thermalState);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<ResourceMetrics> CREATOR = new Creator<ResourceMetrics>() {
        @Override
        public ResourceMetrics createFromParcel(Parcel in) {
            return new ResourceMetrics(in);
        }

        @Override
        public ResourceMetrics[] newArray(int size) {
            return new ResourceMetrics[size];
        }
    };
}
