/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Metadata describing an available LLM model.
 */
public final class ModelInfo implements Parcelable {

    /** Unique model identifier (e.g., "qwen-1.5b-q4"). */
    public String id;

    /** Human-readable model name. */
    public String name;

    /** Number of parameters (e.g., 1_500_000_000 for 1.5B). */
    public long parameterCount;

    /** On-disk size in bytes. */
    public long sizeBytes;

    /** Minimum RAM required to run this model, in MB. */
    public int minRamMb;

    /** Recommended device tier (1–5) for this model. */
    public int recommendedTier;

    /** True if the model is bundled in /system/circle/models/. */
    public boolean isBundled;

    /** True if the model file is present on disk and ready to load. */
    public boolean isDownloaded;

    /** Inference backend identifier (e.g., "llama.cpp"). */
    public String backend;

    public ModelInfo() {}

    protected ModelInfo(Parcel in) {
        id = in.readString();
        name = in.readString();
        parameterCount = in.readLong();
        sizeBytes = in.readLong();
        minRamMb = in.readInt();
        recommendedTier = in.readInt();
        isBundled = in.readByte() != 0;
        isDownloaded = in.readByte() != 0;
        backend = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(id);
        dest.writeString(name);
        dest.writeLong(parameterCount);
        dest.writeLong(sizeBytes);
        dest.writeInt(minRamMb);
        dest.writeInt(recommendedTier);
        dest.writeByte((byte) (isBundled ? 1 : 0));
        dest.writeByte((byte) (isDownloaded ? 1 : 0));
        dest.writeString(backend);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<ModelInfo> CREATOR = new Creator<ModelInfo>() {
        @Override
        public ModelInfo createFromParcel(Parcel in) {
            return new ModelInfo(in);
        }

        @Override
        public ModelInfo[] newArray(int size) {
            return new ModelInfo[size];
        }
    };
}
