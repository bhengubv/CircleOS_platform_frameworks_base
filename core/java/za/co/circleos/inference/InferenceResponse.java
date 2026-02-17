/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Result of a completed inference request.
 */
public final class InferenceResponse implements Parcelable {

    /** The generated text. */
    public String text;

    /** Number of tokens in the prompt. */
    public int promptTokens;

    /** Number of tokens generated. */
    public int completionTokens;

    /** End-to-end latency in milliseconds. */
    public long latencyMs;

    /** True if output was cut short by maxTokens or context limit. */
    public boolean truncated;

    public InferenceResponse() {}

    protected InferenceResponse(Parcel in) {
        text = in.readString();
        promptTokens = in.readInt();
        completionTokens = in.readInt();
        latencyMs = in.readLong();
        truncated = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(text);
        dest.writeInt(promptTokens);
        dest.writeInt(completionTokens);
        dest.writeLong(latencyMs);
        dest.writeByte((byte) (truncated ? 1 : 0));
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<InferenceResponse> CREATOR = new Creator<InferenceResponse>() {
        @Override
        public InferenceResponse createFromParcel(Parcel in) {
            return new InferenceResponse(in);
        }

        @Override
        public InferenceResponse[] newArray(int size) {
            return new InferenceResponse[size];
        }
    };
}
