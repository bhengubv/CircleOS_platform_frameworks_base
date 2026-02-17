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
 * Parameters for a single LLM inference request.
 */
public final class InferenceRequest implements Parcelable {

    /** The user prompt text. */
    public String prompt;

    /** Optional system prompt prepended before the user prompt. */
    public String systemPrompt;

    /** Maximum number of tokens to generate. Default: 512. */
    public int maxTokens = 512;

    /** Sampling temperature (0.0 = deterministic, 1.0 = creative). Default: 0.7. */
    public float temperature = 0.7f;

    /** Top-p nucleus sampling parameter. Default: 0.9. */
    public float topP = 0.9f;

    /** Sequences that, when generated, terminate output early. */
    public List<String> stopSequences;

    /** Context window size in tokens. 0 = use model default. */
    public int contextSize = 0;

    public InferenceRequest() {
        stopSequences = new ArrayList<>();
    }

    protected InferenceRequest(Parcel in) {
        prompt = in.readString();
        systemPrompt = in.readString();
        maxTokens = in.readInt();
        temperature = in.readFloat();
        topP = in.readFloat();
        stopSequences = new ArrayList<>();
        in.readStringList(stopSequences);
        contextSize = in.readInt();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(prompt);
        dest.writeString(systemPrompt);
        dest.writeInt(maxTokens);
        dest.writeFloat(temperature);
        dest.writeFloat(topP);
        dest.writeStringList(stopSequences);
        dest.writeInt(contextSize);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<InferenceRequest> CREATOR = new Creator<InferenceRequest>() {
        @Override
        public InferenceRequest createFromParcel(Parcel in) {
            return new InferenceRequest(in);
        }

        @Override
        public InferenceRequest[] newArray(int size) {
            return new InferenceRequest[size];
        }
    };
}
