/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * A single generated token from a streaming inference response.
 */
public final class Token implements Parcelable {

    /** The decoded text of this token. */
    public String text;

    /** Zero-based index of this token in the output sequence. */
    public int index;

    /** True if this is the last token in the sequence. */
    public boolean isFinal;

    /** Log-probability of this token. Float.NaN if not available. */
    public float logprob;

    public Token() {}

    protected Token(Parcel in) {
        text = in.readString();
        index = in.readInt();
        isFinal = in.readByte() != 0;
        logprob = in.readFloat();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(text);
        dest.writeInt(index);
        dest.writeByte((byte) (isFinal ? 1 : 0));
        dest.writeFloat(logprob);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<Token> CREATOR = new Creator<Token>() {
        @Override
        public Token createFromParcel(Parcel in) {
            return new Token(in);
        }

        @Override
        public Token[] newArray(int size) {
            return new Token[size];
        }
    };
}
