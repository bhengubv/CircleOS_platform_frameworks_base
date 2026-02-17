/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Structured error from the inference service.
 */
public final class InferenceError implements Parcelable {

    // ── Error codes ──────────────────────────────────────────────────────────

    /** No error. */
    public static final int ERROR_NONE = 0;

    /** No model is loaded. Call loadModel() first. */
    public static final int ERROR_NO_MODEL_LOADED = 1;

    /** The requested model was not found in any model directory. */
    public static final int ERROR_MODEL_NOT_FOUND = 2;

    /** Model file failed SHA-256 integrity verification. */
    public static final int ERROR_MODEL_INTEGRITY_FAILED = 3;

    /** Not enough memory to load or run the model. */
    public static final int ERROR_INSUFFICIENT_MEMORY = 4;

    /** Native inference library is not available. */
    public static final int ERROR_NATIVE_NOT_AVAILABLE = 5;

    /** Inference was cancelled by the caller. */
    public static final int ERROR_CANCELLED = 6;

    /** Context window exceeded. */
    public static final int ERROR_CONTEXT_EXCEEDED = 7;

    /** Thermal throttling forced inference to abort. */
    public static final int ERROR_THERMAL_ABORT = 8;

    /** Permission check failed. */
    public static final int ERROR_PERMISSION_DENIED = 9;

    /** An unexpected internal error occurred. */
    public static final int ERROR_INTERNAL = 100;

    // ── Fields ───────────────────────────────────────────────────────────────

    /** One of the ERROR_* constants above. */
    public int code;

    /** Human-readable error description. */
    public String message;

    /** True if the caller may retry after the condition resolves. */
    public boolean recoverable;

    public InferenceError() {}

    public InferenceError(int code, String message, boolean recoverable) {
        this.code = code;
        this.message = message;
        this.recoverable = recoverable;
    }

    protected InferenceError(Parcel in) {
        code = in.readInt();
        message = in.readString();
        recoverable = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(code);
        dest.writeString(message);
        dest.writeByte((byte) (recoverable ? 1 : 0));
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<InferenceError> CREATOR = new Creator<InferenceError>() {
        @Override
        public InferenceError createFromParcel(Parcel in) {
            return new InferenceError(in);
        }

        @Override
        public InferenceError[] newArray(int size) {
            return new InferenceError[size];
        }
    };
}
