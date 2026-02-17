/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.inference;

import android.util.Log;

import za.co.circleos.inference.InferenceError;
import za.co.circleos.inference.InferenceRequest;
import za.co.circleos.inference.InferenceResponse;
import za.co.circleos.inference.Token;

/**
 * JNI bridge to the native llama.cpp inference engine.
 *
 * In Phase 1, the native library provides stub implementations that return
 * placeholder responses. Real llama.cpp integration is wired in Phase 2.
 *
 * If the native library is not found (e.g., simulator), all methods degrade
 * gracefully and return stub data so the service stack remains functional.
 */
public class LlamaCppBackend {

    private static final String TAG = "CircleInference.Llama";
    private static final String LIB_NAME = "circle_inference";

    /** Non-zero when a model is loaded natively; 0 otherwise. */
    private long mHandle = 0;

    /** True if the native library loaded successfully. */
    private static boolean sNativeAvailable = false;

    static {
        try {
            System.loadLibrary(LIB_NAME);
            sNativeAvailable = true;
            Log.i(TAG, "Native library " + LIB_NAME + " loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "Native library not available — running in stub mode: " + e.getMessage());
        }
    }

    // ── Native method declarations ────────────────────────────────────────────

    /**
     * Loads a GGUF model from disk into native memory.
     *
     * @param modelPath     Absolute path to the .gguf file.
     * @param contextSize   Context window in tokens (0 = model default).
     * @param memoryBudgetMb Maximum memory the model may use, in MB.
     * @return Opaque native handle (> 0 on success, 0 on failure).
     */
    private native long nativeLoad(String modelPath, int contextSize, int memoryBudgetMb);

    /**
     * Runs text generation synchronously.
     *
     * @param handle      Handle returned by nativeLoad.
     * @param prompt      Full formatted prompt string.
     * @param maxTokens   Token generation limit.
     * @param temperature Sampling temperature.
     * @return Generated text, or an error string prefixed with "[ERROR]".
     */
    private native String nativeGenerate(long handle, String prompt, int maxTokens,
            float temperature);

    /**
     * Releases all native resources for the given handle.
     *
     * @param handle Handle returned by nativeLoad.
     */
    private native void nativeUnload(long handle);

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Returns true if the native library is available and usable.
     */
    public static boolean isNativeAvailable() {
        return sNativeAvailable;
    }

    /**
     * Loads a model file. Must be called before generate().
     *
     * @param modelPath      Absolute path to the .gguf model file.
     * @param contextSize    Token context window (0 = model default).
     * @param memoryBudgetMb Memory budget in MB.
     * @return true if the model loaded successfully.
     */
    public boolean load(String modelPath, int contextSize, int memoryBudgetMb) {
        if (mHandle != 0) {
            Log.w(TAG, "Model already loaded — unload first");
            return false;
        }

        if (!sNativeAvailable) {
            Log.i(TAG, "Stub load: native not available, returning placeholder handle");
            mHandle = 1L; // Stub handle
            return true;
        }

        mHandle = nativeLoad(modelPath, contextSize, memoryBudgetMb);
        if (mHandle == 0) {
            Log.e(TAG, "nativeLoad returned 0 — load failed for: " + modelPath);
            return false;
        }
        Log.i(TAG, "Model loaded, handle=" + mHandle);
        return true;
    }

    /**
     * Runs synchronous text generation.
     *
     * @param request Inference parameters.
     * @return Populated InferenceResponse.
     */
    public InferenceResponse generate(InferenceRequest request) {
        InferenceResponse response = new InferenceResponse();
        long startMs = System.currentTimeMillis();

        if (mHandle == 0) {
            Log.e(TAG, "generate() called but no model is loaded");
            response.text = "";
            response.truncated = false;
            return response;
        }

        String prompt = buildPrompt(request);

        if (!sNativeAvailable) {
            // Stub mode: return placeholder text
            response.text = "[llama.cpp not yet linked — Phase 1 stub response]";
            response.promptTokens = estimateTokens(prompt);
            response.completionTokens = 10;
            response.latencyMs = System.currentTimeMillis() - startMs;
            response.truncated = false;
            return response;
        }

        String result = nativeGenerate(mHandle, prompt, request.maxTokens, request.temperature);

        response.text = (result != null) ? result : "";
        response.promptTokens = estimateTokens(prompt);
        response.completionTokens = estimateTokens(response.text);
        response.latencyMs = System.currentTimeMillis() - startMs;
        response.truncated = response.completionTokens >= request.maxTokens;
        return response;
    }

    /**
     * Unloads the currently loaded model and frees native memory.
     */
    public void unload() {
        if (mHandle == 0) return;

        if (sNativeAvailable) {
            nativeUnload(mHandle);
        }
        Log.i(TAG, "Model unloaded, handle was " + mHandle);
        mHandle = 0;
    }

    /**
     * Returns true if a model is currently loaded.
     */
    public boolean isLoaded() {
        return mHandle != 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String buildPrompt(InferenceRequest request) {
        if (request.systemPrompt != null && !request.systemPrompt.isEmpty()) {
            return "<|system|>\n" + request.systemPrompt + "\n<|user|>\n" + request.prompt
                    + "\n<|assistant|>\n";
        }
        return request.prompt;
    }

    /** Rough token count estimate: ~4 chars per token. */
    private int estimateTokens(String text) {
        if (text == null || text.isEmpty()) return 0;
        return Math.max(1, text.length() / 4);
    }
}
