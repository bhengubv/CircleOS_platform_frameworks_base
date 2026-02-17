/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import za.co.circleos.inference.DeviceCapabilities;
import za.co.circleos.inference.InferenceRequest;
import za.co.circleos.inference.InferenceResponse;
import za.co.circleos.inference.ModelInfo;
import za.co.circleos.inference.ResourceMetrics;
import za.co.circleos.inference.IInferenceCallback;
import za.co.circleos.inference.IResourceCallback;

/**
 * Main Binder interface for the CircleOS on-device LLM inference service.
 * Service name: "circle.inference"
 *
 * Callers require com.circleos.permission.ACCESS_INFERENCE.
 */
interface ICircleInference {

    // ── Capability ──────────────────────────────────────────────────────────

    /** Returns device hardware capabilities and recommended inference tier (1-5). */
    DeviceCapabilities getDeviceCapabilities();

    /** Returns the service protocol version. Phase 1 returns 1. */
    int getServiceVersion();

    // ── Model lifecycle ──────────────────────────────────────────────────────

    /** Returns all models available on this device (bundled + downloaded). */
    List<ModelInfo> listModels();

    /**
     * Loads a model by ID. Loading is asynchronous; the callback receives
     * onModelLoaded() when the model is ready.
     */
    void loadModel(String modelId, in IInferenceCallback callback);

    /** Unloads the currently loaded model, freeing native memory. */
    void unloadModel(String modelId);

    /** Returns the ID of the currently loaded model, or null if none. */
    String getLoadedModelId();

    // ── Inference ────────────────────────────────────────────────────────────

    /**
     * Runs inference and returns the complete response synchronously.
     * Blocks until generation is complete. Prefer generateStream for long outputs.
     */
    InferenceResponse generate(in InferenceRequest request);

    /**
     * Runs streaming inference. onToken() is called for each token;
     * onComplete() is called with the final response.
     */
    void generateStream(in InferenceRequest request, in IInferenceCallback callback);

    /** Cancels any in-progress inference for the calling UID. */
    void cancelGeneration();

    // ── Resource management ──────────────────────────────────────────────────

    /** Returns current resource usage metrics. */
    ResourceMetrics getResourceMetrics();

    /** Registers a callback to receive memory/thermal/eviction events. */
    void registerResourceCallback(in IResourceCallback callback);

    /** Unregisters a previously registered resource callback. */
    void unregisterResourceCallback(in IResourceCallback callback);
}
