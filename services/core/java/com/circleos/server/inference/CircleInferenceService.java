/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.inference;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.util.Log;

import com.android.server.SystemService;

import za.co.circleos.inference.DeviceCapabilities;
import za.co.circleos.inference.ICircleInference;
import za.co.circleos.inference.IInferenceCallback;
import za.co.circleos.inference.IResourceCallback;
import za.co.circleos.inference.InferenceError;
import za.co.circleos.inference.InferenceRequest;
import za.co.circleos.inference.InferenceResponse;
import za.co.circleos.inference.ModelInfo;
import za.co.circleos.inference.ResourceMetrics;
import za.co.circleos.inference.Token;

import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * CircleOS on-device LLM inference system service.
 *
 * Provides all apps with access to on-device language model inference via a
 * shared Binder interface, eliminating per-app model bundling and cloud
 * dependency.
 *
 * Service name: "circle.inference"
 * Permission required: com.circleos.permission.ACCESS_INFERENCE
 *
 * Architecture:
 *  - Single HandlerThread serialises all model load/unload/generate operations.
 *  - LinkedBlockingQueue holds pending inference requests for fair FIFO scheduling.
 *  - LlamaCppBackend wraps the native llama.cpp JNI calls.
 *  - CapabilityDetector classifies the device tier on first access.
 *  - ModelManager discovers and verifies models in /system/circle/models/ and
 *    /data/circle/models/.
 */
public class CircleInferenceService extends SystemService {

    private static final String TAG          = "CircleInference";
    private static final String SERVICE_NAME = "circle.inference";
    private static final int    SERVICE_VERSION = 1;

    private HandlerThread mHandlerThread;
    private Handler mHandler;

    private CapabilityDetector mCapabilityDetector;
    private ModelManager mModelManager;
    private LlamaCppBackend mBackend;

    private DeviceCapabilities mCachedCapabilities;
    private String mLoadedModelId;

    private final LinkedBlockingQueue<Runnable> mRequestQueue = new LinkedBlockingQueue<>();
    private final RemoteCallbackList<IResourceCallback> mResourceCallbacks =
            new RemoteCallbackList<>();

    // ── Constructor ───────────────────────────────────────────────────────────

    public CircleInferenceService(Context context) {
        super(context);
    }

    // ── SystemService lifecycle ───────────────────────────────────────────────

    @Override
    public void onStart() {
        Log.i(TAG, "Starting CircleInferenceService");

        mHandlerThread = new HandlerThread("CircleInference");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        mCapabilityDetector = new CapabilityDetector(getContext());
        mModelManager = new ModelManager();
        mBackend = new LlamaCppBackend();

        publishBinderService(SERVICE_NAME, new InferenceImpl());
        Log.i(TAG, "CircleInferenceService published as " + SERVICE_NAME);
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed — loading optimal model");
            mHandler.post(this::loadOptimalModelAsync);
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private void loadOptimalModelAsync() {
        DeviceCapabilities caps = getOrDetectCapabilities();
        ModelInfo best = mModelManager.selectOptimalModel(caps.recommendedTier);

        if (best == null) {
            Log.i(TAG, "No suitable model available for tier " + caps.recommendedTier);
            return;
        }

        String path = mModelManager.getModelPath(best.id);
        if (path == null) {
            Log.w(TAG, "Model path not found for: " + best.id);
            return;
        }

        // Integrity check
        String expectedSha = mModelManager.getExpectedChecksum(best.id);
        if (expectedSha != null) {
            if (!mModelManager.verifyIntegrity(new java.io.File(path), expectedSha)) {
                Log.e(TAG, "Model integrity check failed — not loading: " + best.id);
                return;
            }
        }

        int memBudget = caps.availableRamMb / 2; // Use up to half of available RAM
        boolean loaded = mBackend.load(path, 0, memBudget);

        if (loaded) {
            mLoadedModelId = best.id;
            Log.i(TAG, "Auto-loaded model: " + best.id);
        } else {
            Log.e(TAG, "Failed to auto-load model: " + best.id);
        }
    }

    private DeviceCapabilities getOrDetectCapabilities() {
        if (mCachedCapabilities == null) {
            mCachedCapabilities = mCapabilityDetector.detect();
        }
        return mCachedCapabilities;
    }

    private ResourceMetrics buildResourceMetrics() {
        ResourceMetrics m = new ResourceMetrics();
        DeviceCapabilities caps = getOrDetectCapabilities();
        m.memoryBudgetMb = caps.availableRamMb / 2;
        m.modelLoaded    = mBackend.isLoaded();
        m.thermalState   = 0;
        m.tokensPerSecond = 0f;
        if (m.modelLoaded) {
            m.memoryUsedMb = caps.availableRamMb / 4; // Rough estimate
        }
        return m;
    }

    // ── Binder implementation ─────────────────────────────────────────────────

    private final class InferenceImpl extends ICircleInference.Stub {

        @Override
        public DeviceCapabilities getDeviceCapabilities() {
            return getOrDetectCapabilities();
        }

        @Override
        public int getServiceVersion() {
            return SERVICE_VERSION;
        }

        @Override
        public List<ModelInfo> listModels() {
            return mModelManager.listAvailableModels();
        }

        @Override
        public void loadModel(String modelId, IInferenceCallback callback) {
            mHandler.post(() -> {
                if (mBackend.isLoaded()) {
                    mBackend.unload();
                    mLoadedModelId = null;
                }

                String path = mModelManager.getModelPath(modelId);
                if (path == null) {
                    if (callback != null) {
                        try {
                            callback.onError(new InferenceError(
                                    InferenceError.ERROR_MODEL_NOT_FOUND,
                                    "Model not found: " + modelId, false));
                        } catch (RemoteException e) {
                            Log.w(TAG, "Callback dead on loadModel error", e);
                        }
                    }
                    return;
                }

                String expectedSha = mModelManager.getExpectedChecksum(modelId);
                if (expectedSha != null
                        && !mModelManager.verifyIntegrity(new java.io.File(path), expectedSha)) {
                    if (callback != null) {
                        try {
                            callback.onError(new InferenceError(
                                    InferenceError.ERROR_MODEL_INTEGRITY_FAILED,
                                    "Integrity check failed for: " + modelId, false));
                        } catch (RemoteException e) {
                            Log.w(TAG, "Callback dead on integrity error", e);
                        }
                    }
                    return;
                }

                DeviceCapabilities caps = getOrDetectCapabilities();
                int memBudget = caps.availableRamMb / 2;
                boolean ok = mBackend.load(path, 0, memBudget);

                if (ok) {
                    mLoadedModelId = modelId;
                    if (callback != null) {
                        try {
                            callback.onModelLoaded(modelId);
                        } catch (RemoteException e) {
                            Log.w(TAG, "Callback dead after load", e);
                        }
                    }
                } else {
                    if (callback != null) {
                        try {
                            callback.onError(new InferenceError(
                                    InferenceError.ERROR_INSUFFICIENT_MEMORY,
                                    "Failed to load model: " + modelId, true));
                        } catch (RemoteException e) {
                            Log.w(TAG, "Callback dead on load failure", e);
                        }
                    }
                }
            });
        }

        @Override
        public void unloadModel(String modelId) {
            mHandler.post(() -> {
                if (modelId.equals(mLoadedModelId)) {
                    mBackend.unload();
                    mLoadedModelId = null;
                    Log.i(TAG, "Unloaded model: " + modelId);
                }
            });
        }

        @Override
        public String getLoadedModelId() {
            return mLoadedModelId;
        }

        @Override
        public InferenceResponse generate(InferenceRequest request) {
            if (!mBackend.isLoaded()) {
                InferenceResponse err = new InferenceResponse();
                err.text = "";
                err.truncated = false;
                return err;
            }
            return mBackend.generate(request);
        }

        @Override
        public void generateStream(InferenceRequest request, IInferenceCallback callback) {
            mHandler.post(() -> {
                if (!mBackend.isLoaded()) {
                    if (callback != null) {
                        try {
                            callback.onError(new InferenceError(
                                    InferenceError.ERROR_NO_MODEL_LOADED,
                                    "No model is currently loaded", true));
                        } catch (RemoteException e) {
                            Log.w(TAG, "Callback dead on generateStream", e);
                        }
                    }
                    return;
                }

                InferenceResponse response = mBackend.generate(request);

                if (callback != null) {
                    try {
                        // Phase 1: emit single token containing full response, then complete
                        Token t = new Token();
                        t.text    = response.text;
                        t.index   = 0;
                        t.isFinal = true;
                        t.logprob = Float.NaN;
                        callback.onToken(t);
                        callback.onComplete(response);
                    } catch (RemoteException e) {
                        Log.w(TAG, "Callback dead during generateStream", e);
                    }
                }
            });
        }

        @Override
        public void cancelGeneration() {
            // Phase 1: no cancellation mechanism; queued work completes naturally
            Log.d(TAG, "cancelGeneration() called — not implemented in Phase 1");
        }

        @Override
        public ResourceMetrics getResourceMetrics() {
            return buildResourceMetrics();
        }

        @Override
        public void registerResourceCallback(IResourceCallback callback) {
            if (callback != null) {
                mResourceCallbacks.register(callback);
            }
        }

        @Override
        public void unregisterResourceCallback(IResourceCallback callback) {
            if (callback != null) {
                mResourceCallbacks.unregister(callback);
            }
        }
    }

    // ── Lifecycle wrapper ─────────────────────────────────────────────────────

    /**
     * Lifecycle wrapper required by SystemServiceManager for reflection-based
     * instantiation. Follows the same pattern as all other Circle services.
     */
    public static final class Lifecycle extends SystemService {

        private CircleInferenceService mService;

        public Lifecycle(Context context) {
            super(context);
        }

        @Override
        public void onStart() {
            mService = new CircleInferenceService(getContext());
            mService.onStart();
        }

        @Override
        public void onBootPhase(int phase) {
            mService.onBootPhase(phase);
        }
    }
}
