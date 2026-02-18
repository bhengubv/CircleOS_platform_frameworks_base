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

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * CircleOS on-device LLM inference system service.
 *
 * Phase 4 additions:
 *   - getDownloadableModels() — queries remote model store manifest
 *   - downloadModel()         — downloads a model to /data/circle/models/
 *
 * Service name: "circle.inference"
 * Permission:   com.circleos.permission.ACCESS_INFERENCE
 */
public class CircleInferenceService extends SystemService {

    private static final String TAG          = "CircleInference";
    private static final String SERVICE_NAME = "circle.inference";
    private static final int    SERVICE_VERSION = 4; // Phase 4

    // Remote model store manifest URL — configurable via system property
    private static final String MODEL_STORE_MANIFEST_URL =
            "https://models.circleos.co.za/manifest.json";

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

    public CircleInferenceService(Context context) {
        super(context);
    }

    // ── SystemService lifecycle ───────────────────────────────────────────────

    @Override
    public void onStart() {
        Log.i(TAG, "Starting CircleInferenceService v" + SERVICE_VERSION);

        mHandlerThread = new HandlerThread("CircleInference");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        mCapabilityDetector = new CapabilityDetector(getContext());
        mModelManager       = new ModelManager();
        mBackend            = new LlamaCppBackend();

        publishBinderService(SERVICE_NAME, new InferenceImpl());
        Log.i(TAG, "Published as " + SERVICE_NAME);
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed — loading optimal model and refreshing remote manifest");
            mHandler.post(this::loadOptimalModelAsync);
            // Fetch remote model store manifest in background after boot
            mHandler.post(() -> {
                String url = android.os.SystemProperties.get(
                        "circleos.inference.model_store_url", MODEL_STORE_MANIFEST_URL);
                mModelManager.refreshRemoteManifest(url);
            });
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private void loadOptimalModelAsync() {
        DeviceCapabilities caps = getOrDetectCapabilities();
        ModelInfo best = mModelManager.selectOptimalModel(caps.recommendedTier);

        if (best == null) {
            Log.i(TAG, "No suitable model for tier " + caps.recommendedTier);
            return;
        }

        String path = mModelManager.getModelPath(best.id);
        if (path == null) { Log.w(TAG, "Path not found for: " + best.id); return; }

        String sha = mModelManager.getExpectedChecksum(best.id);
        if (sha != null && !mModelManager.verifyIntegrity(new File(path), sha)) {
            Log.e(TAG, "Integrity check failed — not loading: " + best.id); return;
        }

        int memBudget = caps.availableRamMb / 2;
        if (mBackend.load(path, 0, memBudget)) {
            mLoadedModelId = best.id;
            Log.i(TAG, "Auto-loaded: " + best.id);
        } else {
            Log.e(TAG, "Failed to auto-load: " + best.id);
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
        m.memoryBudgetMb  = caps.availableRamMb / 2;
        m.modelLoaded     = mBackend.isLoaded();
        m.thermalState    = 0;
        m.tokensPerSecond = 0f;
        if (m.modelLoaded) m.memoryUsedMb = caps.availableRamMb / 4;
        return m;
    }

    // ── Binder implementation ─────────────────────────────────────────────────

    private final class InferenceImpl extends ICircleInference.Stub {

        @Override public DeviceCapabilities getDeviceCapabilities() {
            return getOrDetectCapabilities();
        }

        @Override public int getServiceVersion() { return SERVICE_VERSION; }

        @Override public List<ModelInfo> listModels() {
            return mModelManager.listAvailableModels();
        }

        @Override public void loadModel(String modelId, IInferenceCallback callback) {
            mHandler.post(() -> {
                // null modelId = load optimal
                if (modelId == null) {
                    loadOptimalModelAsync();
                    if (callback != null && mLoadedModelId != null) {
                        try { callback.onModelLoaded(mLoadedModelId); }
                        catch (RemoteException e) { Log.w(TAG, "callback dead", e); }
                    }
                    return;
                }

                if (mBackend.isLoaded()) { mBackend.unload(); mLoadedModelId = null; }

                String path = mModelManager.getModelPath(modelId);
                if (path == null) {
                    notifyError(callback, InferenceError.ERROR_MODEL_NOT_FOUND,
                            "Model not found: " + modelId, false); return;
                }

                String sha = mModelManager.getExpectedChecksum(modelId);
                if (sha != null && !mModelManager.verifyIntegrity(new File(path), sha)) {
                    notifyError(callback, InferenceError.ERROR_MODEL_INTEGRITY_FAILED,
                            "Integrity failed: " + modelId, false); return;
                }

                DeviceCapabilities caps = getOrDetectCapabilities();
                if (mBackend.load(path, 0, caps.availableRamMb / 2)) {
                    mLoadedModelId = modelId;
                    if (callback != null) {
                        try { callback.onModelLoaded(modelId); }
                        catch (RemoteException e) { Log.w(TAG, "callback dead", e); }
                    }
                } else {
                    notifyError(callback, InferenceError.ERROR_INSUFFICIENT_MEMORY,
                            "Failed to load: " + modelId, true);
                }
            });
        }

        @Override public void unloadModel(String modelId) {
            mHandler.post(() -> {
                if (modelId == null || modelId.equals(mLoadedModelId)) {
                    mBackend.unload(); mLoadedModelId = null;
                    Log.i(TAG, "Unloaded model");
                }
            });
        }

        @Override public String getLoadedModelId() { return mLoadedModelId; }

        @Override public InferenceResponse generate(InferenceRequest request) {
            if (!mBackend.isLoaded()) {
                InferenceResponse r = new InferenceResponse(); r.text = ""; return r;
            }
            return mBackend.generate(request);
        }

        @Override public void generateStream(InferenceRequest request, IInferenceCallback callback) {
            mHandler.post(() -> {
                if (!mBackend.isLoaded()) {
                    notifyError(callback, InferenceError.ERROR_NO_MODEL_LOADED,
                            "No model loaded", true); return;
                }
                InferenceResponse response = mBackend.generate(request);
                if (callback != null) {
                    try {
                        Token t = new Token();
                        t.text = response.text; t.index = 0;
                        t.isFinal = true; t.logprob = Float.NaN;
                        callback.onToken(t);
                        callback.onComplete(response);
                    } catch (RemoteException e) {
                        Log.w(TAG, "Callback dead during stream", e);
                    }
                }
            });
        }

        @Override public void cancelGeneration() {
            Log.d(TAG, "cancelGeneration() — queued requests will drain naturally");
        }

        @Override public ResourceMetrics getResourceMetrics() { return buildResourceMetrics(); }

        @Override public void registerResourceCallback(IResourceCallback callback) {
            if (callback != null) mResourceCallbacks.register(callback);
        }

        @Override public void unregisterResourceCallback(IResourceCallback callback) {
            if (callback != null) mResourceCallbacks.unregister(callback);
        }

        // ── Model store (Phase 4) ─────────────────────────────────────────────

        @Override public List<ModelInfo> getDownloadableModels() {
            // Merge local (bundled + downloaded) with cached remote manifest.
            // Local entries take precedence so isDownloaded stays accurate.
            Map<String, ModelInfo> seen = new LinkedHashMap<>();
            for (ModelInfo m : mModelManager.listAvailableModels()) seen.put(m.id, m);
            for (ModelInfo m : mModelManager.getCachedRemoteModels()) {
                if (!seen.containsKey(m.id)) seen.put(m.id, m);
            }
            return new ArrayList<>(seen.values());
        }

        @Override public void downloadModel(String modelId, IInferenceCallback callback) {
            mHandler.post(() -> {
                mModelManager.downloadModel(modelId, new ModelManager.DownloadCallback() {
                    @Override
                    public void onProgress(String id, long received, long total) {
                        if (callback == null) return;
                        try {
                            Token progress = new Token();
                            progress.text = "progress:" + received + ":" + total;
                            progress.index = 0; progress.isFinal = false;
                            callback.onToken(progress);
                        } catch (RemoteException e) {
                            Log.w(TAG, "progress callback dead", e);
                        }
                    }

                    @Override public void onComplete(String id) {
                        if (callback == null) return;
                        try { callback.onModelLoaded(id); }
                        catch (RemoteException e) { Log.w(TAG, "complete callback dead", e); }
                    }

                    @Override public void onError(String id, String message) {
                        notifyError(callback, InferenceError.ERROR_INTERNAL, message, true);
                    }
                });
            });
        }

        private void notifyError(IInferenceCallback cb, int code, String msg, boolean recoverable) {
            if (cb == null) return;
            try {
                InferenceError err = new InferenceError(code, msg, recoverable);
                cb.onError(err);
            } catch (RemoteException e) {
                Log.w(TAG, "error callback dead", e);
            }
        }
    }

    // ── Lifecycle wrapper ─────────────────────────────────────────────────────

    public static final class Lifecycle extends SystemService {
        private CircleInferenceService mService;

        public Lifecycle(Context context) { super(context); }

        @Override public void onStart() {
            mService = new CircleInferenceService(getContext());
            mService.onStart();
        }

        @Override public void onBootPhase(int phase) { mService.onBootPhase(phase); }
    }
}
