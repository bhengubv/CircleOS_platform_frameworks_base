/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.compression;

import za.co.circleos.compression.CompressionResult;

/**
 * Callback interface for asynchronous compression notifications.
 * Phase 2: wire into CircleCompressionService for push-based results.
 */
oneway interface ICompressionCallback {
    void onComplete(in CompressionResult result);
    void onProgress(String sessionId, int percentDone);
    void onError(String sessionId, int errorCode, String message);
}
