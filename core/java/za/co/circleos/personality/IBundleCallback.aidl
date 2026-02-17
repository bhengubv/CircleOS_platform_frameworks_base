/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.personality;

oneway interface IBundleCallback {
    void onProgress(String modeId, int progressPercent);
    void onComplete(String modeId, boolean success, String errorMessage);
}
