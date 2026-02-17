/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import za.co.circleos.inference.ResourceMetrics;

/**
 * Callback interface for resource pressure and thermal events.
 */
oneway interface IResourceCallback {
    /** Called when memory pressure is detected. */
    void onMemoryPressure(in ResourceMetrics metrics);

    /** Called when thermal throttling begins or changes state. */
    void onThermalThrottle(int thermalState);

    /** Called when a model is evicted from memory due to resource pressure. */
    void onModelEvicted(String modelId);
}
