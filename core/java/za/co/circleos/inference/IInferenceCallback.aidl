/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.inference;

import za.co.circleos.inference.Token;
import za.co.circleos.inference.InferenceResponse;
import za.co.circleos.inference.InferenceError;

/**
 * Callback interface for streaming inference results and model lifecycle events.
 */
oneway interface IInferenceCallback {
    /** Called for each token generated during streaming inference. */
    void onToken(in Token token);

    /** Called when inference completes successfully. */
    void onComplete(in InferenceResponse response);

    /** Called when inference encounters an error. */
    void onError(in InferenceError error);

    /** Called when a model has finished loading and is ready for inference. */
    void onModelLoaded(String modelId);
}
