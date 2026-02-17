/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * C ABI exported by the Rust circle_inference crate.
 * Used by circle_inference_jni.cpp to call into the Rust abstraction layer.
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load a GGUF model file into the inference backend.
 *
 * @param model_path      Absolute path to the .gguf model file (UTF-8, null-terminated).
 * @param context_size    Context window in tokens. 0 = use model default.
 * @param memory_budget_mb Maximum memory the model may use, in MB.
 * @return Opaque handle > 0 on success; 0 on failure.
 */
int64_t circle_inference_load(const char* model_path,
                               int32_t context_size,
                               int32_t memory_budget_mb);

/**
 * Generate text from a prompt.
 *
 * @param handle          Handle returned by circle_inference_load.
 * @param prompt          Input prompt (UTF-8, null-terminated).
 * @param max_tokens      Maximum tokens to generate.
 * @param temperature     Sampling temperature (0.0 = deterministic).
 * @param out_buf         Caller-allocated buffer to receive generated text (UTF-8).
 * @param out_buf_len     Size of out_buf in bytes.
 * @return Bytes written to out_buf (not counting null terminator), or -1 on error.
 */
int32_t circle_inference_generate(int64_t handle,
                                   const char* prompt,
                                   int32_t max_tokens,
                                   float temperature,
                                   char* out_buf,
                                   int32_t out_buf_len);

/**
 * Unload the model associated with handle and free all native resources.
 *
 * @param handle Handle returned by circle_inference_load.
 */
void circle_inference_unload(int64_t handle);

/**
 * Returns 1 if the native inference backend is compiled and available;
 * 0 if running in stub/placeholder mode (Phase 1-2 without llama.cpp linked).
 */
int32_t circle_inference_is_native_available(void);

#ifdef __cplusplus
}
#endif
