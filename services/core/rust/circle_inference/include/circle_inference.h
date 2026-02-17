/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * C ABI exported by the Rust circle_inference crate.
 * Phase 3: adds circle_inference_backend_name().
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load a model using the auto-selected backend (BitNet or llama.cpp).
 * Returns handle > 0 on success; 0 on failure.
 */
int64_t circle_inference_load(const char* model_path,
                               int32_t context_size,
                               int32_t memory_budget_mb);

/**
 * Generate text. Writes UTF-8 result into out_buf (null-terminated).
 * Returns bytes written, or -1 on error.
 */
int32_t circle_inference_generate(int64_t handle,
                                   const char* prompt,
                                   int32_t max_tokens,
                                   float temperature,
                                   char* out_buf,
                                   int32_t out_buf_len);

/**
 * Unload the model and free all native resources.
 */
void circle_inference_unload(int64_t handle);

/**
 * Returns 1 if a native backend is compiled in; 0 for stub mode.
 */
int32_t circle_inference_is_native_available(void);

/**
 * Writes the active backend name ("llama.cpp" or "bitnet.cpp") for
 * the given handle into out_buf. Returns bytes written, or -1 on error.
 * Phase 3+.
 */
int32_t circle_inference_backend_name(int64_t handle,
                                       char* out_buf,
                                       int32_t out_buf_len);

#ifdef __cplusplus
}
#endif
