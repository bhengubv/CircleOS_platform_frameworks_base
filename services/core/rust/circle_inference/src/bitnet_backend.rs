/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! BitNet.cpp inference backend.
//!
//! BitNet.cpp is Microsoft's reference implementation for 1-bit LLM inference.
//! It delivers 1.37x–5.07x speedup and 55–70% energy reduction vs full-precision
//! models on ARM CPUs, making it ideal for Tier 2+ Circle OS devices.
//!
//! Feature gate: only compiled when `bitnet_native` Cargo feature is enabled.
//! Without that feature, all methods return stub responses — the service
//! compiles and runs but reports "bitnet stub mode" to callers.
//!
//! Supported model formats: BitNet native (.bitnet) and GGUF 1-bit variants.
//! Minimum device tier: Tier 2 (4 GB RAM).

use std::collections::HashMap;
use std::sync::{Mutex, atomic::{AtomicI64, Ordering}};
use std::time::Instant;

use crate::backend::InferenceBackend;
use crate::types::{
    BackendCapabilities, DeviceTier, GenerateRequest, GenerateResponse,
    InferenceError, ModelConfig, ModelFormat, ModelHandle,
    ResourceMetrics, Result, StreamControl, Token,
};

// ── BitNet.cpp FFI declarations ───────────────────────────────────────────────
// Only compiled when native library is present and linked.

#[cfg(feature = "bitnet_native")]
mod ffi {
    use std::ffi::{c_char, c_float, c_int, c_void};

    /// Opaque BitNet model context.
    #[repr(C)]
    pub struct BitnetContext { _opaque: [u8; 0] }

    #[repr(C)]
    #[derive(Default)]
    pub struct BitnetParams {
        pub n_ctx: u32,
        pub n_threads: c_int,
        pub memory_budget_mb: u32,
    }

    #[link(name = "bitnet")]
    extern "C" {
        /// Initialise a BitNet context from a model file.
        /// Returns null on failure.
        pub fn bitnet_init_from_file(
            path: *const c_char,
            params: BitnetParams,
        ) -> *mut BitnetContext;

        /// Run inference synchronously. Writes generated text into out_buf.
        /// Returns bytes written, or -1 on error.
        pub fn bitnet_generate(
            ctx: *mut BitnetContext,
            prompt: *const c_char,
            max_tokens: c_int,
            temperature: c_float,
            out_buf: *mut c_char,
            out_buf_len: c_int,
        ) -> c_int;

        /// Free all resources associated with the context.
        pub fn bitnet_free(ctx: *mut BitnetContext);

        /// Returns the number of model parameters in millions.
        pub fn bitnet_n_params(ctx: *const BitnetContext) -> u64;

        /// Returns current memory usage in MB.
        pub fn bitnet_memory_usage_mb(ctx: *const BitnetContext) -> u32;
    }
}

// ── Loaded model record ───────────────────────────────────────────────────────

struct LoadedModel {
    config: ModelConfig,
    loaded_at: Instant,
    #[cfg(feature = "bitnet_native")]
    ctx: *mut ffi::BitnetContext,
}

#[cfg(feature = "bitnet_native")]
unsafe impl Send for LoadedModel {}
#[cfg(feature = "bitnet_native")]
unsafe impl Sync for LoadedModel {}

// ── Backend ───────────────────────────────────────────────────────────────────

pub struct BitNetBackend {
    models: Mutex<HashMap<ModelHandle, LoadedModel>>,
    next_handle: AtomicI64,
}

impl BitNetBackend {
    pub fn new() -> Self {
        BitNetBackend {
            models: Mutex::new(HashMap::new()),
            next_handle: AtomicI64::new(1),
        }
    }

    fn alloc_handle(&self) -> ModelHandle {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns true if BitNet is available and beneficial for the given tier.
    /// Tier 1 (< 3 GB RAM) is excluded — too constrained for BitNet 2B.
    pub fn is_suitable_for_tier(tier: DeviceTier) -> bool {
        #[cfg(feature = "bitnet_native")]
        return tier >= DeviceTier::Tier2;
        #[cfg(not(feature = "bitnet_native"))]
        return false;
    }
}

impl Default for BitNetBackend {
    fn default() -> Self { Self::new() }
}

impl InferenceBackend for BitNetBackend {
    fn load_model(&mut self, config: ModelConfig) -> Result<ModelHandle> {
        let handle = self.alloc_handle();

        #[cfg(feature = "bitnet_native")]
        {
            use std::ffi::CString;
            let path_c = CString::new(config.path.as_str())
                .map_err(|e| InferenceError::ModelLoadFailed(e.to_string()))?;

            let params = ffi::BitnetParams {
                n_ctx: if config.context_size > 0 { config.context_size } else { 4096 },
                n_threads: 0, // 0 = auto-detect
                memory_budget_mb: config.memory_budget_mb,
            };

            let ctx = unsafe { ffi::bitnet_init_from_file(path_c.as_ptr(), params) };
            if ctx.is_null() {
                return Err(InferenceError::ModelLoadFailed(
                    format!("bitnet_init_from_file failed for {}", config.path),
                ));
            }

            self.models.lock().unwrap().insert(handle, LoadedModel {
                config, loaded_at: Instant::now(), ctx,
            });
        }

        #[cfg(not(feature = "bitnet_native"))]
        {
            self.models.lock().unwrap().insert(handle, LoadedModel {
                config, loaded_at: Instant::now(),
            });
        }

        Ok(handle)
    }

    fn unload_model(&mut self, handle: ModelHandle) -> Result<()> {
        let mut models = self.models.lock().unwrap();
        match models.remove(&handle) {
            None => Err(InferenceError::InvalidHandle(handle)),
            Some(record) => {
                #[cfg(feature = "bitnet_native")]
                unsafe { ffi::bitnet_free(record.ctx); }
                let _ = record;
                Ok(())
            }
        }
    }

    fn generate(&self, handle: ModelHandle, request: GenerateRequest) -> Result<GenerateResponse> {
        let start = Instant::now();
        let models = self.models.lock().unwrap();

        if !models.contains_key(&handle) {
            return Err(InferenceError::InvalidHandle(handle));
        }

        let text = {
            #[cfg(feature = "bitnet_native")]
            {
                use std::ffi::CString;
                let prompt_c = CString::new(request.prompt.as_str())
                    .map_err(|e| InferenceError::GenerateFailed(e.to_string()))?;
                let mut buf = vec![0u8; 4 * 1024 * 1024];
                let record = models.get(&handle).unwrap();
                let written = unsafe {
                    ffi::bitnet_generate(
                        record.ctx,
                        prompt_c.as_ptr(),
                        request.max_tokens as i32,
                        request.temperature,
                        buf.as_mut_ptr() as *mut _,
                        buf.len() as i32,
                    )
                };
                if written < 0 {
                    return Err(InferenceError::GenerateFailed("bitnet_generate returned -1".into()));
                }
                String::from_utf8_lossy(&buf[..written as usize]).into_owned()
            }
            #[cfg(not(feature = "bitnet_native"))]
            {
                "[BitNet.cpp not yet linked — Phase 3 stub. Enable bitnet_native feature when libbitnet.so is available.]".to_string()
            }
        };

        let latency_ms = start.elapsed().as_millis() as u64;
        let prompt_tokens = (request.prompt.len() / 4).max(1) as u32;
        let completion_tokens = (text.len() / 4).max(1) as u32;

        Ok(GenerateResponse {
            text,
            prompt_tokens,
            completion_tokens,
            latency_ms,
            truncated: completion_tokens >= request.max_tokens,
        })
    }

    fn generate_stream(
        &self,
        handle: ModelHandle,
        request: GenerateRequest,
        callback: Box<dyn Fn(Token) -> StreamControl + Send>,
    ) -> Result<()> {
        // Phase 3: delegate to synchronous generate; true token streaming in Phase 4+
        let response = self.generate(handle, request)?;
        callback(Token {
            text: response.text,
            index: 0,
            is_final: true,
            logprob: f32::NAN,
        });
        Ok(())
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "bitnet.cpp".to_string(),
            supports_gpu: false, // BitNet is CPU-optimised; GPU path future work
            supports_streaming: true,
            max_context_size: 4096,
            supported_formats: vec![ModelFormat::BitNetNative, ModelFormat::Gguf, ModelFormat::Auto],
        }
    }

    fn resource_usage(&self) -> ResourceMetrics {
        let models = self.models.lock().unwrap();
        let memory_used = {
            #[cfg(feature = "bitnet_native")]
            if let Some(record) = models.values().next() {
                unsafe { ffi::bitnet_memory_usage_mb(record.ctx) }
            } else { 0 }
            #[cfg(not(feature = "bitnet_native"))]
            0u32
        };

        ResourceMetrics {
            memory_used_mb: memory_used,
            memory_budget_mb: 0,
            tokens_per_second: 0.0,
            model_loaded: !models.is_empty(),
            thermal_state: 0,
        }
    }
}
