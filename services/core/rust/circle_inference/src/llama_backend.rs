/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! llama.cpp inference backend.
//!
//! When the `llama_native` Cargo feature is enabled, this module uses real
//! llama.cpp FFI calls. Without the feature, it runs in stub mode returning
//! placeholder responses — allowing the service to compile and operate
//! without the native binary present (Phase 1 / Phase 2 without llama.cpp).

use std::collections::HashMap;
use std::sync::{atomic::{AtomicI64, Ordering}, Mutex};
use std::time::Instant;

use crate::backend::InferenceBackend;
use crate::types::{
    BackendCapabilities, DeviceTier, GenerateRequest, GenerateResponse,
    InferenceError, ModelConfig, ModelHandle, ModelFormat,
    ResourceMetrics, Result, StreamControl, Token,
};

// ── llama.cpp FFI declarations ────────────────────────────────────────────────
// Only compiled when the native library is available.

#[cfg(feature = "llama_native")]
mod ffi {
    use std::ffi::{c_char, c_float, c_int, c_void};

    /// Opaque model struct.
    #[repr(C)]
    pub struct LlamaModel { _opaque: [u8; 0] }

    /// Opaque context struct.
    #[repr(C)]
    pub struct LlamaContext { _opaque: [u8; 0] }

    #[repr(C)]
    #[derive(Default)]
    pub struct LlamaModelParams {
        pub n_gpu_layers: c_int,
        pub main_gpu: c_int,
        pub use_mmap: bool,
        pub use_mlock: bool,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct LlamaContextParams {
        pub n_ctx: u32,
        pub n_batch: u32,
        pub n_threads: c_int,
        pub seed: u32,
    }

    #[link(name = "llama")]
    extern "C" {
        pub fn llama_model_default_params() -> LlamaModelParams;
        pub fn llama_context_default_params() -> LlamaContextParams;
        pub fn llama_load_model_from_file(
            path: *const c_char,
            params: LlamaModelParams,
        ) -> *mut LlamaModel;
        pub fn llama_new_context_with_model(
            model: *mut LlamaModel,
            params: LlamaContextParams,
        ) -> *mut LlamaContext;
        pub fn llama_free_model(model: *mut LlamaModel);
        pub fn llama_free(ctx: *mut LlamaContext);
    }
}

// ── Loaded model record ───────────────────────────────────────────────────────

struct LoadedModel {
    config: ModelConfig,
    #[cfg(feature = "llama_native")]
    ctx: *mut ffi::LlamaContext,
    #[cfg(feature = "llama_native")]
    model: *mut ffi::LlamaModel,
    loaded_at: Instant,
}

// SAFETY: LlamaContext/Model are accessed only under the registry Mutex.
#[cfg(feature = "llama_native")]
unsafe impl Send for LoadedModel {}
#[cfg(feature = "llama_native")]
unsafe impl Sync for LoadedModel {}

// ── Backend implementation ────────────────────────────────────────────────────

/// llama.cpp inference backend.
///
/// Thread-safety: the model registry is protected by a Mutex. Generation
/// calls are serialised by the Java service layer (single HandlerThread).
pub struct LlamaCppBackend {
    models: Mutex<HashMap<ModelHandle, LoadedModel>>,
    next_handle: AtomicI64,
}

impl LlamaCppBackend {
    pub fn new() -> Self {
        LlamaCppBackend {
            models: Mutex::new(HashMap::new()),
            next_handle: AtomicI64::new(1),
        }
    }

    fn alloc_handle(&self) -> ModelHandle {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for LlamaCppBackend {
    fn default() -> Self { Self::new() }
}

impl InferenceBackend for LlamaCppBackend {
    fn load_model(&mut self, config: ModelConfig) -> Result<ModelHandle> {
        let handle = self.alloc_handle();

        #[cfg(feature = "llama_native")]
        {
            use std::ffi::CString;
            let path_c = CString::new(config.path.as_str())
                .map_err(|e| InferenceError::ModelLoadFailed(e.to_string()))?;

            let model_params = unsafe { ffi::llama_model_default_params() };
            let model = unsafe { ffi::llama_load_model_from_file(path_c.as_ptr(), model_params) };
            if model.is_null() {
                return Err(InferenceError::ModelLoadFailed(
                    format!("llama_load_model_from_file returned null for {}", config.path),
                ));
            }

            let mut ctx_params = unsafe { ffi::llama_context_default_params() };
            if config.context_size > 0 {
                ctx_params.n_ctx = config.context_size;
            }

            let ctx = unsafe { ffi::llama_new_context_with_model(model, ctx_params) };
            if ctx.is_null() {
                unsafe { ffi::llama_free_model(model) };
                return Err(InferenceError::ModelLoadFailed("context creation failed".into()));
            }

            let record = LoadedModel { config, ctx, model, loaded_at: Instant::now() };
            self.models.lock().unwrap().insert(handle, record);
        }

        #[cfg(not(feature = "llama_native"))]
        {
            // Stub mode: store config only
            let record = LoadedModel { config, loaded_at: Instant::now() };
            self.models.lock().unwrap().insert(handle, record);
        }

        Ok(handle)
    }

    fn unload_model(&mut self, handle: ModelHandle) -> Result<()> {
        let mut models = self.models.lock().unwrap();
        match models.remove(&handle) {
            None => Err(InferenceError::InvalidHandle(handle)),
            Some(record) => {
                #[cfg(feature = "llama_native")]
                unsafe {
                    ffi::llama_free(record.ctx);
                    ffi::llama_free_model(record.model);
                }
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

        // Phase 2 stub: real tokenisation + sampling wired in Phase 3
        let text = {
            #[cfg(feature = "llama_native")]
            {
                // TODO Phase 3: call llama_decode(), sample tokens
                "[llama.cpp native generation — Phase 3]".to_string()
            }
            #[cfg(not(feature = "llama_native"))]
            {
                "[llama.cpp not yet linked — Phase 2 Rust stub]".to_string()
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
        // Phase 2: delegate to synchronous generate, then emit as a single token
        let response = self.generate(handle, request)?;
        let token = Token {
            text: response.text,
            index: 0,
            is_final: true,
            logprob: f32::NAN,
        };
        callback(token);
        Ok(())
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "llama.cpp".to_string(),
            supports_gpu: false, // Phase 2: CPU only; GPU via Vulkan in Phase 3+
            supports_streaming: true,
            max_context_size: 4096,
            supported_formats: vec![ModelFormat::Gguf, ModelFormat::Auto],
        }
    }

    fn resource_usage(&self) -> ResourceMetrics {
        let models = self.models.lock().unwrap();
        ResourceMetrics {
            memory_used_mb: 0, // Phase 3: query llama_context for actual usage
            memory_budget_mb: 0,
            tokens_per_second: 0.0,
            model_loaded: !models.is_empty(),
            thermal_state: 0,
        }
    }
}
