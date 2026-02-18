/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! llama.cpp inference backend — Phase 3: real tokenise / decode / sample loop.
//!
//! When the `llama_native` Cargo feature is enabled, this module uses real
//! llama.cpp FFI calls.  Without the feature it runs in stub mode returning
//! placeholder responses (Phase 1/2 without llama.cpp present).

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Mutex,
};
use std::time::Instant;

use crate::backend::InferenceBackend;
use crate::types::{
    BackendCapabilities, GenerateRequest, GenerateResponse, InferenceError,
    ModelConfig, ModelFormat, ModelHandle, ResourceMetrics, Result, StreamControl,
    Token,
};

// ── llama.cpp FFI declarations ────────────────────────────────────────────────

#[cfg(feature = "llama_native")]
mod ffi {
    use std::ffi::{c_char, c_float, c_int};

    pub type LlamaToken = i32;
    pub type LlamaPos   = i32;
    pub type LlamaSeqId = i32;

    /// Opaque llama_model struct.
    #[repr(C)]
    pub struct LlamaModel { _opaque: [u8; 0] }

    /// Opaque llama_context struct.
    #[repr(C)]
    pub struct LlamaContext { _opaque: [u8; 0] }

    #[repr(C)]
    #[derive(Default)]
    pub struct LlamaModelParams {
        pub n_gpu_layers: c_int,
        pub main_gpu:     c_int,
        pub use_mmap:     bool,
        pub use_mlock:    bool,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct LlamaContextParams {
        pub n_ctx:     u32,
        pub n_batch:   u32,
        pub n_threads: c_int,
        pub seed:      u32,
    }

    /// Per-token candidate for sampling.
    #[repr(C)]
    pub struct LlamaTokenData {
        pub id:    LlamaToken,
        pub logit: c_float,
        pub p:     c_float,
    }

    /// Slice wrapper passed to sampling functions.
    #[repr(C)]
    pub struct LlamaTokenDataArray {
        pub data:   *mut LlamaTokenData,
        pub size:   usize,
        pub sorted: bool,
    }

    /// Mirror of the llama_batch C struct. All pointer fields are managed by
    /// llama_batch_init / llama_batch_free — do not allocate them separately.
    #[repr(C)]
    pub struct LlamaBatch {
        pub n_tokens:  i32,
        pub token:     *mut LlamaToken,
        pub embd:      *mut c_float,
        pub pos:       *mut LlamaPos,
        pub n_seq_id:  *mut i32,
        pub seq_id:    *mut *mut LlamaSeqId,
        pub logits:    *mut i8,
    }

    #[link(name = "llama")]
    extern "C" {
        // ── Model / context lifecycle ──────────────────────────────────────────
        pub fn llama_model_default_params()   -> LlamaModelParams;
        pub fn llama_context_default_params() -> LlamaContextParams;
        pub fn llama_load_model_from_file(
            path:   *const c_char,
            params: LlamaModelParams,
        ) -> *mut LlamaModel;
        pub fn llama_new_context_with_model(
            model:  *mut LlamaModel,
            params: LlamaContextParams,
        ) -> *mut LlamaContext;
        pub fn llama_free_model(model: *mut LlamaModel);
        pub fn llama_free(ctx: *mut LlamaContext);

        // ── Tokenisation ──────────────────────────────────────────────────────
        /// Tokenise `text` into `tokens`. Returns number of tokens written
        /// (positive), or the negative of the required buffer size on overflow.
        pub fn llama_tokenize(
            model:        *const LlamaModel,
            text:         *const c_char,
            text_len:     c_int,
            tokens:       *mut LlamaToken,
            n_tokens_max: c_int,
            add_bos:      bool,
            special:      bool,
        ) -> c_int;

        /// Convert a single token to its UTF-8 string piece.
        /// Returns bytes written, negative on error.
        pub fn llama_token_to_piece(
            model:   *const LlamaModel,
            token:   LlamaToken,
            buf:     *mut c_char,
            length:  c_int,
            lstrip:  c_int,
            special: bool,
        ) -> c_int;

        /// End-of-sequence token id for this model.
        pub fn llama_token_eos(model: *const LlamaModel) -> LlamaToken;
        /// Beginning-of-sequence token id for this model.
        pub fn llama_token_bos(model: *const LlamaModel) -> LlamaToken;

        // ── Batch operations ──────────────────────────────────────────────────
        /// Allocate a batch for at most `n_tokens` tokens per step.
        /// `embd` = 0 for token-based mode; `n_seq_max` = max sequences per token.
        pub fn llama_batch_init(n_tokens: i32, embd: c_int, n_seq_max: c_int) -> LlamaBatch;
        pub fn llama_batch_free(batch: LlamaBatch);

        // ── Decoding ──────────────────────────────────────────────────────────
        /// Run model forward pass on `batch`. Returns 0 on success.
        pub fn llama_decode(ctx: *mut LlamaContext, batch: LlamaBatch) -> c_int;

        // ── Logits / sampling ─────────────────────────────────────────────────
        /// Return logit vector (n_vocab floats) for batch position `i`.
        pub fn llama_get_logits_ith(ctx: *mut LlamaContext, i: i32) -> *mut c_float;
        /// Vocabulary size of the model.
        pub fn llama_n_vocab(model: *const LlamaModel) -> c_int;

        /// Greedy sampling (argmax).
        pub fn llama_sample_token_greedy(
            ctx:        *mut LlamaContext,
            candidates: *mut LlamaTokenDataArray,
        ) -> LlamaToken;

        /// Apply temperature scaling in-place.
        pub fn llama_sample_temp(
            ctx:        *mut LlamaContext,
            candidates: *mut LlamaTokenDataArray,
            temp:       c_float,
        );

        /// Apply nucleus (top-p) filtering in-place.
        pub fn llama_sample_top_p(
            ctx:        *mut LlamaContext,
            candidates: *mut LlamaTokenDataArray,
            p:          c_float,
            min_keep:   usize,
        );

        /// Sample one token from the (already filtered) distribution.
        pub fn llama_sample_token(
            ctx:        *mut LlamaContext,
            candidates: *mut LlamaTokenDataArray,
        ) -> LlamaToken;

        // ── Context metadata ──────────────────────────────────────────────────
        pub fn llama_n_ctx(ctx: *const LlamaContext) -> u32;
        pub fn llama_get_kv_cache_used_cells(ctx: *const LlamaContext) -> i32;
        pub fn llama_get_model(ctx: *const LlamaContext) -> *const LlamaModel;

        // ── KV cache management ───────────────────────────────────────────────
        /// Remove all entries from the KV cache.
        pub fn llama_kv_cache_clear(ctx: *mut LlamaContext);
    }
}

// ── Loaded-model record ───────────────────────────────────────────────────────

struct LoadedModel {
    config: ModelConfig,
    #[cfg(feature = "llama_native")]
    ctx: *mut ffi::LlamaContext,
    #[cfg(feature = "llama_native")]
    model: *mut ffi::LlamaModel,
    loaded_at: Instant,
}

// SAFETY: LlamaContext/Model are accessed only while holding the models Mutex,
// and the Java layer serialises all calls onto a single HandlerThread.
#[cfg(feature = "llama_native")]
unsafe impl Send for LoadedModel {}
#[cfg(feature = "llama_native")]
unsafe impl Sync for LoadedModel {}

// ── Backend implementation ────────────────────────────────────────────────────

/// llama.cpp inference backend.
///
/// Thread-safety: the model registry is protected by a Mutex.  Generation
/// calls are serialised by the Java service layer (single HandlerThread).
pub struct LlamaCppBackend {
    /// Internal model registry.  Each instance will hold at most one model
    /// in practice, because lib.rs creates a fresh backend per load call.
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
    // ── load_model ────────────────────────────────────────────────────────────

    fn load_model(&mut self, config: ModelConfig) -> Result<ModelHandle> {
        let handle = self.alloc_handle();

        #[cfg(feature = "llama_native")]
        {
            use std::ffi::CString;
            let path_c = CString::new(config.path.as_str())
                .map_err(|e| InferenceError::ModelLoadFailed(e.to_string()))?;

            let mut model_params = unsafe { ffi::llama_model_default_params() };
            model_params.use_mmap = true; // memory-map for lower RSS on mobile

            let model = unsafe {
                ffi::llama_load_model_from_file(path_c.as_ptr(), model_params)
            };
            if model.is_null() {
                return Err(InferenceError::ModelLoadFailed(
                    format!("llama_load_model_from_file returned null for {}", config.path),
                ));
            }

            let mut ctx_params = unsafe { ffi::llama_context_default_params() };
            if config.context_size > 0 {
                ctx_params.n_ctx = config.context_size;
            }
            // Use all available hardware threads; caller can override via config later.
            ctx_params.n_threads = num_cpus_online();

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
            let record = LoadedModel { config, loaded_at: Instant::now() };
            self.models.lock().unwrap().insert(handle, record);
        }

        Ok(handle)
    }

    // ── unload_model ──────────────────────────────────────────────────────────

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

    // ── generate (blocking) ───────────────────────────────────────────────────

    fn generate(&self, _handle: ModelHandle, request: GenerateRequest) -> Result<GenerateResponse> {
        let start = Instant::now();

        // Each LlamaCppBackend instance holds at most one model (lib.rs
        // creates a fresh backend per load).  Use values().next() rather than
        // looking up by the external handle so we work regardless of the
        // handle numbering scheme used by lib.rs.
        let models = self.models.lock().unwrap();
        let record = models.values().next().ok_or(InferenceError::NotLoaded)?;

        #[cfg(feature = "llama_native")]
        {
            let ctx   = record.ctx;
            let model = record.model;
            // Hold the lock for the entire generation so no one can unload
            // the model mid-way (generation is serialised by the HandlerThread).
            return Self::generate_native(ctx, model, &request, start);
        }

        #[cfg(not(feature = "llama_native"))]
        {
            let _ = record;
            let latency_ms = start.elapsed().as_millis() as u64;
            Ok(GenerateResponse {
                text: "[llama.cpp not compiled — stub mode]".to_string(),
                prompt_tokens: (request.prompt.len() / 4).max(1) as u32,
                completion_tokens: 1,
                latency_ms,
                truncated: false,
            })
        }
    }

    // ── generate_stream (streaming) ───────────────────────────────────────────

    fn generate_stream(
        &self,
        _handle: ModelHandle,
        request: GenerateRequest,
        callback: Box<dyn Fn(Token) -> StreamControl + Send>,
    ) -> Result<()> {
        let start = Instant::now();

        let models = self.models.lock().unwrap();
        let record = models.values().next().ok_or(InferenceError::NotLoaded)?;

        #[cfg(feature = "llama_native")]
        {
            let ctx   = record.ctx;
            let model = record.model;
            return Self::generate_stream_native(ctx, model, &request, start, callback);
        }

        #[cfg(not(feature = "llama_native"))]
        {
            let _ = (record, start);
            let tok = Token {
                text:     "[llama.cpp stub]".to_string(),
                index:    0,
                is_final: true,
                logprob:  f32::NAN,
            };
            callback(tok);
            Ok(())
        }
    }

    // ── capabilities ─────────────────────────────────────────────────────────

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "llama.cpp".to_string(),
            // GPU (Vulkan/CLBLAST) support requires compile-time feature; Phase 4+.
            supports_gpu: false,
            supports_streaming: true,
            max_context_size: 8192,
            supported_formats: vec![ModelFormat::Gguf, ModelFormat::Auto],
        }
    }

    // ── resource_usage ────────────────────────────────────────────────────────

    fn resource_usage(&self) -> ResourceMetrics {
        let models = self.models.lock().unwrap();

        #[cfg(feature = "llama_native")]
        if let Some(record) = models.values().next() {
            let ctx_size   = unsafe { ffi::llama_n_ctx(record.ctx as *const _) };
            let kv_used    = unsafe { ffi::llama_get_kv_cache_used_cells(record.ctx as *const _) };
            // Rough estimate: each KV cell ~2 × n_layers × n_kv_heads × head_dim × 2 bytes.
            // Use ctx_size as a proxy for memory consumption normalisation.
            let used_frac  = if ctx_size > 0 { kv_used as f32 / ctx_size as f32 } else { 0.0 };
            let budget_mb  = record.config.memory_budget_mb;
            let used_mb    = (budget_mb as f32 * used_frac) as u32;
            return ResourceMetrics {
                memory_used_mb:   used_mb,
                memory_budget_mb: budget_mb,
                tokens_per_second: 0.0, // updated by lib.rs benchmark recorder
                model_loaded:     true,
                thermal_state:    0,
            };
        }

        ResourceMetrics {
            memory_used_mb:   0,
            memory_budget_mb: 0,
            tokens_per_second: 0.0,
            model_loaded: !models.is_empty(),
            thermal_state: 0,
        }
    }
}

// ── Native generation helpers (llama_native only) ─────────────────────────────

#[cfg(feature = "llama_native")]
impl LlamaCppBackend {
    /// Tokenise `text` and return the token ids.
    unsafe fn tokenize(
        model:   *const ffi::LlamaModel,
        text:    &str,
        add_bos: bool,
    ) -> Result<Vec<ffi::LlamaToken>> {
        use std::ffi::CString;
        let text_c = CString::new(text)
            .map_err(|e| InferenceError::GenerateFailed(e.to_string()))?;

        // First pass: discover required buffer size (returns negative).
        let required = ffi::llama_tokenize(
            model, text_c.as_ptr(), text.len() as i32,
            std::ptr::null_mut(), 0, add_bos, false,
        );
        let n_max = if required < 0 { (-required) as usize + 4 } else { required as usize + 4 };

        let mut tokens = vec![0i32; n_max];
        let n = ffi::llama_tokenize(
            model, text_c.as_ptr(), text.len() as i32,
            tokens.as_mut_ptr(), n_max as i32, add_bos, false,
        );
        if n < 0 {
            return Err(InferenceError::GenerateFailed(
                format!("llama_tokenize overflow: needed {}", -n),
            ));
        }
        tokens.truncate(n as usize);
        Ok(tokens)
    }

    /// Decode a batch of tokens and fill the KV cache.
    /// Only the last slot gets `logits=1` so we can sample from it.
    unsafe fn decode_batch(
        ctx:    *mut ffi::LlamaContext,
        tokens: &[ffi::LlamaToken],
        offset: i32, // position offset (KV cache cursor)
    ) -> Result<()> {
        let n = tokens.len() as i32;
        let mut batch = ffi::llama_batch_init(n, 0, 1);

        for (i, &tok) in tokens.iter().enumerate() {
            *batch.token.add(i)    = tok;
            *batch.pos.add(i)      = offset + i as i32;
            *batch.n_seq_id.add(i) = 1;
            *(*batch.seq_id.add(i)) = 0;                           // sequence id 0
            *batch.logits.add(i)   = if i + 1 == tokens.len() { 1 } else { 0 };
        }
        batch.n_tokens = n;

        let rc = ffi::llama_decode(ctx, batch);
        ffi::llama_batch_free(batch);

        if rc != 0 {
            return Err(InferenceError::GenerateFailed(format!("llama_decode rc={}", rc)));
        }
        Ok(())
    }

    /// Sample the next token given logits at batch position `logit_idx`.
    unsafe fn sample_token(
        ctx:       *mut ffi::LlamaContext,
        model:     *const ffi::LlamaModel,
        logit_idx: i32,
        request:   &GenerateRequest,
    ) -> ffi::LlamaToken {
        let n_vocab = ffi::llama_n_vocab(model);
        let logits  = ffi::llama_get_logits_ith(ctx, logit_idx);

        let mut candidates: Vec<ffi::LlamaTokenData> = (0..n_vocab)
            .map(|id| ffi::LlamaTokenData {
                id,
                logit: *logits.add(id as usize),
                p: 0.0,
            })
            .collect();

        let mut arr = ffi::LlamaTokenDataArray {
            data:   candidates.as_mut_ptr(),
            size:   candidates.len(),
            sorted: false,
        };

        if request.temperature < 1e-6 {
            ffi::llama_sample_token_greedy(ctx, &mut arr)
        } else {
            ffi::llama_sample_temp(ctx, &mut arr, request.temperature);
            ffi::llama_sample_top_p(ctx, &mut arr, 0.9, 1);
            ffi::llama_sample_token(ctx, &mut arr)
        }
    }

    /// Convert a token id to its UTF-8 string piece.
    unsafe fn token_to_piece(
        model: *const ffi::LlamaModel,
        token: ffi::LlamaToken,
    ) -> String {
        let mut buf = [0i8; 256];
        let n = ffi::llama_token_to_piece(
            model, token, buf.as_mut_ptr(), buf.len() as i32, 0, false,
        );
        if n <= 0 { return String::new(); }
        let slice = std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize);
        String::from_utf8_lossy(slice).into_owned()
    }

    /// Check if `text` ends with any stop sequence. Returns the trimmed length.
    fn find_stop(text: &str, stops: &[String]) -> Option<usize> {
        for s in stops {
            if text.ends_with(s.as_str()) {
                return Some(text.len() - s.len());
            }
        }
        None
    }

    // ── Blocking generation ───────────────────────────────────────────────────

    fn generate_native(
        ctx:     *mut ffi::LlamaContext,
        model:   *mut ffi::LlamaModel,
        request: &GenerateRequest,
        start:   Instant,
    ) -> Result<GenerateResponse> {
        let eos_token = unsafe { ffi::llama_token_eos(model as *const _) };

        // Combine system prompt + user prompt if provided.
        let full_prompt = match &request.system_prompt {
            Some(sys) => format!("<|system|>\n{}\n<|user|>\n{}\n<|assistant|>\n", sys, request.prompt),
            None      => request.prompt.clone(),
        };

        // 1. Tokenise
        let prompt_tokens = unsafe {
            Self::tokenize(model as *const _, &full_prompt, true)?
        };
        let n_prompt = prompt_tokens.len();

        // 2. Decode prompt into KV cache
        unsafe { Self::decode_batch(ctx, &prompt_tokens, 0)? };

        // 3. Autoregressive generation loop
        let mut output = String::new();
        let mut n_generated = 0u32;
        let mut n_past = n_prompt as i32;
        let mut truncated = false;

        loop {
            // For the first token, logits sit at the last prompt position in the batch.
            // For subsequent tokens the batch has n_tokens=1, so index is always 0.
            let logit_idx = if n_generated == 0 { n_prompt as i32 - 1 } else { 0 };

            let next_tok = unsafe {
                Self::sample_token(ctx, model as *const _, logit_idx, request)
            };

            if next_tok == eos_token { break; }
            if n_generated >= request.max_tokens { truncated = true; break; }

            let piece = unsafe { Self::token_to_piece(model as *const _, next_tok) };
            output.push_str(&piece);
            n_generated += 1;

            // Check stop sequences
            if let Some(trim) = Self::find_stop(&output, &request.stop_sequences) {
                output.truncate(trim);
                break;
            }

            // Decode the single generated token to prepare next logits
            let single = [next_tok];
            unsafe { Self::decode_batch(ctx, &single, n_past)? };
            n_past += 1;
        }

        // 4. Clear KV cache so next call starts fresh
        unsafe { ffi::llama_kv_cache_clear(ctx) };

        Ok(GenerateResponse {
            text: output,
            prompt_tokens:     n_prompt as u32,
            completion_tokens: n_generated,
            latency_ms:        start.elapsed().as_millis() as u64,
            truncated,
        })
    }

    // ── Streaming generation ──────────────────────────────────────────────────

    fn generate_stream_native(
        ctx:      *mut ffi::LlamaContext,
        model:    *mut ffi::LlamaModel,
        request:  &GenerateRequest,
        start:    Instant,
        callback: Box<dyn Fn(Token) -> StreamControl + Send>,
    ) -> Result<()> {
        let eos_token = unsafe { ffi::llama_token_eos(model as *const _) };

        let full_prompt = match &request.system_prompt {
            Some(sys) => format!("<|system|>\n{}\n<|user|>\n{}\n<|assistant|>\n", sys, request.prompt),
            None      => request.prompt.clone(),
        };

        let prompt_tokens = unsafe {
            Self::tokenize(model as *const _, &full_prompt, true)?
        };
        let n_prompt = prompt_tokens.len();

        unsafe { Self::decode_batch(ctx, &prompt_tokens, 0)? };

        let mut n_generated = 0u32;
        let mut n_past = n_prompt as i32;
        let mut acc = String::new(); // accumulate for stop-sequence detection

        loop {
            let logit_idx = if n_generated == 0 { n_prompt as i32 - 1 } else { 0 };
            let next_tok  = unsafe {
                Self::sample_token(ctx, model as *const _, logit_idx, request)
            };

            let done = next_tok == eos_token || n_generated >= request.max_tokens;
            if !done {
                let piece = unsafe { Self::token_to_piece(model as *const _, next_tok) };
                acc.push_str(&piece);

                // Emit token to caller
                let ctrl = callback(Token {
                    text:     piece,
                    index:    n_generated,
                    is_final: false,
                    logprob:  f32::NAN,
                });
                n_generated += 1;

                if ctrl == StreamControl::Stop { break; }

                // Stop-sequence check
                if let Some(trim) = Self::find_stop(&acc, &request.stop_sequences) {
                    acc.truncate(trim);
                    break;
                }

                let single = [next_tok];
                unsafe { Self::decode_batch(ctx, &single, n_past)? };
                n_past += 1;
            } else {
                break;
            }
        }

        // Emit final sentinel token
        callback(Token {
            text:     String::new(),
            index:    n_generated,
            is_final: true,
            logprob:  f32::NAN,
        });

        unsafe { ffi::llama_kv_cache_clear(ctx) };

        let _ = start;
        Ok(())
    }
}

// ── Platform helpers ──────────────────────────────────────────────────────────

/// Return the number of online CPU cores, falling back to 4 on error.
fn num_cpus_online() -> i32 {
    // _SC_NPROCESSORS_ONLN is POSIX and available on Android.
    #[cfg(target_os = "android")]
    unsafe {
        extern "C" { fn sysconf(name: i32) -> i64; }
        const _SC_NPROCESSORS_ONLN: i32 = 84;
        let n = sysconf(_SC_NPROCESSORS_ONLN);
        if n > 0 { n as i32 } else { 4 }
    }
    #[cfg(not(target_os = "android"))]
    { 4 }
}
