/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! The InferenceBackend trait — the core abstraction over llama.cpp, BitNet.cpp,
//! and any future inference runtime.
//!
//! Each backend is responsible for:
//!   - Loading a model from disk into native memory
//!   - Running synchronous and streaming text generation
//!   - Reporting its own capabilities and live resource usage

use crate::types::{
    BackendCapabilities, GenerateRequest, GenerateResponse, ModelConfig, ModelHandle,
    ResourceMetrics, Result, StreamControl, Token,
};

/// Core trait implemented by every inference backend.
///
/// Implementations must be `Send + Sync` so they can be stored in a global
/// registry and called from multiple threads (one active generate at a time,
/// serialised by the Java service layer).
pub trait InferenceBackend: Send + Sync {
    /// Load a model from disk. Returns an opaque handle on success.
    ///
    /// The handle is only valid for subsequent calls on *this* backend instance.
    fn load_model(&mut self, config: ModelConfig) -> Result<ModelHandle>;

    /// Unload the model identified by `handle` and free all native memory.
    fn unload_model(&mut self, handle: ModelHandle) -> Result<()>;

    /// Run synchronous text generation. Blocks until complete or error.
    fn generate(&self, handle: ModelHandle, request: GenerateRequest) -> Result<GenerateResponse>;

    /// Run streaming generation. The `callback` is called once per token.
    ///
    /// Returning `StreamControl::Stop` from the callback cancels generation.
    /// The backend must honour cancellation promptly (within one token).
    fn generate_stream(
        &self,
        handle: ModelHandle,
        request: GenerateRequest,
        callback: Box<dyn Fn(Token) -> StreamControl + Send>,
    ) -> Result<()>;

    /// Return static capability metadata for this backend.
    fn capabilities(&self) -> BackendCapabilities;

    /// Return a live resource usage snapshot.
    fn resource_usage(&self) -> ResourceMetrics;
}
