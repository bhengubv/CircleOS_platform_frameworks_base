/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Shared types for the CircleOS inference abstraction layer.

use std::fmt;

/// Opaque handle identifying a loaded model instance in the backend registry.
pub type ModelHandle = i64;

// ── Model configuration ───────────────────────────────────────────────────────

/// Parameters passed to the backend when loading a model.
#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// Absolute path to the model file (GGUF or BitNet native format).
    pub path: String,
    /// Context window size in tokens. 0 = use model default.
    pub context_size: u32,
    /// Memory budget for this model in MB. Backend must stay within this limit.
    pub memory_budget_mb: u32,
}

// ── Inference request / response ─────────────────────────────────────────────

/// Parameters for a single generation request.
#[derive(Debug, Clone)]
pub struct GenerateRequest {
    /// The full prompt string (system + user, already formatted if needed).
    pub prompt: String,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Sampling temperature. 0.0 = greedy/deterministic.
    pub temperature: f32,
    /// Sequences that, when generated, terminate output early.
    pub stop_sequences: Vec<String>,
    /// Optional system prompt to prepend.
    pub system_prompt: Option<String>,
}

/// Result of a completed generation.
#[derive(Debug, Clone)]
pub struct GenerateResponse {
    /// The generated text.
    pub text: String,
    /// Approximate number of tokens in the prompt.
    pub prompt_tokens: u32,
    /// Number of tokens generated.
    pub completion_tokens: u32,
    /// Wall-clock latency in milliseconds.
    pub latency_ms: u64,
    /// True if generation stopped due to reaching max_tokens.
    pub truncated: bool,
}

// ── Streaming ─────────────────────────────────────────────────────────────────

/// A single token produced during streaming generation.
#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub index: u32,
    pub is_final: bool,
    /// Log-probability; f32::NAN if backend does not provide it.
    pub logprob: f32,
}

/// Return value from a streaming callback: continue or stop generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamControl {
    Continue,
    Stop,
}

// ── Backend metadata ─────────────────────────────────────────────────────────

/// Static capability description returned by each backend.
#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    /// Short identifier, e.g. "llama.cpp" or "bitnet.cpp".
    pub name: String,
    pub supports_gpu: bool,
    pub supports_streaming: bool,
    /// Maximum context size the backend can handle.
    pub max_context_size: u32,
    /// Model formats this backend accepts.
    pub supported_formats: Vec<ModelFormat>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelFormat {
    Gguf,
    BitNetNative,
    Auto,
}

// ── Resource metrics ─────────────────────────────────────────────────────────

/// Runtime resource usage snapshot.
#[derive(Debug, Clone, Default)]
pub struct ResourceMetrics {
    pub memory_used_mb: u32,
    pub memory_budget_mb: u32,
    pub tokens_per_second: f32,
    pub model_loaded: bool,
    /// 0 = nominal, 1 = light, 2 = moderate, 3 = severe throttle.
    pub thermal_state: i32,
}

// ── Device capability / tier ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DeviceTier {
    Tier1 = 1, // < 3 GB RAM  — ultra-budget
    Tier2 = 2, // 3-6 GB RAM  — budget/mid
    Tier3 = 3, // 6-8 GB RAM  — mid-range
    Tier4 = 4, // 8-12 GB RAM — flagship
    Tier5 = 5, // 12 GB+ RAM  — ultra flagship
}

impl DeviceTier {
    pub fn as_u8(self) -> u8 { self as u8 }
}

/// CPU feature flags detected at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuFeature {
    Neon,
    Asimd,
    DotProd,
    I8Mm,
    Sve,
    Sve2,
    Other(String),
}

/// GPU family, used to select compute paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuType {
    Adreno,
    Mali,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct DeviceCapabilities {
    pub total_ram_mb: u32,
    pub available_ram_mb: u32,
    pub cpu_cores: u32,
    pub cpu_features: Vec<CpuFeature>,
    pub gpu_available: bool,
    pub gpu_type: Option<GpuType>,
    pub thermal_state: ThermalState,
    pub tier: DeviceTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalState {
    Nominal,
    LightThrottle,
    ModerateThrottle,
    SevereThrottle,
}

impl ThermalState {
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Nominal => 0,
            Self::LightThrottle => 1,
            Self::ModerateThrottle => 2,
            Self::SevereThrottle => 3,
        }
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum InferenceError {
    ModelNotFound(String),
    ModelLoadFailed(String),
    IntegrityCheckFailed(String),
    NotLoaded,
    InvalidHandle(i64),
    InsufficientMemory { required_mb: u32, available_mb: u32 },
    NativeNotAvailable,
    GenerateFailed(String),
    Cancelled,
    ThermalAbort,
    Internal(String),
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelNotFound(p)     => write!(f, "Model not found: {}", p),
            Self::ModelLoadFailed(e)   => write!(f, "Model load failed: {}", e),
            Self::IntegrityCheckFailed(id) => write!(f, "Integrity check failed: {}", id),
            Self::NotLoaded            => write!(f, "No model loaded"),
            Self::InvalidHandle(h)     => write!(f, "Invalid handle: {}", h),
            Self::InsufficientMemory { required_mb, available_mb } =>
                write!(f, "Insufficient memory: need {}MB, have {}MB", required_mb, available_mb),
            Self::NativeNotAvailable   => write!(f, "Native inference backend not available"),
            Self::GenerateFailed(e)    => write!(f, "Generation failed: {}", e),
            Self::Cancelled            => write!(f, "Generation cancelled"),
            Self::ThermalAbort         => write!(f, "Aborted due to thermal throttle"),
            Self::Internal(e)          => write!(f, "Internal error: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, InferenceError>;
