/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Backend auto-selection logic.
//!
//! Selects the optimal inference backend for the device at runtime:
//!
//!   1. BitNet.cpp — if `bitnet_native` feature enabled AND device is Tier 2+
//!      BitNet.cpp delivers 1.37–5.07x speedup on ARM CPUs for 1-bit models
//!      and uses ~0.4 GB for 2B-parameter models.
//!
//!   2. llama.cpp  — fallback for all other cases (Tier 1, or BitNet not linked)
//!
//! The selection is logged so operators can verify which path is active.

use crate::backend::InferenceBackend;
use crate::bitnet_backend::BitNetBackend;
use crate::capability_detector::CapabilityDetector;
use crate::llama_backend::LlamaCppBackend;
use crate::types::DeviceTier;

/// The active backend selection for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    LlamaCpp,
    BitNet,
}

/// Result of backend selection, including the rationale.
pub struct SelectionResult {
    pub choice: BackendChoice,
    pub tier: DeviceTier,
    pub reason: &'static str,
}

impl SelectionResult {
    /// Consume the result and produce the concrete backend instance.
    pub fn into_backend(self) -> Box<dyn InferenceBackend + Send + Sync> {
        match self.choice {
            BackendChoice::BitNet    => Box::new(BitNetBackend::new()),
            BackendChoice::LlamaCpp => Box::new(LlamaCppBackend::new()),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self.choice {
            BackendChoice::BitNet    => "bitnet.cpp",
            BackendChoice::LlamaCpp => "llama.cpp",
        }
    }
}

pub struct BackendSelector;

impl BackendSelector {
    /// Detect device capabilities and select the best available backend.
    pub fn select() -> SelectionResult {
        let detector = CapabilityDetector::new();
        let caps = detector.detect();
        Self::select_for_tier(caps.tier)
    }

    /// Select backend for an explicit tier (useful for testing).
    pub fn select_for_tier(tier: DeviceTier) -> SelectionResult {
        // BitNet.cpp: requires Tier 2+ and the bitnet_native feature
        if BitNetBackend::is_suitable_for_tier(tier) {
            return SelectionResult {
                choice: BackendChoice::BitNet,
                tier,
                reason: "BitNet.cpp selected: device is Tier 2+, bitnet_native enabled",
            };
        }

        // Tier 1 or BitNet not linked — fall back to llama.cpp
        let reason = if tier == DeviceTier::Tier1 {
            "llama.cpp selected: Tier 1 device (< 3 GB RAM), BitNet requires Tier 2+"
        } else {
            "llama.cpp selected: bitnet_native feature not enabled (Phase 2 build)"
        };

        SelectionResult {
            choice: BackendChoice::LlamaCpp,
            tier,
            reason,
        }
    }
}

// ── Performance benchmarking ──────────────────────────────────────────────────

/// Lightweight benchmark result recorded after model load.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub backend: &'static str,
    pub tier: DeviceTier,
    /// Estimated tokens/second based on a short warm-up prompt.
    pub estimated_tps: f32,
    /// Memory used after loading the model, in MB.
    pub memory_used_mb: u32,
    /// Time taken to load the model, in milliseconds.
    pub load_time_ms: u64,
}

impl BenchmarkResult {
    pub fn new(
        backend: &'static str,
        tier: DeviceTier,
        load_time_ms: u64,
        memory_used_mb: u32,
    ) -> Self {
        BenchmarkResult {
            backend,
            tier,
            estimated_tps: 0.0, // Updated after first inference
            memory_used_mb,
            load_time_ms,
        }
    }

    /// Record the per-token throughput from a completed generation.
    pub fn record_tps(&mut self, tokens: u32, latency_ms: u64) {
        if latency_ms > 0 {
            self.estimated_tps = (tokens as f32 * 1000.0) / latency_ms as f32;
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "backend={} tier={:?} load={}ms mem={}MB tps={:.1}",
            self.backend, self.tier, self.load_time_ms,
            self.memory_used_mb, self.estimated_tps
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier1_always_selects_llama() {
        let result = BackendSelector::select_for_tier(DeviceTier::Tier1);
        assert_eq!(result.choice, BackendChoice::LlamaCpp);
    }

    #[test]
    fn tier5_selects_bitnet_when_native() {
        let result = BackendSelector::select_for_tier(DeviceTier::Tier5);
        #[cfg(feature = "bitnet_native")]
        assert_eq!(result.choice, BackendChoice::BitNet);
        #[cfg(not(feature = "bitnet_native"))]
        assert_eq!(result.choice, BackendChoice::LlamaCpp);
    }
}
