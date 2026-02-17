/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Resource governance: memory budgeting and thermal response.
//!
//! The ResourceGovernor mediates between available system resources and the
//! inference service's consumption. It enforces memory ceilings, monitors
//! thermal state, and signals when models should be evicted.

use std::fs;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::types::{ResourceMetrics, ThermalState};

/// Fraction of available RAM the inference service may use.
const RAM_BUDGET_FRACTION: f32 = 0.5;

/// Minimum RAM kept free for the rest of the system, in MB.
const MIN_FREE_RAM_MB: u32 = 512;

pub struct ResourceGovernor {
    /// Configured memory ceiling in MB.
    memory_budget_mb: u32,
    /// Currently reported memory used by loaded model, in MB.
    memory_used_mb: AtomicU32,
    /// Last known thermal state (as ThermalState::as_i32()).
    thermal_state: AtomicI32,
    /// Tokens generated in the last measurement window.
    tokens_generated: AtomicU32,
    /// Timestamp (seconds since epoch) of last tps measurement window start.
    window_start_secs: AtomicU32,
}

impl ResourceGovernor {
    /// Create a new governor with a budget derived from total available RAM.
    pub fn new(total_ram_mb: u32, available_ram_mb: u32) -> Self {
        let budget = Self::compute_budget(total_ram_mb, available_ram_mb);
        ResourceGovernor {
            memory_budget_mb: budget,
            memory_used_mb: AtomicU32::new(0),
            thermal_state: AtomicI32::new(0),
            tokens_generated: AtomicU32::new(0),
            window_start_secs: AtomicU32::new(current_secs()),
        }
    }

    /// Compute a safe memory budget given system RAM figures.
    fn compute_budget(total_ram_mb: u32, available_ram_mb: u32) -> u32 {
        let from_available = (available_ram_mb as f32 * RAM_BUDGET_FRACTION) as u32;
        let from_available = from_available.saturating_sub(MIN_FREE_RAM_MB);
        // Cap at 60% of total RAM
        let from_total = (total_ram_mb as f32 * 0.6) as u32;
        from_available.min(from_total).max(256) // at least 256 MB floor
    }

    // ── Budget checks ─────────────────────────────────────────────────────

    /// Returns true if loading a model of `size_mb` would stay within budget.
    pub fn can_accommodate(&self, size_mb: u32) -> bool {
        let used = self.memory_used_mb.load(Ordering::Relaxed);
        used.saturating_add(size_mb) <= self.memory_budget_mb
    }

    /// Returns the configured memory budget in MB.
    pub fn budget_mb(&self) -> u32 {
        self.memory_budget_mb
    }

    // ── Usage tracking ────────────────────────────────────────────────────

    /// Record that a model of `size_mb` has been loaded.
    pub fn on_model_loaded(&self, size_mb: u32) {
        self.memory_used_mb.fetch_add(size_mb, Ordering::Relaxed);
    }

    /// Record that a model of `size_mb` has been unloaded.
    pub fn on_model_unloaded(&self, size_mb: u32) {
        let _ = self.memory_used_mb.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(size_mb)),
        );
    }

    /// Record that `count` tokens were generated (for tps tracking).
    pub fn on_tokens_generated(&self, count: u32) {
        self.tokens_generated.fetch_add(count, Ordering::Relaxed);
    }

    // ── Thermal monitoring ────────────────────────────────────────────────

    /// Poll and cache the current thermal state. Call periodically.
    pub fn refresh_thermal_state(&self) {
        let state = read_thermal_state();
        self.thermal_state.store(state.as_i32(), Ordering::Relaxed);
    }

    /// Returns true if the thermal state requires halting inference.
    pub fn should_abort_generation(&self) -> bool {
        self.thermal_state.load(Ordering::Relaxed) >= ThermalState::SevereThrottle.as_i32()
    }

    // ── Metrics snapshot ──────────────────────────────────────────────────

    pub fn metrics(&self, model_loaded: bool) -> ResourceMetrics {
        let now = current_secs();
        let window_start = self.window_start_secs.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(window_start).max(1);
        let tokens = self.tokens_generated.swap(0, Ordering::Relaxed);

        // Reset window
        self.window_start_secs.store(now, Ordering::Relaxed);

        ResourceMetrics {
            memory_used_mb: self.memory_used_mb.load(Ordering::Relaxed),
            memory_budget_mb: self.memory_budget_mb,
            tokens_per_second: tokens as f32 / elapsed as f32,
            model_loaded,
            thermal_state: self.thermal_state.load(Ordering::Relaxed),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn read_thermal_state() -> ThermalState {
    let temp_mc = read_thermal_zone_temp();
    match temp_mc {
        t if t >= 85_000 => ThermalState::SevereThrottle,
        t if t >= 75_000 => ThermalState::ModerateThrottle,
        t if t >= 65_000 => ThermalState::LightThrottle,
        _                => ThermalState::Nominal,
    }
}

fn read_thermal_zone_temp() -> i64 {
    for i in 0..10 {
        let path = format!("/sys/class/thermal/thermal_zone{}/temp", i);
        if let Ok(s) = fs::read_to_string(&path) {
            if let Ok(t) = s.trim().parse::<i64>() {
                return t;
            }
        }
    }
    0
}

fn current_secs() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}
