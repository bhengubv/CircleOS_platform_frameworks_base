/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Runtime device capability detection.
//!
//! Reads /proc/meminfo, /proc/cpuinfo, and Android system properties to
//! classify the device into a tier (1–5) and determine which inference
//! backends are viable.

use std::fs;
use std::io::{self, BufRead};

use crate::types::{CpuFeature, DeviceCapabilities, DeviceTier, GpuType, ThermalState};

pub struct CapabilityDetector;

impl CapabilityDetector {
    pub fn new() -> Self {
        CapabilityDetector
    }

    /// Detect all device capabilities and return a populated snapshot.
    pub fn detect(&self) -> DeviceCapabilities {
        let (total_ram_mb, available_ram_mb) = self.read_meminfo();
        let cpu_cores = self.cpu_cores();
        let cpu_features = self.read_cpu_features();
        let (gpu_available, gpu_type) = self.detect_gpu();
        let thermal_state = self.read_thermal_state();
        let tier = Self::classify_tier(total_ram_mb);

        DeviceCapabilities {
            total_ram_mb,
            available_ram_mb,
            cpu_cores,
            cpu_features,
            gpu_available,
            gpu_type,
            thermal_state,
            tier,
        }
    }

    /// Classify device tier from total RAM in MB.
    pub fn classify_tier(total_ram_mb: u32) -> DeviceTier {
        match total_ram_mb {
            0..=3071   => DeviceTier::Tier1,
            3072..=6143  => DeviceTier::Tier2,
            6144..=8191  => DeviceTier::Tier3,
            8192..=12287 => DeviceTier::Tier4,
            _            => DeviceTier::Tier5,
        }
    }

    // ── Memory ─────────────────────────────────────────────────────────────

    fn read_meminfo(&self) -> (u32, u32) {
        let mut total_kb: u64 = 0;
        let mut available_kb: u64 = 0;

        if let Ok(f) = fs::File::open("/proc/meminfo") {
            for line in io::BufReader::new(f).lines().flatten() {
                if line.starts_with("MemTotal:") {
                    total_kb = parse_kb_value(&line);
                } else if line.starts_with("MemAvailable:") {
                    available_kb = parse_kb_value(&line);
                }
                if total_kb > 0 && available_kb > 0 {
                    break;
                }
            }
        }

        (
            (total_kb / 1024) as u32,
            (available_kb / 1024) as u32,
        )
    }

    // ── CPU ────────────────────────────────────────────────────────────────

    fn cpu_cores(&self) -> u32 {
        // Count "processor" entries in /proc/cpuinfo
        let count = fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count();
        if count > 0 { count as u32 } else { 1 }
    }

    fn read_cpu_features(&self) -> Vec<CpuFeature> {
        let mut features = Vec::new();

        if let Ok(f) = fs::File::open("/proc/cpuinfo") {
            for line in io::BufReader::new(f).lines().flatten() {
                if line.starts_with("Features") {
                    if let Some(vals) = line.splitn(2, ':').nth(1) {
                        for feat in vals.split_whitespace() {
                            match feat {
                                "neon"    => features.push(CpuFeature::Neon),
                                "asimd"   => features.push(CpuFeature::Asimd),
                                "dotprod" => features.push(CpuFeature::DotProd),
                                "i8mm"    => features.push(CpuFeature::I8Mm),
                                "sve"     => features.push(CpuFeature::Sve),
                                "sve2"    => features.push(CpuFeature::Sve2),
                                _ => {}
                            }
                        }
                    }
                    break; // First CPU block is sufficient
                }
            }
        }

        // ARM64 baseline always has NEON/ASIMD
        if features.is_empty() {
            features.push(CpuFeature::Neon);
            features.push(CpuFeature::Asimd);
        }

        features
    }

    // ── GPU ────────────────────────────────────────────────────────────────

    fn detect_gpu(&self) -> (bool, Option<GpuType>) {
        let platform = read_sysprop("ro.board.platform").to_lowercase();
        let hardware  = read_sysprop("ro.hardware").to_lowercase();

        if platform.contains("qcom") || platform.starts_with("sm") || hardware.contains("qcom") {
            return (true, Some(GpuType::Adreno));
        }
        if hardware.contains("mali") || platform.contains("exynos") || platform.contains("mt") {
            return (true, Some(GpuType::Mali));
        }
        (false, None)
    }

    // ── Thermal ────────────────────────────────────────────────────────────

    fn read_thermal_state(&self) -> ThermalState {
        // Read the first available thermal zone temperature
        // Throttling thresholds are device-specific; use a conservative heuristic
        let temp_mc = read_thermal_zone_temp(); // milliCelsius

        match temp_mc {
            t if t >= 85_000 => ThermalState::SevereThrottle,
            t if t >= 75_000 => ThermalState::ModerateThrottle,
            t if t >= 65_000 => ThermalState::LightThrottle,
            _                => ThermalState::Nominal,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_kb_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
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

/// Read an Android system property via /proc or a simple sysfs fallback.
/// In the full AOSP environment this would use android_get_device_api_level()
/// or similar; here we use a file-based fallback for portability.
fn read_sysprop(key: &str) -> String {
    // Try /proc/cmdline for board platform as a fallback
    if key == "ro.board.platform" {
        if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
            if cmdline.to_lowercase().contains("qcom") {
                return "qcom".to_string();
            }
        }
    }
    String::new()
}
