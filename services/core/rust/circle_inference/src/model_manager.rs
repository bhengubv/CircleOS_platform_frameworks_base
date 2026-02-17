/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Model discovery, integrity verification, and download management.
//!
//! Scans two directories:
//!   /system/circle/models/   — bundled (read-only, ships with OS)
//!   /data/circle/models/     — downloaded (read-write, user-installed)
//!
//! Each directory may contain a manifest.json with this schema:
//! {
//!   "models": [
//!     {
//!       "id": "qwen-1.5b-q4",
//!       "name": "Qwen 1.5B Q4_K_M",
//!       "filename": "qwen-1.5b-q4_k_m.gguf",
//!       "parameterCount": 1500000000,
//!       "sizeBytes": 987654321,
//!       "minRamMb": 2048,
//!       "recommendedTier": 2,
//!       "backend": "llama.cpp",
//!       "sha256": "abcdef..."
//!     }
//!   ]
//! }

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::types::{DeviceTier, InferenceError, Result};

const BUNDLED_DIR: &str  = "/system/circle/models";
const DOWNLOAD_DIR: &str = "/data/circle/models";
const MANIFEST_FILE: &str = "manifest.json";

// ── Model record ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelRecord {
    pub id: String,
    pub name: String,
    pub filename: String,
    pub parameter_count: u64,
    pub size_bytes: u64,
    pub min_ram_mb: u32,
    pub recommended_tier: DeviceTier,
    pub backend: String,
    pub sha256: Option<String>,
    pub is_bundled: bool,
    pub is_downloaded: bool,
    pub dir: PathBuf,
}

impl ModelRecord {
    pub fn file_path(&self) -> PathBuf {
        self.dir.join(&self.filename)
    }
}

// ── Download state ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadState {
    Pending,
    Downloading { bytes_received: u64, total_bytes: u64 },
    Verifying,
    Complete,
    Failed(String),
}

type DownloadRegistry = Arc<Mutex<HashMap<String, DownloadState>>>;

// ── Model Manager ─────────────────────────────────────────────────────────────

pub struct ModelManager {
    downloads: DownloadRegistry,
}

impl ModelManager {
    pub fn new() -> Self {
        ModelManager {
            downloads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ── Discovery ─────────────────────────────────────────────────────────

    /// Return all models visible in bundled and downloaded directories.
    pub fn list_models(&self) -> Vec<ModelRecord> {
        let mut records = Vec::new();
        self.scan_dir(Path::new(BUNDLED_DIR), true, &mut records);
        self.scan_dir(Path::new(DOWNLOAD_DIR), false, &mut records);
        records
    }

    fn scan_dir(&self, dir: &Path, is_bundled: bool, out: &mut Vec<ModelRecord>) {
        if !dir.is_dir() { return; }
        let manifest_path = dir.join(MANIFEST_FILE);
        if !manifest_path.exists() { return; }

        let json = match fs::read_to_string(&manifest_path) {
            Ok(s) => s,
            Err(_) => return,
        };

        if let Some(records) = parse_manifest(&json, dir, is_bundled) {
            out.extend(records);
        }
    }

    // ── Selection ─────────────────────────────────────────────────────────

    /// Pick the best available model for the given device tier.
    ///
    /// Prefers models with `recommended_tier == tier`; falls back to lower
    /// tiers if no exact match. Returns `None` if nothing is available.
    pub fn select_optimal(&self, tier: DeviceTier) -> Option<ModelRecord> {
        let models = self.list_models();
        let mut best: Option<ModelRecord> = None;

        for m in models {
            if !m.is_downloaded && !m.is_bundled { continue; }
            if m.recommended_tier <= tier {
                let better = match &best {
                    None => true,
                    Some(b) => m.recommended_tier > b.recommended_tier,
                };
                if better { best = Some(m); }
            }
        }
        best
    }

    /// Return the absolute path to a model file by ID, or None if not found.
    pub fn model_path(&self, id: &str) -> Option<PathBuf> {
        self.list_models()
            .into_iter()
            .find(|m| m.id == id)
            .map(|m| m.file_path())
    }

    // ── Integrity ─────────────────────────────────────────────────────────

    /// SHA-256 integrity check. Returns Ok(()) if the file matches.
    /// Skips verification if `expected_sha256` is None.
    pub fn verify_integrity(&self, path: &Path, expected_sha256: Option<&str>) -> Result<()> {
        let expected = match expected_sha256 {
            None => return Ok(()),
            Some(s) if s.is_empty() => return Ok(()),
            Some(s) => s,
        };

        let actual = sha256_file(path)
            .map_err(|e| InferenceError::Internal(format!("SHA-256 error: {}", e)))?;

        if actual.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(InferenceError::IntegrityCheckFailed(format!(
                "{}: expected {} got {}", path.display(), expected, actual
            )))
        }
    }

    // ── Download support (Phase 2) ────────────────────────────────────────

    /// Begin downloading a model from `url` into /data/circle/models/.
    ///
    /// Progress is tracked in the download registry and can be polled via
    /// `download_state()`. The actual HTTP fetch happens on the calling thread;
    /// callers should dispatch to a background thread.
    ///
    /// Phase 2: Uses basic std::net HTTP (no TLS). TLS via rustls in Phase 3.
    pub fn download_model<F>(&self, model_id: &str, url: &str, on_progress: F) -> Result<()>
    where
        F: Fn(u64, u64), // (bytes_received, total_bytes)
    {
        {
            let mut reg = self.downloads.lock().unwrap();
            reg.insert(model_id.to_string(), DownloadState::Pending);
        }

        // Ensure download directory exists
        if let Err(e) = fs::create_dir_all(DOWNLOAD_DIR) {
            let msg = format!("Cannot create download dir: {}", e);
            self.set_download_state(model_id, DownloadState::Failed(msg.clone()));
            return Err(InferenceError::Internal(msg));
        }

        // Determine filename from URL
        let filename = url.rsplit('/').next().unwrap_or(model_id);
        let dest_path = Path::new(DOWNLOAD_DIR).join(filename);

        // Phase 2 stub: real HTTP download wired in Phase 3 with proper TLS
        // For now, log intent and mark as failed (no real network call)
        let msg = format!("HTTP download not yet implemented — Phase 3 (url={})", url);
        self.set_download_state(model_id, DownloadState::Failed(msg.clone()));
        return Err(InferenceError::Internal(msg));
    }

    /// Poll the download state for a model.
    pub fn download_state(&self, model_id: &str) -> Option<DownloadState> {
        self.downloads.lock().unwrap().get(model_id).cloned()
    }

    fn set_download_state(&self, model_id: &str, state: DownloadState) {
        self.downloads.lock().unwrap().insert(model_id.to_string(), state);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_manifest(json: &str, dir: &Path, is_bundled: bool) -> Option<Vec<ModelRecord>> {
    // Minimal JSON parser — avoids serde dependency.
    // Expects well-formed manifest produced by Circle OS tooling.
    let mut records = Vec::new();

    // Extract the "models" array content
    let models_start = json.find("\"models\"")?;
    let arr_start = json[models_start..].find('[')? + models_start;
    let arr_end   = find_matching_bracket(json, arr_start, '[', ']')?;
    let arr_content = &json[arr_start + 1..arr_end];

    // Split on top-level { ... } objects
    let mut depth = 0i32;
    let mut obj_start = None;
    for (i, ch) in arr_content.char_indices() {
        match ch {
            '{' => {
                if depth == 0 { obj_start = Some(i); }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &arr_content[start..=i];
                        if let Some(r) = parse_model_obj(obj, dir, is_bundled) {
                            records.push(r);
                        }
                    }
                    obj_start = None;
                }
            }
            _ => {}
        }
    }
    Some(records)
}

fn parse_model_obj(obj: &str, dir: &Path, is_bundled: bool) -> Option<ModelRecord> {
    let id       = extract_str(obj, "id")?;
    let name     = extract_str(obj, "name").unwrap_or_else(|| id.clone());
    let filename = extract_str(obj, "filename").unwrap_or_default();
    let backend  = extract_str(obj, "backend").unwrap_or_else(|| "llama.cpp".to_string());
    let sha256   = extract_str(obj, "sha256");

    let param_count  = extract_u64(obj, "parameterCount").unwrap_or(0);
    let size_bytes   = extract_u64(obj, "sizeBytes").unwrap_or(0);
    let min_ram_mb   = extract_u32(obj, "minRamMb").unwrap_or(0);
    let tier_raw     = extract_u32(obj, "recommendedTier").unwrap_or(1);

    let recommended_tier = match tier_raw {
        1 => crate::types::DeviceTier::Tier1,
        2 => crate::types::DeviceTier::Tier2,
        3 => crate::types::DeviceTier::Tier3,
        4 => crate::types::DeviceTier::Tier4,
        _ => crate::types::DeviceTier::Tier5,
    };

    let file_path = dir.join(&filename);
    let is_downloaded = file_path.exists();

    Some(ModelRecord {
        id, name, filename, parameter_count: param_count, size_bytes,
        min_ram_mb, recommended_tier, backend, sha256,
        is_bundled, is_downloaded, dir: dir.to_path_buf(),
    })
}

fn extract_str(obj: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let pos = obj.find(&search)?;
    let after_colon = obj[pos + search.len()..].trim_start();
    let after_colon = after_colon.trim_start_matches(':').trim_start();
    if !after_colon.starts_with('"') { return None; }
    let inner = &after_colon[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

fn extract_u64(obj: &str, key: &str) -> Option<u64> {
    let search = format!("\"{}\"", key);
    let pos = obj.find(&search)?;
    let after = obj[pos + search.len()..].trim_start()
        .trim_start_matches(':').trim_start();
    after.chars().take_while(|c| c.is_ascii_digit())
        .collect::<String>().parse().ok()
}

fn extract_u32(obj: &str, key: &str) -> Option<u32> {
    extract_u64(obj, key).map(|v| v as u32)
}

fn find_matching_bracket(s: &str, start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s[start..].char_indices() {
        if ch == open  { depth += 1; }
        if ch == close { depth -= 1; if depth == 0 { return Some(start + i); } }
    }
    None
}

fn sha256_file(path: &Path) -> io::Result<String> {
    use std::io::Read;
    // Simple SHA-256 without ring/sha2 crate — use /proc/self/fd trick on Android
    // Phase 2: delegates to sha256sum binary as a fallback
    // Phase 3: use ring crate (available in AOSP)
    let output = std::process::Command::new("sha256sum")
        .arg(path)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.split_whitespace().next().unwrap_or("").to_string())
}
