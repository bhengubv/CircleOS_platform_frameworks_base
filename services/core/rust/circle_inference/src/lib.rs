/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! libcircle_inference — Rust abstraction layer (Phase 3: backend auto-selection).
//!
//! Phase 3 changes from Phase 2:
//!   - BackendSelector auto-picks BitNet.cpp or llama.cpp at load time
//!   - Registry holds Box<dyn InferenceBackend + Send + Sync>
//!   - New C export: circle_inference_backend_name()
//!   - BenchmarkResult tracks per-load performance

mod backend;
mod backend_selector;
mod bitnet_backend;
mod capability_detector;
mod llama_backend;
mod model_manager;
mod resource_governor;
mod types;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_float, c_int};
use std::sync::{Mutex, OnceLock};

use backend::InferenceBackend;
use backend_selector::{BackendSelector, BenchmarkResult};
use types::{GenerateRequest, ModelConfig, ModelHandle};

// ── Global registry ───────────────────────────────────────────────────────────

struct BackendEntry {
    backend: Box<dyn InferenceBackend + Send + Sync>,
    benchmark: BenchmarkResult,
}

fn registry() -> &'static Mutex<HashMap<ModelHandle, BackendEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<ModelHandle, BackendEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_HANDLE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);

fn alloc_handle() -> ModelHandle {
    NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── C ABI exports ─────────────────────────────────────────────────────────────

/// Load a model using the auto-selected backend.
/// Returns handle > 0 on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_load(
    model_path: *const c_char,
    context_size: c_int,
    memory_budget_mb: c_int,
) -> i64 {
    let path = match cstr_to_string(model_path) {
        Some(p) => p,
        None => { log_error("circle_inference_load: null path"); return 0; }
    };

    let config = ModelConfig {
        path,
        context_size: context_size.max(0) as u32,
        memory_budget_mb: memory_budget_mb.max(0) as u32,
    };

    // Auto-select backend for this device
    let selection = BackendSelector::select();
    log_info(&format!("circle_inference_load: {} — {}",
        selection.backend_name(), selection.reason));

    let load_start = std::time::Instant::now();
    let mut backend = selection.into_backend();

    match backend.load_model(config) {
        Ok(_) => {
            let load_time_ms = load_start.elapsed().as_millis() as u64;
            let usage = backend.resource_usage();
            let mut bench = BenchmarkResult::new(
                // backend_name from resource_usage not ideal; use capabilities()
                backend.capabilities().name.leak(), // static str approximation
                selection.tier,
                load_time_ms,
                usage.memory_used_mb,
            );

            let handle = alloc_handle();
            log_info(&format!("circle_inference_load: handle={} {}", handle, bench.summary()));

            registry().lock().unwrap().insert(handle, BackendEntry { backend, benchmark: bench });
            handle
        }
        Err(e) => {
            log_error(&format!("circle_inference_load failed: {}", e));
            0
        }
    }
}

/// Generate text. Returns bytes written into out_buf, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_generate(
    handle: i64,
    prompt: *const c_char,
    max_tokens: c_int,
    temperature: c_float,
    out_buf: *mut c_char,
    out_buf_len: c_int,
) -> c_int {
    if out_buf.is_null() || out_buf_len <= 0 { return -1; }

    let prompt_str = match cstr_to_string(prompt) {
        Some(s) => s,
        None => { write_str_to_buf(out_buf, out_buf_len, "null prompt"); return -1; }
    };

    let request = GenerateRequest {
        prompt: prompt_str,
        max_tokens: max_tokens.max(1) as u32,
        temperature,
        stop_sequences: Vec::new(),
        system_prompt: None,
    };

    let mut reg = registry().lock().unwrap();
    let entry = match reg.get_mut(&handle) {
        Some(e) => e,
        None => {
            log_error(&format!("circle_inference_generate: invalid handle {}", handle));
            drop(reg);
            write_str_to_buf(out_buf, out_buf_len, "invalid handle");
            return -1;
        }
    };

    let gen_start = std::time::Instant::now();
    match entry.backend.generate(handle, request) {
        Ok(response) => {
            let latency_ms = gen_start.elapsed().as_millis() as u64;
            entry.benchmark.record_tps(response.completion_tokens, latency_ms);
            write_str_to_buf(out_buf, out_buf_len, &response.text)
        }
        Err(e) => {
            log_error(&format!("circle_inference_generate: {}", e));
            write_str_to_buf(out_buf, out_buf_len, &e.to_string());
            -1
        }
    }
}

/// Unload model and free resources.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_unload(handle: i64) {
    if registry().lock().unwrap().remove(&handle).is_some() {
        log_info(&format!("circle_inference_unload: handle={}", handle));
    } else {
        log_error(&format!("circle_inference_unload: unknown handle {}", handle));
    }
}

/// Returns 1 if a native backend (llama or bitnet) is compiled in; 0 = stub only.
#[no_mangle]
pub extern "C" fn circle_inference_is_native_available() -> c_int {
    if cfg!(feature = "llama_native") || cfg!(feature = "bitnet_native") { 1 } else { 0 }
}

/// Writes the active backend name ("llama.cpp" or "bitnet.cpp") for a handle
/// into out_buf. Returns bytes written, or -1 if handle not found.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_backend_name(
    handle: i64,
    out_buf: *mut c_char,
    out_buf_len: c_int,
) -> c_int {
    if out_buf.is_null() || out_buf_len <= 0 { return -1; }
    let reg = registry().lock().unwrap();
    match reg.get(&handle) {
        Some(entry) => {
            let name = entry.backend.capabilities().name;
            drop(reg);
            write_str_to_buf(out_buf, out_buf_len, &name)
        }
        None => {
            drop(reg);
            write_str_to_buf(out_buf, out_buf_len, "unknown");
            -1
        }
    }
}

// ── Android logging ───────────────────────────────────────────────────────────

extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

const ANDROID_LOG_INFO:  c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;
const LOG_TAG: &[u8] = b"CircleInference\0";

fn log_info(msg: &str) {
    if let Ok(cs) = CString::new(msg) {
        unsafe { __android_log_print(ANDROID_LOG_INFO, LOG_TAG.as_ptr() as _, cs.as_ptr()); }
    }
}
fn log_error(msg: &str) {
    if let Ok(cs) = CString::new(msg) {
        unsafe { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG.as_ptr() as _, cs.as_ptr()); }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() { return None; }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
}

unsafe fn write_str_to_buf(buf: *mut c_char, buf_len: c_int, s: &str) -> c_int {
    let bytes = s.as_bytes();
    let max = (buf_len as usize).saturating_sub(1);
    let n = bytes.len().min(max);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
    *buf.add(n) = 0;
    n as c_int
}
