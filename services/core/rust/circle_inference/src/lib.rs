/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! libcircle_inference — Rust abstraction layer for CircleOS on-device inference.
//!
//! This crate exports a C ABI consumed by circle_inference_jni.cpp, which
//! bridges the Java service layer to this Rust implementation.
//!
//! Exported C functions:
//!   circle_inference_load()               — load a GGUF model
//!   circle_inference_generate()           — synchronous text generation
//!   circle_inference_unload()             — free a loaded model
//!   circle_inference_is_native_available()— query backend availability

mod backend;
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
use llama_backend::LlamaCppBackend;
use types::{GenerateRequest, ModelConfig, ModelHandle};

// ── Global model registry ─────────────────────────────────────────────────────
// Maps handle → LlamaCppBackend instance.
// Protected by Mutex; all operations serialised by the Java HandlerThread.

fn registry() -> &'static Mutex<HashMap<ModelHandle, LlamaCppBackend>> {
    static REGISTRY: OnceLock<Mutex<HashMap<ModelHandle, LlamaCppBackend>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Handle allocator ──────────────────────────────────────────────────────────

static NEXT_HANDLE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);

fn alloc_handle() -> ModelHandle {
    NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── Helper: safely read a C string ───────────────────────────────────────────

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() { return None; }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
}

// ── C ABI exports ─────────────────────────────────────────────────────────────

/// Load a GGUF model file.
///
/// Returns a handle > 0 on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_load(
    model_path: *const c_char,
    context_size: c_int,
    memory_budget_mb: c_int,
) -> i64 {
    let path = match cstr_to_string(model_path) {
        Some(p) => p,
        None => {
            log_error("circle_inference_load: null model_path");
            return 0;
        }
    };

    let config = ModelConfig {
        path,
        context_size: context_size.max(0) as u32,
        memory_budget_mb: memory_budget_mb.max(0) as u32,
    };

    let handle = alloc_handle();
    let mut backend = LlamaCppBackend::new();

    match backend.load_model(config) {
        Ok(_model_handle) => {
            registry().lock().unwrap().insert(handle, backend);
            log_info(&format!("circle_inference_load: handle={}", handle));
            handle
        }
        Err(e) => {
            log_error(&format!("circle_inference_load failed: {}", e));
            0
        }
    }
}

/// Generate text from a prompt.
///
/// Writes UTF-8 result (null-terminated) into `out_buf[0..out_buf_len]`.
/// Returns bytes written (not counting null), or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_generate(
    handle: i64,
    prompt: *const c_char,
    max_tokens: c_int,
    temperature: c_float,
    out_buf: *mut c_char,
    out_buf_len: c_int,
) -> c_int {
    if out_buf.is_null() || out_buf_len <= 0 {
        return -1;
    }

    let prompt_str = match cstr_to_string(prompt) {
        Some(s) => s,
        None => {
            write_error_to_buf(out_buf, out_buf_len, "null prompt");
            return -1;
        }
    };

    let request = GenerateRequest {
        prompt: prompt_str,
        max_tokens: max_tokens.max(1) as u32,
        temperature,
        stop_sequences: Vec::new(),
        system_prompt: None,
    };

    let reg = registry().lock().unwrap();
    let backend = match reg.get(&handle) {
        Some(b) => b,
        None => {
            log_error(&format!("circle_inference_generate: invalid handle {}", handle));
            drop(reg);
            write_error_to_buf(out_buf, out_buf_len, "invalid handle");
            return -1;
        }
    };

    match backend.generate(handle, request) {
        Ok(response) => {
            write_str_to_buf(out_buf, out_buf_len, &response.text)
        }
        Err(e) => {
            log_error(&format!("circle_inference_generate error: {}", e));
            write_error_to_buf(out_buf, out_buf_len, &e.to_string());
            -1
        }
    }
}

/// Unload a model and free all associated native resources.
#[no_mangle]
pub unsafe extern "C" fn circle_inference_unload(handle: i64) {
    let removed = registry().lock().unwrap().remove(&handle);
    if removed.is_some() {
        log_info(&format!("circle_inference_unload: handle={}", handle));
    } else {
        log_error(&format!("circle_inference_unload: unknown handle {}", handle));
    }
}

/// Returns 1 if a native inference backend is compiled in; 0 for stub mode.
#[no_mangle]
pub extern "C" fn circle_inference_is_native_available() -> c_int {
    if cfg!(feature = "llama_native") { 1 } else { 0 }
}

// ── Logging ───────────────────────────────────────────────────────────────────
// android/log.h is available in the NDK and AOSP build environment.

extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

const ANDROID_LOG_INFO:  c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;
const LOG_TAG: &[u8] = b"CircleInference\0";

fn log_info(msg: &str) {
    let tag = LOG_TAG.as_ptr() as *const c_char;
    if let Ok(cs) = CString::new(msg) {
        unsafe { __android_log_print(ANDROID_LOG_INFO, tag, cs.as_ptr()); }
    }
}

fn log_error(msg: &str) {
    let tag = LOG_TAG.as_ptr() as *const c_char;
    if let Ok(cs) = CString::new(msg) {
        unsafe { __android_log_print(ANDROID_LOG_ERROR, tag, cs.as_ptr()); }
    }
}

// ── Buffer helpers ────────────────────────────────────────────────────────────

/// Copy `s` into a C char buffer. Returns bytes written (not counting null),
/// clamped to `buf_len - 1`. Always null-terminates.
unsafe fn write_str_to_buf(buf: *mut c_char, buf_len: c_int, s: &str) -> c_int {
    let bytes = s.as_bytes();
    let max = (buf_len as usize).saturating_sub(1);
    let write_len = bytes.len().min(max);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, write_len);
    *buf.add(write_len) = 0;
    write_len as c_int
}

unsafe fn write_error_to_buf(buf: *mut c_char, buf_len: c_int, msg: &str) {
    write_str_to_buf(buf, buf_len, msg);
}
