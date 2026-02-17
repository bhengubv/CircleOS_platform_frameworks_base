/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * JNI bridge: LlamaCppBackend.java → Rust abstraction layer (Phase 2).
 * Replaces Phase 1 stubs with real Rust C ABI calls.
 */

#define LOG_TAG "CircleInference"
#include <android/log.h>
#include <jni.h>
#include <cinttypes>
#include <string>
#include <vector>

#include "circle_inference.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr int OUT_BUF_SIZE = 4 * 1024 * 1024; // 4 MB

static jlong nativeLoad(JNIEnv* env, jobject,
                        jstring modelPath, jint contextSize, jint memoryBudgetMb) {
    const char* path = env->GetStringUTFChars(modelPath, nullptr);
    if (!path) { LOGE("nativeLoad: null path"); return 0L; }
    int64_t handle = circle_inference_load(path, contextSize, memoryBudgetMb);
    env->ReleaseStringUTFChars(modelPath, path);
    if (!handle) LOGE("nativeLoad: load failed");
    else LOGI("nativeLoad: handle=%" PRId64, handle);
    return static_cast<jlong>(handle);
}

static jstring nativeGenerate(JNIEnv* env, jobject,
                               jlong handle, jstring prompt,
                               jint maxTokens, jfloat temperature) {
    const char* p = env->GetStringUTFChars(prompt, nullptr);
    if (!p) { LOGE("nativeGenerate: null prompt"); return env->NewStringUTF(""); }
    std::vector<char> buf(OUT_BUF_SIZE, '\0');
    int32_t written = circle_inference_generate(
        static_cast<int64_t>(handle), p, maxTokens, temperature,
        buf.data(), OUT_BUF_SIZE);
    env->ReleaseStringUTFChars(prompt, p);
    if (written < 0) { LOGE("nativeGenerate: error"); return env->NewStringUTF(""); }
    LOGI("nativeGenerate: %d bytes", written);
    return env->NewStringUTF(buf.data());
}

static void nativeUnload(JNIEnv*, jobject, jlong handle) {
    LOGI("nativeUnload: handle=%" PRId64, static_cast<int64_t>(handle));
    circle_inference_unload(static_cast<int64_t>(handle));
}

static const JNINativeMethod kMethods[] = {
    {"nativeLoad",     "(Ljava/lang/String;II)J",               (void*) nativeLoad},
    {"nativeGenerate", "(JLjava/lang/String;IF)Ljava/lang/String;", (void*) nativeGenerate},
    {"nativeUnload",   "(J)V",                                  (void*) nativeUnload},
};

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed"); return JNI_ERR;
    }
    jclass cls = env->FindClass("com/circleos/server/inference/LlamaCppBackend");
    if (!cls) { LOGE("JNI_OnLoad: class not found"); return JNI_ERR; }
    if (env->RegisterNatives(cls, kMethods, 3) != JNI_OK) {
        LOGE("JNI_OnLoad: RegisterNatives failed"); return JNI_ERR;
    }
    LOGI("JNI_OnLoad: registered (native=%s)",
         circle_inference_is_native_available() ? "yes" : "stub");
    return JNI_VERSION_1_6;
}
