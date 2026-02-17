/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 JNI stub for the CircleOS on-device LLM inference service.
 *
 * These stubs allow the Java service to compile and link against a real
 * .so without requiring the full llama.cpp dependency tree in Phase 1.
 * Phase 2 will replace these stubs with real llama.cpp calls.
 *
 * Registered methods match the native declarations in LlamaCppBackend.java:
 *   private native long   nativeLoad(String modelPath, int contextSize, int memoryBudgetMb)
 *   private native String nativeGenerate(long handle, String prompt, int maxTokens, float temperature)
 *   private native void   nativeUnload(long handle)
 */

#define LOG_TAG "CircleInference"
#include <android/log.h>
#include <jni.h>
#include <string>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Stub implementations
// ---------------------------------------------------------------------------

/**
 * nativeLoad — Phase 1 stub.
 * Returns a placeholder handle of 1 without loading any model.
 */
static jlong nativeLoad(JNIEnv* env, jobject /* thiz */,
                        jstring modelPath, jint contextSize, jint memoryBudgetMb) {
    const char* path = env->GetStringUTFChars(modelPath, nullptr);
    LOGI("nativeLoad stub: path=%s contextSize=%d memBudget=%dMB",
         path ? path : "<null>", contextSize, memoryBudgetMb);
    if (path) env->ReleaseStringUTFChars(modelPath, path);

    // Phase 1: return a non-zero handle to indicate success
    return static_cast<jlong>(1);
}

/**
 * nativeGenerate — Phase 1 stub.
 * Returns a fixed placeholder string.
 */
static jstring nativeGenerate(JNIEnv* env, jobject /* thiz */,
                              jlong handle, jstring prompt,
                              jint maxTokens, jfloat temperature) {
    LOGI("nativeGenerate stub: handle=%lld maxTokens=%d temperature=%.2f",
         static_cast<long long>(handle), maxTokens, temperature);

    std::string result = "[llama.cpp not yet linked]";
    return env->NewStringUTF(result.c_str());
}

/**
 * nativeUnload — Phase 1 stub.
 * No-op; there is nothing to free in Phase 1.
 */
static void nativeUnload(JNIEnv* env, jobject /* thiz */, jlong handle) {
    LOGI("nativeUnload stub: handle=%lld", static_cast<long long>(handle));
    // Nothing to free in Phase 1
}

// ---------------------------------------------------------------------------
// JNI registration
// ---------------------------------------------------------------------------

static const JNINativeMethod kMethods[] = {
    {"nativeLoad",     "(Ljava/lang/String;II)J",              (void*) nativeLoad},
    {"nativeGenerate", "(JLjava/lang/String;IF)Ljava/lang/String;", (void*) nativeGenerate},
    {"nativeUnload",   "(J)V",                                 (void*) nativeUnload},
};

static const char* kClassName =
    "com/circleos/server/inference/LlamaCppBackend";

jint JNI_OnLoad(JavaVM* vm, void* /* reserved */) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }

    jclass cls = env->FindClass(kClassName);
    if (cls == nullptr) {
        LOGE("JNI_OnLoad: class not found: %s", kClassName);
        return JNI_ERR;
    }

    int rc = env->RegisterNatives(cls, kMethods,
                                  static_cast<jint>(sizeof(kMethods) / sizeof(kMethods[0])));
    if (rc != JNI_OK) {
        LOGE("JNI_OnLoad: RegisterNatives failed: %d", rc);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: circle_inference registered (%zu methods)",
         sizeof(kMethods) / sizeof(kMethods[0]));
    return JNI_VERSION_1_6;
}
