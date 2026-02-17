/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.inference;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import za.co.circleos.inference.DeviceCapabilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects device hardware capabilities relevant to on-device LLM inference.
 *
 * Tier classification (recommendedTier):
 *   1 — < 3 GB RAM   (minimal)
 *   2 — 3–5 GB RAM   (low)
 *   3 — 6–7 GB RAM   (mid)
 *   4 — 8–11 GB RAM  (high)
 *   5 — ≥ 12 GB RAM  (flagship)
 */
public class CapabilityDetector {

    private static final String TAG = "CircleInference.CapDet";

    private final Context mContext;

    public CapabilityDetector(Context context) {
        mContext = context;
    }

    /**
     * Detects all device capabilities and returns a populated DeviceCapabilities object.
     */
    public DeviceCapabilities detect() {
        DeviceCapabilities caps = new DeviceCapabilities();

        detectRam(caps);
        detectCpu(caps);
        detectGpu(caps);

        caps.recommendedTier = classifyTier(caps.totalRamMb);
        caps.availableBackends = getAvailableBackends();

        Log.i(TAG, "Capabilities: RAM=" + caps.totalRamMb + "MB tier=" + caps.recommendedTier
                + " cores=" + caps.cpuCores + " gpu=" + caps.gpuType);
        return caps;
    }

    private void detectRam(DeviceCapabilities caps) {
        ActivityManager am = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);
        if (am != null) {
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mi);
            caps.totalRamMb = (int) (mi.totalMem / (1024 * 1024));
            caps.availableRamMb = (int) (mi.availMem / (1024 * 1024));
        }
    }

    private void detectCpu(DeviceCapabilities caps) {
        caps.cpuCores = Runtime.getRuntime().availableProcessors();
        caps.cpuFeatures = readCpuFeatures();
    }

    private List<String> readCpuFeatures() {
        List<String> features = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Features")) {
                    String[] parts = line.split(":\\s*", 2);
                    if (parts.length == 2) {
                        for (String f : parts[1].trim().split("\\s+")) {
                            String feat = f.trim().toLowerCase();
                            if (feat.equals("neon") || feat.equals("asimd")
                                    || feat.equals("dotprod") || feat.equals("i8mm")
                                    || feat.equals("sve") || feat.equals("sve2")) {
                                features.add(feat);
                            }
                        }
                    }
                    break;
                }
            }
        } catch (IOException e) {
            Log.w(TAG, "Could not read /proc/cpuinfo: " + e.getMessage());
        }

        // Fallback: infer from ABI
        if (features.isEmpty()) {
            String abi = Build.CPU_ABI;
            if (abi != null && abi.startsWith("arm64")) {
                features.add("neon");
                features.add("asimd");
            } else if (abi != null && abi.startsWith("armeabi")) {
                features.add("neon");
            }
        }

        return features;
    }

    private void detectGpu(DeviceCapabilities caps) {
        String platform = getSystemProperty("ro.board.platform", "");
        String hardware = getSystemProperty("ro.hardware", "");

        if (platform.toLowerCase().contains("qcom")
                || platform.toLowerCase().startsWith("sm")
                || hardware.toLowerCase().contains("qcom")) {
            caps.gpuAvailable = true;
            caps.gpuType = "adreno";
        } else if (hardware.toLowerCase().contains("mali")
                || platform.toLowerCase().contains("exynos")
                || platform.toLowerCase().contains("mt")) {
            caps.gpuAvailable = true;
            caps.gpuType = "mali";
        } else {
            caps.gpuAvailable = false;
            caps.gpuType = "";
        }
    }

    /**
     * Maps total RAM to a tier (1–5).
     */
    public int classifyTier(int totalRamMb) {
        if (totalRamMb < 3 * 1024) return 1;
        if (totalRamMb < 6 * 1024) return 2;
        if (totalRamMb < 8 * 1024) return 3;
        if (totalRamMb < 12 * 1024) return 4;
        return 5;
    }

    /**
     * Returns the list of inference backends available in this build.
     * Phase 1 always returns ["llama.cpp"].
     */
    public List<String> getAvailableBackends() {
        List<String> backends = new ArrayList<>();
        backends.add("llama.cpp");
        return backends;
    }

    private String getSystemProperty(String key, String defaultValue) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method get = cls.getMethod("get", String.class, String.class);
            return (String) get.invoke(null, key, defaultValue);
        } catch (Exception e) {
            return defaultValue;
        }
    }
}
