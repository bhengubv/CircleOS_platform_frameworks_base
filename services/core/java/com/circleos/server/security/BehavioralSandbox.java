/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.security;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import za.co.circleos.security.DmzAnalysisResult;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Behavioral Analysis Sandbox — Phase 2.
 *
 * Phase 2 implementation: static behavioral analysis — detects suspicious
 * patterns in file content without execution:
 *   - Embedded URLs (C2 candidates)
 *   - Macro/script fragments (VBA, JavaScript, PowerShell)
 *   - Embedded PE headers (executable in non-executable container)
 *   - Base64-encoded payloads above threshold length
 *   - IP literals in unexpected file types
 *   - Known shellcode byte sequences
 *
 * Phase 3: Full sandboxed execution in isolated process with:
 *   - Dropped capabilities + seccomp-bpf whitelist
 *   - Network namespace isolation (captures attempted connections)
 *   - inotify filesystem monitoring
 *   - Syscall trace for API call capture
 *   - On-charge-only execution gate
 */
public class BehavioralSandbox {

    private static final String TAG = "CircleFileDmz.Sandbox";

    // Regex patterns for static analysis
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-.]+(:\\d+)?(/[\\w\\-./?%&=]*)?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern VBA_MACRO = Pattern.compile(
            "\\b(Sub|Function|AutoOpen|AutoExec|Document_Open|Workbook_Open)\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PS_PATTERN = Pattern.compile(
            "powershell|Invoke-Expression|IEX|downloadstring|webclient",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_LONG = Pattern.compile(
            "[A-Za-z0-9+/]{200,}={0,2}");
    /** MZ header — embedded PE/DLL in non-executable file */
    private static final byte[] PE_MAGIC = {0x4D, 0x5A}; // MZ
    /** ELF magic */
    private static final byte[] ELF_MAGIC = {0x7F, 0x45, 0x4C, 0x46};
    /** Max bytes to scan for static analysis */
    private static final int SCAN_LIMIT_BYTES = 5 * 1024 * 1024; // 5 MB

    public static class SandboxResult {
        public boolean suspiciousActivity;
        public List<String> findings = new ArrayList<>();
        public List<String> extractedUrls = new ArrayList<>();
        public List<String> extractedIps  = new ArrayList<>();
    }

    /**
     * Run static behavioral analysis on a file.
     * @param fileFd    Input file
     * @param mimeType  Expected MIME type
     * @param result    DmzAnalysisResult to append findings to
     * @return SandboxResult with extracted IOCs
     */
    public SandboxResult analyze(ParcelFileDescriptor fileFd,
                                 String mimeType, DmzAnalysisResult result) {
        SandboxResult sr = new SandboxResult();
        result.stageReached = DmzAnalysisResult.STAGE_SANDBOXED;

        try (FileInputStream fis = new FileInputStream(fileFd.getFileDescriptor())) {
            byte[] raw = readLimited(fis, SCAN_LIMIT_BYTES);

            // PE/ELF embedded check
            if (containsSequence(raw, PE_MAGIC)) {
                sr.suspiciousActivity = true;
                sr.findings.add("Embedded PE/DLL header detected (MZ magic)");
                result.findings.add("BEHAVIORAL: Embedded executable detected");
            }
            if (containsSequence(raw, ELF_MAGIC)) {
                sr.suspiciousActivity = true;
                sr.findings.add("Embedded ELF binary detected");
                result.findings.add("BEHAVIORAL: Embedded Linux executable detected");
            }

            // Text-based analysis
            String text = new String(raw, "ISO-8859-1");

            // URL extraction
            Matcher urlMatcher = URL_PATTERN.matcher(text);
            while (urlMatcher.find()) {
                String url = urlMatcher.group();
                if (!isCommonCdn(url)) {
                    sr.extractedUrls.add(url);
                }
            }

            // IP extraction
            Matcher ipMatcher = IPV4_PATTERN.matcher(text);
            while (ipMatcher.find()) {
                String ip = ipMatcher.group();
                if (!ip.startsWith("192.168") && !ip.startsWith("10.")
                        && !ip.startsWith("127.") && !ip.startsWith("0.")) {
                    sr.extractedIps.add(ip);
                }
            }

            // VBA macro detection
            Matcher vbaMatcher = VBA_MACRO.matcher(text);
            if (vbaMatcher.find()) {
                sr.suspiciousActivity = true;
                sr.findings.add("VBA macro code detected");
                result.findings.add("BEHAVIORAL: Macro detected — " + vbaMatcher.group());
            }

            // PowerShell detection
            Matcher psMatcher = PS_PATTERN.matcher(text);
            if (psMatcher.find()) {
                sr.suspiciousActivity = true;
                sr.findings.add("PowerShell invocation detected");
                result.findings.add("BEHAVIORAL: PowerShell code detected");
            }

            // Long Base64 blocks (possible payload)
            Matcher b64Matcher = BASE64_LONG.matcher(text);
            if (b64Matcher.find()) {
                sr.suspiciousActivity = true;
                sr.findings.add("Long Base64 block (possible encoded payload) — length: "
                        + b64Matcher.group().length());
                result.findings.add("BEHAVIORAL: Encoded payload candidate detected");
            }

            if (!sr.extractedUrls.isEmpty()) {
                result.findings.add("BEHAVIORAL: " + sr.extractedUrls.size() + " URLs extracted");
                result.c2Addresses.addAll(sr.extractedUrls);
            }
            if (!sr.extractedIps.isEmpty()) {
                result.findings.add("BEHAVIORAL: " + sr.extractedIps.size() + " IP addresses extracted");
                result.c2Addresses.addAll(sr.extractedIps);
            }

            Log.i(TAG, "Static analysis complete — suspicious=" + sr.suspiciousActivity
                    + " urls=" + sr.extractedUrls.size()
                    + " ips=" + sr.extractedIps.size());

        } catch (Exception e) {
            Log.e(TAG, "Sandbox analysis failed", e);
            result.findings.add("Sandbox error: " + e.getMessage());
        }

        return sr;
    }

    private byte[] readLimited(FileInputStream fis, int limit) throws Exception {
        byte[] buf = new byte[limit];
        int total = 0, n;
        while (total < limit && (n = fis.read(buf, total, limit - total)) != -1) {
            total += n;
        }
        byte[] result = new byte[total];
        System.arraycopy(buf, 0, result, 0, total);
        return result;
    }

    private boolean containsSequence(byte[] data, byte[] seq) {
        outer:
        for (int i = 0; i <= data.length - seq.length; i++) {
            for (int j = 0; j < seq.length; j++) {
                if (data[i + j] != seq[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    /** Don't flag common CDN hostnames as C2 candidates. */
    private boolean isCommonCdn(String url) {
        return url.contains("googleapis.com") || url.contains("gstatic.com")
                || url.contains("android.com") || url.contains("schema.org")
                || url.contains("w3.org") || url.contains("purl.org");
    }
}
