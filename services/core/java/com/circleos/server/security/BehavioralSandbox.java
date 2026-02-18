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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

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

    // Phase 3 constants
    /** Native sandbox helper binary; ships in /system/bin/ alongside the OS. */
    private static final String SANDBOX_BINARY   = "/system/bin/circle_sandbox";
    /** Temp directory for extracted files before analysis. */
    private static final String SANDBOX_TEMP_DIR = "/data/local/tmp";
    /** Maximum wall-clock time (ms) allowed for sandbox execution. */
    private static final int    SANDBOX_TIMEOUT_MS = 30_000;

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

    /* ── Phase 3: Sandboxed execution with namespace isolation ─────────── */

    /**
     * Execute the file inside an isolated subprocess managed by the
     * {@code circle_sandbox} native helper binary.  The binary handles:
     * <ul>
     *   <li>Network namespace creation ({@code unshare(CLONE_NEWNET)}) — all
     *       outbound connections are captured, never reach the network.</li>
     *   <li>seccomp-bpf allow-list — only whitelisted syscalls permitted.</li>
     *   <li>inotify filesystem monitoring — reports accessed paths.</li>
     *   <li>Capability drop ({@code prctl(PR_SET_SECCOMP)}) after setup.</li>
     * </ul>
     *
     * <p>Only invoked for high-risk MIME types (APK, ELF, shell scripts).
     * Gated on device-charging state to avoid battery drain.
     *
     * @param fileFd         File to analyse (read-only)
     * @param mimeType       Declared MIME type of the file
     * @param result         DmzAnalysisResult to append findings to
     * @param deviceCharging Whether the device is currently charging
     * @return SandboxResult augmented with runtime IOCs
     */
    public SandboxResult executeInNamespace(ParcelFileDescriptor fileFd,
            String mimeType, DmzAnalysisResult result, boolean deviceCharging) {
        SandboxResult sr = new SandboxResult();

        if (!deviceCharging) {
            Log.d(TAG, "Phase 3 skipped — not charging");
            result.findings.add("SANDBOX[P3]: skipped (not charging)");
            return sr;
        }

        if (!new File(SANDBOX_BINARY).exists()) {
            Log.w(TAG, "circle_sandbox not found — using proc monitoring fallback");
            return executeWithProcMonitor(fileFd, mimeType, result);
        }

        File tempFile = null;
        Process process = null;
        try {
            tempFile = extractToTemp(fileFd);

            ProcessBuilder pb = new ProcessBuilder(
                    SANDBOX_BINARY,
                    "--timeout", String.valueOf(SANDBOX_TIMEOUT_MS / 1000),
                    "--no-net",
                    "--trace-syscalls",
                    "--input",  tempFile.getAbsolutePath(),
                    "--mime",   mimeType
            );
            pb.redirectErrorStream(true);
            process = pb.start();

            byte[] output = readWithTimeout(process.getInputStream(), SANDBOX_TIMEOUT_MS);
            boolean exited = process.waitFor(SANDBOX_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            if (!exited) {
                process.destroyForcibly();
                sr.suspiciousActivity = true;
                result.findings.add("SANDBOX[P3]: TIMEOUT after "
                        + (SANDBOX_TIMEOUT_MS / 1000) + "s — likely evasive loop");
                return sr;
            }

            parseSandboxOutput(new String(output, "UTF-8"), sr, result);
            Log.i(TAG, "Phase 3 sandbox complete — suspicious=" + sr.suspiciousActivity);

        } catch (Exception e) {
            Log.e(TAG, "Phase 3 execution failed", e);
            result.findings.add("SANDBOX[P3]: error — " + e.getMessage());
        } finally {
            if (process != null) process.destroyForcibly();
            if (tempFile != null) tempFile.delete();
        }
        return sr;
    }

    /**
     * Fallback when {@code circle_sandbox} is unavailable.
     * Spawns the file in a background process and monitors
     * {@code /proc/<pid>/net/tcp} and {@code /proc/<pid>/net/tcp6} for
     * outbound connection attempts.
     */
    private SandboxResult executeWithProcMonitor(ParcelFileDescriptor fileFd,
            String mimeType, DmzAnalysisResult result) {
        SandboxResult sr = new SandboxResult();
        File tempFile = null;
        Process process = null;
        try {
            tempFile = extractToTemp(fileFd);
            // Only attempt execution for ELF/shell types; document types get static-only
            if (!mimeType.contains("x-executable") && !mimeType.contains("x-sharedlib")
                    && !mimeType.contains("x-sh")) {
                result.findings.add("SANDBOX[P3-fallback]: skipped for MIME " + mimeType);
                return sr;
            }

            tempFile.setExecutable(true, true);
            ProcessBuilder pb = new ProcessBuilder(tempFile.getAbsolutePath());
            pb.environment().clear(); // minimal environment
            pb.redirectErrorStream(true);
            process = pb.start();

            int pid = getPid(process);
            long deadline = System.currentTimeMillis() + SANDBOX_TIMEOUT_MS;

            while (System.currentTimeMillis() < deadline && isAlive(process)) {
                if (pid > 0) monitorProcNet(pid, sr, result);
                try { Thread.sleep(500); } catch (InterruptedException ie) { break; }
            }

            if (isAlive(process)) {
                process.destroyForcibly();
                result.findings.add("SANDBOX[P3-fallback]: process timed out");
            }

        } catch (Exception e) {
            Log.w(TAG, "Proc-monitor fallback failed: " + e.getMessage());
        } finally {
            if (process != null) process.destroyForcibly();
            if (tempFile != null) { tempFile.setExecutable(false, false); tempFile.delete(); }
        }
        return sr;
    }

    /**
     * Parses the JSON report emitted by {@code circle_sandbox} on stdout.
     *
     * <pre>
     * {
     *   "suspicious": true,
     *   "connections": ["1.2.3.4:80", "evil.example.com:443"],
     *   "syscalls":    ["connect", "execve"],
     *   "files":       ["/data/data/com.victim/shared_prefs/token.xml"]
     * }
     * </pre>
     */
    private void parseSandboxOutput(String json, SandboxResult sr, DmzAnalysisResult result) {
        try {
            JSONObject obj = new JSONObject(json);
            sr.suspiciousActivity = obj.optBoolean("suspicious", false);

            JSONArray conns = obj.optJSONArray("connections");
            if (conns != null) {
                for (int i = 0; i < conns.length(); i++) {
                    String c = conns.getString(i);
                    sr.extractedIps.add(c);
                    result.c2Addresses.add(c);
                    result.findings.add("SANDBOX[P3]: outbound connection attempt — " + c);
                    sr.suspiciousActivity = true;
                }
            }

            JSONArray syscalls = obj.optJSONArray("syscalls");
            if (syscalls != null) {
                for (int i = 0; i < syscalls.length(); i++) {
                    String sc = syscalls.getString(i);
                    if ("execve".equals(sc) || "fork".equals(sc) || "clone".equals(sc)) {
                        sr.findings.add("SANDBOX[P3]: process creation — " + sc);
                        sr.suspiciousActivity = true;
                    } else if ("ptrace".equals(sc)) {
                        sr.findings.add("SANDBOX[P3]: debugger-detection syscall — ptrace");
                        sr.suspiciousActivity = true;
                    }
                }
            }

            JSONArray files = obj.optJSONArray("files");
            if (files != null) {
                for (int i = 0; i < files.length(); i++) {
                    String f = files.getString(i);
                    if (f.contains("/data/data/") || f.contains("/.ssh/")
                            || f.contains("/etc/passwd") || f.contains("/proc/net")) {
                        sr.findings.add("SANDBOX[P3]: sensitive file access — " + f);
                        sr.suspiciousActivity = true;
                    }
                }
            }

            if (sr.suspiciousActivity) {
                result.findings.add("SANDBOX[P3]: malicious runtime behaviour detected");
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse sandbox output: " + e.getMessage());
        }
    }

    /** Copy PFD content to a temporary file in SANDBOX_TEMP_DIR. */
    private File extractToTemp(ParcelFileDescriptor pfd) throws Exception {
        new File(SANDBOX_TEMP_DIR).mkdirs();
        File tmp = File.createTempFile("dmz_p3_", ".bin", new File(SANDBOX_TEMP_DIR));
        try (FileInputStream in  = new FileInputStream(pfd.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        return tmp;
    }

    /** Read from {@code is} until EOF or timeout, returning all bytes collected. */
    private byte[] readWithTimeout(java.io.InputStream is, int timeoutMs) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (is.available() > 0) {
                int n = is.read(buf);
                if (n < 0) break;
                baos.write(buf, 0, n);
            } else {
                try { Thread.sleep(100); } catch (InterruptedException ie) { break; }
            }
        }
        return baos.toByteArray();
    }

    /** Read /proc/<pid>/net/tcp{,6} and record any non-loopback remote addresses. */
    private void monitorProcNet(int pid, SandboxResult sr, DmzAnalysisResult result) {
        for (String netFile : new String[]{"/proc/" + pid + "/net/tcp",
                                           "/proc/" + pid + "/net/tcp6"}) {
            try (BufferedReader br = new BufferedReader(
                    new java.io.FileReader(netFile))) {
                String line; boolean first = true;
                while ((line = br.readLine()) != null) {
                    if (first) { first = false; continue; } // skip header
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length < 4) continue;
                    // state 01 = ESTABLISHED, 02 = SYN_SENT
                    String state = parts[3];
                    if (!"01".equals(state) && !"02".equals(state)) continue;
                    String remote = hexToIpPort(parts[2]);
                    if (remote != null && !remote.startsWith("127.")
                            && !remote.startsWith("0.0.0.0")) {
                        if (!sr.extractedIps.contains(remote)) {
                            sr.extractedIps.add(remote);
                            result.c2Addresses.add(remote);
                            result.findings.add("SANDBOX[P3-monitor]: connection to " + remote);
                            sr.suspiciousActivity = true;
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    /** Decode hex-encoded IP:port from /proc/net/tcp (little-endian). */
    private String hexToIpPort(String hexIpPort) {
        try {
            String[] parts = hexIpPort.split(":");
            if (parts.length != 2) return null;
            long ipHex  = Long.parseLong(parts[0], 16);
            int  port   = Integer.parseInt(parts[1], 16);
            // IPv4 — little-endian 4 bytes
            if (parts[0].length() == 8) {
                return ((ipHex & 0xFF)) + "." + ((ipHex >> 8) & 0xFF) + "."
                     + ((ipHex >> 16) & 0xFF) + "." + ((ipHex >> 24) & 0xFF)
                     + ":" + port;
            }
            return null; // IPv6 not decoded here
        } catch (Exception e) { return null; }
    }

    private boolean isAlive(Process p) {
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private int getPid(Process p) {
        try {
            java.lang.reflect.Field f = p.getClass().getDeclaredField("pid");
            f.setAccessible(true);
            return (int) f.get(p);
        } catch (Exception e) { return -1; }
    }
}
