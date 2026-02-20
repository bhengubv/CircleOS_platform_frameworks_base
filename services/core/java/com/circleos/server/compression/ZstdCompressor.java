/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.util.Log;

import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionResult;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * ZSTD-capable archive compressor for Compression Phase 2.
 *
 * <p>Uses the native {@code libcircle_zstd_jni.so} library when available,
 * providing ~15–25% additional compression vs DEFLATE-9 for typical archive
 * content. Falls back to DEFLATE-9 (identical to Phase 1 ArchiveCompressor)
 * when the native library has not yet been loaded.
 *
 * <p>The native library is loaded once in the static initialiser. If it fails
 * (e.g. during build testing without the prebuilt), {@link #sNativeAvailable}
 * remains {@code false} and every call transparently uses DEFLATE-9.
 *
 * <h3>Native JNI contract</h3>
 * <pre>
 *   nativeCompressBlock(byte[] src, int level) → byte[]
 *   nativeDecompressBlock(byte[] src, int originalSize) → byte[]
 * </pre>
 * These are implemented in {@code jni/circle_zstd_jni.cpp}.
 *
 * <h3>ZSTD framing</h3>
 * Each ZIP entry that passes through ZSTD compression is stored with a 4-byte
 * magic prefix ({@code CZST}) so the reader can identify ZSTD-compressed entries
 * and decompress them correctly on read.
 *
 * <h3>Compression levels</h3>
 * <ul>
 *   <li>TIER_LOSSLESS / TIER_VISUALLY_LOSSLESS: ZSTD level 9 (balanced speed/ratio)</li>
 *   <li>TIER_AGGRESSIVE: ZSTD level 19 (maximum ratio, slower)</li>
 * </ul>
 */
public class ZstdCompressor {

    private static final String TAG = "CircleZstdComp";

    private static final int ZSTD_LEVEL_NORMAL    = 9;
    private static final int ZSTD_LEVEL_AGGRESSIVE = 19;

    /** Magic prefix written before ZSTD-compressed entry data. */
    static final byte[] ZSTD_MAGIC = { 'C', 'Z', 'S', 'T' };

    /** Maximum bytes to read per ZIP entry. */
    private static final int MAX_ENTRY_BYTES = 128 * 1024 * 1024;

    /** File extensions that are already compressed — don't re-compress. */
    private static final String[] ALREADY_COMPRESSED = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif",
        ".mp4", ".mov", ".mkv", ".avi", ".webm",
        ".mp3", ".aac", ".ogg", ".opus", ".flac",
        ".gz", ".bz2", ".xz", ".zst", ".lz4", ".br",
        ".apk", ".aab", ".jar", ".zip",
    };

    /** True iff the native ZSTD library was loaded successfully. */
    private static volatile boolean sNativeAvailable = false;

    static {
        try {
            System.loadLibrary("circle_zstd_jni");
            sNativeAvailable = true;
            Log.i(TAG, "Native ZSTD library loaded — ZSTD compression active");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "libcircle_zstd_jni.so not found — falling back to DEFLATE-9");
        }
    }

    // ── Native method declarations ────────────────────────────────────────────

    /**
     * Compress {@code src} with ZSTD at {@code level}.
     * Implemented in {@code jni/circle_zstd_jni.cpp}.
     *
     * @return compressed bytes, or null on error.
     */
    private static native byte[] nativeCompressBlock(byte[] src, int level);

    /**
     * Decompress a ZSTD block.  {@code originalSize} is a hint (used to allocate
     * the output buffer); pass 0 if unknown.
     * Implemented in {@code jni/circle_zstd_jni.cpp}.
     *
     * @return decompressed bytes, or null on error.
     */
    private static native byte[] nativeDecompressBlock(byte[] src, int originalSize);

    // ── Public API ────────────────────────────────────────────────────────────

    /** @return true if the native ZSTD library is loaded and available. */
    public static boolean isNativeAvailable() { return sNativeAvailable; }

    /**
     * Compress a ZIP archive, re-encoding each entry with ZSTD (or DEFLATE-9
     * fallback).  Drops macOS/Windows metadata garbage.  Already-compressed
     * entries (JPEG, MP4, etc.) are stored unmodified.
     */
    public CompressionResult compress(File inputFile, File outputFile, int tier) {
        CompressionResult result = new CompressionResult();
        result.originalBytes = inputFile.length();
        long start = System.currentTimeMillis();

        try {
            int zstdLevel = (tier == CompressionRequest.TIER_AGGRESSIVE)
                    ? ZSTD_LEVEL_AGGRESSIVE : ZSTD_LEVEL_NORMAL;

            repackZip(inputFile, outputFile, zstdLevel);

            result.compressedBytes = outputFile.length();
            if (result.compressedBytes >= result.originalBytes * 0.95f) {
                result.status = CompressionResult.STATUS_SKIPPED;
                result.method = "zstd-zip-skipped";
                outputFile.delete();
            } else {
                result.status = CompressionResult.STATUS_OK;
                result.method = sNativeAvailable ? "zstd-zip" : "deflate9-zip";
            }
        } catch (Exception e) {
            Log.e(TAG, "ZSTD archive compression failed: " + inputFile.getName(), e);
            result.status = CompressionResult.STATUS_ERROR;
        } finally {
            result.savingsPercent = savingsPercent(result.originalBytes, result.compressedBytes);
            result.processingMs   = System.currentTimeMillis() - start;
        }
        return result;
    }

    // ── ZIP repack ────────────────────────────────────────────────────────────

    private void repackZip(File in, File out, int zstdLevel) throws IOException {
        try (ZipInputStream  zin  = new ZipInputStream(new FileInputStream(in));
             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(out))) {

            zout.setLevel(Deflater.BEST_COMPRESSION);
            ZipEntry entry;

            while ((entry = zin.getNextEntry()) != null) {
                String name = entry.getName();
                if (shouldDrop(name)) {
                    zin.closeEntry();
                    continue;
                }

                byte[] data = readEntry(zin);
                zin.closeEntry();

                ZipEntry newEntry = new ZipEntry(name);
                newEntry.setExtra(null);

                if (entry.isDirectory()) {
                    newEntry.setMethod(ZipEntry.STORED);
                    newEntry.setSize(0);
                    newEntry.setCrc(0);
                    zout.putNextEntry(newEntry);
                } else if (alreadyCompressed(name)) {
                    newEntry.setMethod(ZipEntry.STORED);
                    newEntry.setSize(data.length);
                    newEntry.setCrc(crc32(data));
                    zout.putNextEntry(newEntry);
                    zout.write(data);
                } else if (sNativeAvailable) {
                    // Compress with ZSTD; prefix with magic so decompressor can identify it
                    byte[] zstdData = nativeCompressBlock(data, zstdLevel);
                    if (zstdData != null && zstdData.length + ZSTD_MAGIC.length < data.length) {
                        byte[] tagged = new byte[ZSTD_MAGIC.length + zstdData.length];
                        System.arraycopy(ZSTD_MAGIC, 0, tagged, 0, ZSTD_MAGIC.length);
                        System.arraycopy(zstdData, 0, tagged, ZSTD_MAGIC.length, zstdData.length);
                        // Store the ZSTD blob as STORED (already "compressed")
                        newEntry.setMethod(ZipEntry.STORED);
                        newEntry.setSize(tagged.length);
                        newEntry.setCrc(crc32(tagged));
                        zout.putNextEntry(newEntry);
                        zout.write(tagged);
                    } else {
                        // ZSTD didn't help — fall back to DEFLATE
                        zout.putNextEntry(newEntry);
                        zout.write(data);
                    }
                } else {
                    // DEFLATE-9 fallback (same as Phase 1 ArchiveCompressor)
                    zout.putNextEntry(newEntry);
                    zout.write(data);
                }
                zout.closeEntry();
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean shouldDrop(String name) {
        if (name.startsWith("__MACOSX/")) return true;
        if (name.endsWith("/.DS_Store")) return true;
        if (name.equals(".DS_Store"))   return true;
        if (name.equalsIgnoreCase("Thumbs.db"))    return true;
        if (name.equalsIgnoreCase("desktop.ini"))  return true;
        return false;
    }

    private boolean alreadyCompressed(String name) {
        String lower = name.toLowerCase();
        for (String ext : ALREADY_COMPRESSED) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    private byte[] readEntry(ZipInputStream zin) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n, total = 0;
        while ((n = zin.read(buf)) != -1) {
            if (total + n > MAX_ENTRY_BYTES) break;
            bos.write(buf, 0, n);
            total += n;
        }
        return bos.toByteArray();
    }

    private long crc32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private int savingsPercent(long original, long compressed) {
        if (original == 0) return 0;
        return (int) ((original - compressed) * 100L / original);
    }
}
