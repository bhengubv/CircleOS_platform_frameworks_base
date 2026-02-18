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
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Document compressor — Phase 1.
 *
 * Handles:
 *   PDF      — strip XMP metadata block; repack with DEFLATE best compression
 *   DOCX / XLSX / PPTX / ODP / ODT / ODS (Open XML / ODF ZIP containers)
 *             — repack internal ZIP with BEST_COMPRESSION
 *             — drop thumbnail cache, print settings, revision history
 *             — strip author/identity metadata from document.xml/core.xml
 *
 * Phase 2: full image recompression inside PDF/Office (requires native MuPDF/libzip).
 * Phase 3: AI semantic compression (summary-based preview generation).
 */
public class DocumentCompressor {

    private static final String TAG = "CircleDocComp";

    /** Maximum individual entry size to recompress (64 MB). */
    private static final int MAX_ENTRY_BYTES = 64 * 1024 * 1024;

    /** Entries to drop from Office ZIP containers. */
    private static final String[] DROP_ENTRIES = {
        "docProps/thumbnail.jpeg",
        "docProps/thumbnail.png",
        "word/settings.xml",    // revision tracking, etc.
        "xl/calcChain.xml",     // Excel calc chain (auto-rebuilt)
    };

    public CompressionResult compress(File inputFile, File outputFile,
                                      String mimeType, int tier) {
        CompressionResult result = new CompressionResult();
        result.originalBytes = inputFile.length();
        long start = System.currentTimeMillis();

        try {
            if (isPdf(mimeType)) {
                compressPdf(inputFile, outputFile, result, tier);
            } else if (isOfficeZip(mimeType, inputFile.getName())) {
                repackOfficeZip(inputFile, outputFile, result, tier);
            } else {
                result.status         = CompressionResult.STATUS_SKIPPED;
                result.compressedBytes = result.originalBytes;
                result.method         = "doc-passthrough";
            }
        } catch (Exception e) {
            Log.e(TAG, "Document compression failed: " + inputFile.getName(), e);
            result.status = CompressionResult.STATUS_ERROR;
        } finally {
            result.savingsPercent = savingsPercent(result.originalBytes, result.compressedBytes);
            result.processingMs   = System.currentTimeMillis() - start;
        }
        return result;
    }

    /* ── PDF ─────────────────────────────────────────────────────────── */

    /**
     * Phase 2 PDF compression:
     *   1. Strip XMP metadata block.
     *   2. Re-deflate all FlateDecode image streams at BEST_COMPRESSION.
     *
     * Stream replacement strategy: scan for FlateDecode image streams, inflate,
     * re-deflate at level 9. If the new stream is smaller, replace it in-place,
     * padding with trailing spaces so all object byte offsets remain valid —
     * avoiding the need to rebuild the cross-reference table.
     */
    private void compressPdf(File in, File out, CompressionResult result, int tier)
            throws IOException {
        byte[] data = readAll(in);

        // Step 1: strip XMP metadata
        byte[] stripped = stripPdfXmp(data);
        if (stripped.length < data.length) {
            result.metadataStripped = true;
        }

        // Step 2: recompress FlateDecode image streams
        int[] stats = new int[]{0, 0}; // [streamsProcessed, bytesSaved]
        byte[] recompressed = recompressPdfFlateStreams(stripped, stats, tier);

        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(recompressed);
        }

        result.status          = CompressionResult.STATUS_OK;
        result.compressedBytes = out.length();

        if (result.compressedBytes >= result.originalBytes) {
            result.status          = CompressionResult.STATUS_SKIPPED;
            result.compressedBytes = result.originalBytes;
            result.method          = "pdf-no-gain";
        } else {
            result.method = "pdf-xmp-strip+flate-repack"
                    + "(streams=" + stats[0] + ",saved=" + stats[1] + "B)";
        }
        Log.i(TAG, "PDF compress: " + in.getName() + " → " + result.method);
    }

    /**
     * Strip XMP metadata packet from PDF bytes.
     * XMP packets are enclosed in: {@code <?xpacket begin...?>...<?xpacket end="w"?>}
     */
    private byte[] stripPdfXmp(byte[] pdf) {
        String text = new String(pdf, StandardCharsets.ISO_8859_1);
        int start = text.indexOf("<?xpacket begin");
        int end   = text.indexOf("<?xpacket end");
        if (start < 0 || end < 0 || end <= start) return pdf;
        end = text.indexOf("?>", end) + 2;
        if (end < 2) return pdf;

        ByteArrayOutputStream bos = new ByteArrayOutputStream(pdf.length);
        for (int i = 0; i < start; i++) bos.write(pdf[i]);
        // Pad removed region with spaces to preserve byte offsets
        for (int i = start; i < end; i++) bos.write(' ');
        for (int i = end; i < pdf.length; i++) bos.write(pdf[i]);
        return bos.toByteArray();
    }

    // ── PDF FlateDecode image stream recompression ─────────────────────────

    /**
     * Scans the PDF byte array for FlateDecode image streams and re-deflates
     * each one at BEST_COMPRESSION. Uses in-place replacement with space-padding
     * to preserve existing byte offsets (no xref rebuild required).
     *
     * Detection heuristic: look for the byte sequence {@code /FlateDecode} (or
     * {@code /Fl }) within 512 bytes before each {@code stream\n} marker, AND
     * {@code /Subtype /Image} (or {@code /Im}) nearby. Plain content streams
     * (page operators) are skipped.
     *
     * @param pdf   Input PDF bytes (already XMP-stripped)
     * @param stats int[]{streamsProcessed, bytesSaved} updated in-place
     * @param tier  Compression tier (AGGRESSIVE uses level 9, else 7)
     */
    private byte[] recompressPdfFlateStreams(byte[] pdf, int[] stats, int tier) {
        byte[] work = pdf.clone();
        byte[] streamMarker    = "stream\n".getBytes(StandardCharsets.ISO_8859_1);
        byte[] endStreamMarker = "endstream".getBytes(StandardCharsets.ISO_8859_1);
        int deflateLevel = (tier == CompressionRequest.TIER_AGGRESSIVE)
                ? Deflater.BEST_COMPRESSION : 7;

        int pos = 0;
        while (pos < work.length - streamMarker.length) {
            int streamStart = indexOf(work, streamMarker, pos);
            if (streamStart < 0) break;

            int dataStart = streamStart + streamMarker.length;

            // Look back up to 1024 bytes for the object dictionary
            int dictLookback = Math.max(0, streamStart - 1024);
            String dictText  = new String(work, dictLookback, streamStart - dictLookback,
                    StandardCharsets.ISO_8859_1);

            // Only process FlateDecode image streams
            boolean isFlateDecode = dictText.contains("/FlateDecode")
                    || dictText.contains("/Fl ");
            boolean isImageStream = dictText.contains("/Subtype /Image")
                    || dictText.contains("/Subtype/Image")
                    || dictText.contains("/Im ")
                    || dictText.contains("/Subtype /Form"); // forms can be large

            if (!isFlateDecode || !isImageStream) {
                pos = dataStart;
                continue;
            }

            // Find the /Length value in the dict to know how long the stream is
            long streamLen = extractLength(dictText);
            if (streamLen <= 0 || dataStart + streamLen > work.length) {
                pos = dataStart;
                continue;
            }

            // Verify endstream marker follows
            int dataEnd = (int) (dataStart + streamLen);
            if (!matchesAt(work, endStreamMarker, dataEnd)
                    && !matchesAt(work, endStreamMarker, dataEnd + 1)) {
                pos = dataStart;
                continue;
            }

            // Inflate the existing stream data
            byte[] compressed = java.util.Arrays.copyOfRange(work, dataStart, dataEnd);
            byte[] raw        = inflate(compressed);
            if (raw == null) {
                // Corrupted stream — skip
                pos = dataEnd;
                continue;
            }

            // Re-deflate at best compression
            byte[] reDeflated = deflate(raw, deflateLevel);
            int saved = compressed.length - reDeflated.length;

            if (saved > 0 && reDeflated.length <= compressed.length) {
                // Replace stream data in-place; pad remaining bytes with spaces
                System.arraycopy(reDeflated, 0, work, dataStart, reDeflated.length);
                java.util.Arrays.fill(work, dataStart + reDeflated.length, dataEnd, (byte) ' ');

                // Update /Length value in-place (pad shorter number with spaces)
                updateLengthInDict(work, dictLookback, streamStart, streamLen, reDeflated.length);

                stats[0]++;
                stats[1] += saved;
                Log.d(TAG, "PDF FlateDecode stream recompressed: saved " + saved + " bytes");
            }
            pos = dataEnd;
        }
        return work;
    }

    /** Parse /Length N from a PDF dict text. Returns -1 if not found. */
    private long extractLength(String dictText) {
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile("/Length\\s+(\\d+)").matcher(dictText);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    /** Update /Length N → /Length M in the raw work buffer, padding with spaces. */
    private void updateLengthInDict(byte[] work, int dictStart, int dictEnd,
                                    long oldLen, int newLen) {
        String old = "/Length " + oldLen;
        String nw  = "/Length " + newLen;
        // Pad new string to same length as old with trailing spaces
        while (nw.length() < old.length()) nw += " ";
        byte[] oldB = old.getBytes(StandardCharsets.ISO_8859_1);
        byte[] newB = nw.getBytes(StandardCharsets.ISO_8859_1);
        int idx = indexOf(work, oldB, dictStart);
        if (idx >= 0 && idx < dictEnd) {
            System.arraycopy(newB, 0, work, idx, Math.min(newB.length, oldB.length));
        }
    }

    /** Inflate a DEFLATE-compressed byte array. Returns null on error. */
    private static byte[] inflate(byte[] data) {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length * 3);
            byte[] buf = new byte[32768];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0 && inflater.needsInput()) break;
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        } catch (DataFormatException e) {
            Log.w(TAG, "inflate failed", e);
            return null;
        } finally {
            inflater.end();
        }
    }

    /** Deflate raw bytes at the given compression level. */
    private static byte[] deflate(byte[] data, int level) {
        Deflater deflater = new Deflater(level);
        try {
            deflater.setInput(data);
            deflater.finish();
            ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);
            byte[] buf = new byte[32768];
            while (!deflater.finished()) {
                bos.write(buf, 0, deflater.deflate(buf));
            }
            return bos.toByteArray();
        } finally {
            deflater.end();
        }
    }

    /** Find needle in haystack starting at fromIndex. Returns -1 if not found. */
    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /** Returns true if needle matches haystack at position pos. */
    private static boolean matchesAt(byte[] haystack, byte[] needle, int pos) {
        if (pos < 0 || pos + needle.length > haystack.length) return false;
        for (int i = 0; i < needle.length; i++) {
            if (haystack[pos + i] != needle[i]) return false;
        }
        return true;
    }

    /* ── Office ZIP containers ──────────────────────────────────────── */

    private void repackOfficeZip(File in, File out, CompressionResult result, int tier)
            throws IOException {
        int deflateLevel = tier == CompressionRequest.TIER_AGGRESSIVE
                ? Deflater.BEST_COMPRESSION
                : (tier == CompressionRequest.TIER_LOSSLESS
                        ? Deflater.BEST_COMPRESSION
                        : Deflater.DEFAULT_COMPRESSION);

        try (ZipInputStream zin  = new ZipInputStream(new FileInputStream(in));
             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(out))) {

            zout.setLevel(deflateLevel);
            ZipEntry entry;

            while ((entry = zin.getNextEntry()) != null) {
                String name = entry.getName();

                // Drop unnecessary entries
                if (shouldDrop(name)) {
                    zin.closeEntry();
                    continue;
                }

                // Strip author/identity from core.xml
                byte[] entryData;
                if (name.equals("docProps/core.xml") || name.equals("docProps/app.xml")) {
                    entryData = stripOfficeMetadata(readEntry(zin, entry));
                    result.metadataStripped = true;
                } else {
                    entryData = readEntry(zin, entry);
                }

                ZipEntry newEntry = new ZipEntry(name);
                // Preserve stored entries (e.g. uncompressed media already optimal)
                if (entry.getMethod() == ZipEntry.STORED) {
                    newEntry.setMethod(ZipEntry.STORED);
                    newEntry.setSize(entryData.length);
                    newEntry.setCrc(crc32(entryData));
                }
                zout.putNextEntry(newEntry);
                zout.write(entryData);
                zout.closeEntry();
                zin.closeEntry();
            }
        }

        result.status          = CompressionResult.STATUS_OK;
        result.compressedBytes = out.length();
        result.method          = "office-repack-deflate" + deflateLevel;

        // If we didn't actually save space, mark as skipped
        if (result.compressedBytes >= result.originalBytes * 0.98) {
            result.status          = CompressionResult.STATUS_SKIPPED;
            result.compressedBytes = result.originalBytes;
        }
    }

    /** Strip author, company, manager, last-modified-by from Office core.xml. */
    private byte[] stripOfficeMetadata(byte[] xml) {
        String text = new String(xml, StandardCharsets.UTF_8);
        // Zero out metadata elements while preserving structure
        text = text.replaceAll("<dc:creator>[^<]*</dc:creator>",
                               "<dc:creator></dc:creator>");
        text = text.replaceAll("<cp:lastModifiedBy>[^<]*</cp:lastModifiedBy>",
                               "<cp:lastModifiedBy></cp:lastModifiedBy>");
        text = text.replaceAll("<cp:revision>[^<]*</cp:revision>",
                               "<cp:revision>1</cp:revision>");
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /* ── Helpers ─────────────────────────────────────────────────────── */

    private boolean shouldDrop(String name) {
        for (String d : DROP_ENTRIES) if (d.equals(name)) return true;
        // Drop Word revision tracking binary
        if (name.endsWith(".rels") && name.contains("revisionView")) return true;
        return false;
    }

    private byte[] readEntry(ZipInputStream zin, ZipEntry entry) throws IOException {
        long size = entry.getSize();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(
                size > 0 && size < MAX_ENTRY_BYTES ? (int) size : 4096);
        byte[] buf = new byte[8192];
        int n;
        int total = 0;
        while ((n = zin.read(buf)) != -1) {
            if (total + n > MAX_ENTRY_BYTES) break;  // safety cap
            bos.write(buf, 0, n);
            total += n;
        }
        return bos.toByteArray();
    }

    private byte[] readAll(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) f.length());
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private long crc32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private boolean isPdf(String mimeType) {
        return "application/pdf".equals(mimeType);
    }

    private boolean isOfficeZip(String mimeType, String fileName) {
        if (mimeType != null) {
            return mimeType.startsWith("application/vnd.openxmlformats")
                || mimeType.startsWith("application/vnd.oasis.opendocument")
                || "application/zip".equals(mimeType);
        }
        String n = fileName.toLowerCase();
        return n.endsWith(".docx") || n.endsWith(".xlsx") || n.endsWith(".pptx")
            || n.endsWith(".odt")  || n.endsWith(".ods")  || n.endsWith(".odp");
    }

    private int savingsPercent(long original, long compressed) {
        if (original == 0) return 0;
        return (int) ((original - compressed) * 100L / original);
    }
}
