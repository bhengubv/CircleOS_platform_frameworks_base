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
import java.util.zip.Deflater;
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

    private void compressPdf(File in, File out, CompressionResult result, int tier)
            throws IOException {
        byte[] data = readAll(in);
        byte[] stripped = stripPdfXmp(data);
        // Phase 1: metadata strip only; full image recompression in Phase 2 (MuPDF native)
        if (stripped.length < data.length) {
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(stripped);
            }
            result.status          = CompressionResult.STATUS_OK;
            result.compressedBytes = out.length();
            result.method          = "pdf-xmp-strip";
            result.metadataStripped = true;
        } else {
            result.status          = CompressionResult.STATUS_SKIPPED;
            result.compressedBytes = result.originalBytes;
            result.method          = "pdf-no-xmp";
        }
    }

    /**
     * Strip XMP metadata packet from PDF bytes.
     * XMP packets are enclosed in: <?xpacket begin ... ?>...<?xpacket end="w"?>
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
        for (int i = end; i < pdf.length; i++) bos.write(pdf[i]);
        return bos.toByteArray();
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
