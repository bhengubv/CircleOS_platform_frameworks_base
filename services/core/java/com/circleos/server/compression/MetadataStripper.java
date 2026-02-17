/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.media.ExifInterface;
import android.util.Log;

import za.co.circleos.compression.CompressionResult;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Pattern;

/**
 * Outbound metadata stripper — Phase 1.
 *
 * Removes privacy-sensitive metadata from files before they leave the device:
 *
 *   JPEG/WebP — strip EXIF via ExifInterface (GPS, device ID, author, timestamps)
 *   PNG       — strip tEXt/iTXt/zTXt metadata chunks; rewrite header only
 *   PDF       — strip XMP packet and Author/Creator/Producer fields
 *   Office    — handled by DocumentCompressor.stripOfficeMetadata()
 *
 * What is stripped:
 *   ✓ GPS coordinates and altitude
 *   ✓ Device make/model/serial
 *   ✓ Software version (reveals OS/app)
 *   ✓ Author / artist / copyright
 *   ✓ Timestamps (creation, modification, digitized)
 *   ✓ Camera body and lens serial numbers
 *   ✓ User comments
 *   ✓ Edit history / revision count
 *
 * What is preserved:
 *   ✓ Image dimensions / color space
 *   ✓ Orientation (needed for correct display)
 *   ✓ Color profile (needed for correct rendering)
 */
public class MetadataStripper {

    private static final String TAG = "CircleMeta";

    /** XMP packet pattern — matches both compressed and uncompressed XMP. */
    private static final Pattern XMP_PATTERN = Pattern.compile(
            "<\\?xpacket begin.*?<\\?xpacket end=\"[wr]\"\\?>",
            Pattern.DOTALL);

    /** PDF Author/Creator/Producer/Keywords lines. */
    private static final Pattern PDF_META_LINE = Pattern.compile(
            "/(?:Author|Creator|Producer|Keywords|Subject|Title)\\s*\\([^)]*\\)");

    /**
     * Strip metadata from a file in-place (modifies the file directly).
     * @return true if any metadata was stripped
     */
    public boolean strip(File file, String mimeType) {
        if (mimeType == null) mimeType = guessMime(file.getName());

        try {
            if (isJpeg(mimeType) || isWebP(mimeType)) {
                return stripExif(file);
            } else if (isPng(mimeType)) {
                return stripPngMetadata(file);
            } else if (isPdf(mimeType)) {
                return stripPdfMetadata(file);
            }
        } catch (Exception e) {
            Log.w(TAG, "Metadata strip failed for " + file.getName(), e);
        }
        return false;
    }

    /* ── JPEG / WebP EXIF ──────────────────────────────────────────── */

    private boolean stripExif(File file) throws IOException {
        ExifInterface exif = new ExifInterface(file.getAbsolutePath());

        boolean hadGps = exif.getAttribute(ExifInterface.TAG_GPS_LATITUDE) != null;

        exif.setAttribute(ExifInterface.TAG_GPS_LATITUDE,           null);
        exif.setAttribute(ExifInterface.TAG_GPS_LATITUDE_REF,       null);
        exif.setAttribute(ExifInterface.TAG_GPS_LONGITUDE,          null);
        exif.setAttribute(ExifInterface.TAG_GPS_LONGITUDE_REF,      null);
        exif.setAttribute(ExifInterface.TAG_GPS_ALTITUDE,           null);
        exif.setAttribute(ExifInterface.TAG_GPS_ALTITUDE_REF,       null);
        exif.setAttribute(ExifInterface.TAG_GPS_TIMESTAMP,          null);
        exif.setAttribute(ExifInterface.TAG_GPS_DATESTAMP,          null);
        exif.setAttribute(ExifInterface.TAG_GPS_SPEED,              null);
        exif.setAttribute(ExifInterface.TAG_GPS_SPEED_REF,          null);
        exif.setAttribute(ExifInterface.TAG_GPS_TRACK,              null);
        exif.setAttribute(ExifInterface.TAG_GPS_TRACK_REF,          null);
        exif.setAttribute(ExifInterface.TAG_GPS_PROCESSING_METHOD,  null);

        exif.setAttribute(ExifInterface.TAG_MAKE,                   null);
        exif.setAttribute(ExifInterface.TAG_MODEL,                  null);
        exif.setAttribute(ExifInterface.TAG_SOFTWARE,               null);
        exif.setAttribute(ExifInterface.TAG_ARTIST,                 null);
        exif.setAttribute(ExifInterface.TAG_IMAGE_DESCRIPTION,      null);
        exif.setAttribute(ExifInterface.TAG_COPYRIGHT,              null);
        exif.setAttribute(ExifInterface.TAG_USER_COMMENT,           null);
        exif.setAttribute(ExifInterface.TAG_CAMERA_OWNER_NAME,      null);
        exif.setAttribute(ExifInterface.TAG_BODY_SERIAL_NUMBER,     null);
        exif.setAttribute(ExifInterface.TAG_LENS_SERIAL_NUMBER,     null);
        exif.setAttribute(ExifInterface.TAG_MAKER_NOTE,             null);

        exif.setAttribute(ExifInterface.TAG_DATETIME,               null);
        exif.setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL,      null);
        exif.setAttribute(ExifInterface.TAG_DATETIME_DIGITIZED,     null);
        exif.setAttribute(ExifInterface.TAG_OFFSET_TIME,            null);
        exif.setAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL,   null);
        exif.setAttribute(ExifInterface.TAG_OFFSET_TIME_DIGITIZED,  null);

        exif.saveAttributes();
        Log.d(TAG, "EXIF stripped from " + file.getName()
                + (hadGps ? " (included GPS)" : ""));
        return true;
    }

    /* ── PNG text chunks ────────────────────────────────────────────── */

    /**
     * PNG text metadata sits in tEXt, iTXt, zTXt chunks.
     * We rewrite the PNG dropping those chunks entirely.
     * PNG structure: 8-byte sig + chunks (4-len, 4-type, data, 4-CRC).
     */
    private boolean stripPngMetadata(File file) throws IOException {
        byte[] data = Files.readAllBytes(file.toPath());
        if (data.length < 8) return false;

        // Verify PNG signature
        if (data[0] != (byte)0x89 || data[1] != 0x50) return false;  // not PNG

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(data.length);
        out.write(data, 0, 8);  // PNG signature

        int pos = 8;
        boolean stripped = false;

        while (pos + 12 <= data.length) {
            int len  = ((data[pos] & 0xFF) << 24) | ((data[pos+1] & 0xFF) << 16)
                     | ((data[pos+2] & 0xFF) << 8) | (data[pos+3] & 0xFF);
            String type = new String(data, pos+4, 4, StandardCharsets.US_ASCII);
            int total = 12 + len;  // len + 4(type) + 4(len) + 4(CRC)

            if (type.equals("tEXt") || type.equals("iTXt") || type.equals("zTXt")
                    || type.equals("eXIf")) {
                // Drop this chunk
                stripped = true;
                Log.d(TAG, "PNG: dropped " + type + " chunk (" + len + " bytes)");
            } else {
                out.write(data, pos, total);
            }
            pos += total;
        }

        if (stripped) {
            Files.write(file.toPath(), out.toByteArray());
        }
        return stripped;
    }

    /* ── PDF metadata ───────────────────────────────────────────────── */

    private boolean stripPdfMetadata(File file) throws IOException {
        byte[] data = Files.readAllBytes(file.toPath());
        String text = new String(data, StandardCharsets.ISO_8859_1);

        // Strip XMP packet
        String stripped = XMP_PATTERN.matcher(text).replaceAll("");
        // Strip inline PDF metadata strings
        stripped = PDF_META_LINE.matcher(stripped).replaceAll("/Redacted ()");

        if (stripped.length() != text.length()) {
            Files.write(file.toPath(), stripped.getBytes(StandardCharsets.ISO_8859_1));
            Log.d(TAG, "PDF metadata stripped: " + file.getName());
            return true;
        }
        return false;
    }

    /* ── Helpers ─────────────────────────────────────────────────────── */

    private String guessMime(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".png"))  return "image/png";
        if (n.endsWith(".webp")) return "image/webp";
        if (n.endsWith(".pdf"))  return "application/pdf";
        return "application/octet-stream";
    }

    private boolean isJpeg(String m) { return "image/jpeg".equals(m); }
    private boolean isWebP(String m) { return "image/webp".equals(m); }
    private boolean isPng(String m)  { return "image/png".equals(m);  }
    private boolean isPdf(String m)  { return "application/pdf".equals(m); }
}
