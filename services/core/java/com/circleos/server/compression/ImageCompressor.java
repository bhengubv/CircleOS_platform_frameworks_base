/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.ExifInterface;
import android.util.Log;

import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionResult;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Image compressor — Phase 1.
 *
 * Format strategy:
 *   JPEG → recompress at tier-dependent quality; strip EXIF via ExifInterface
 *   PNG  → recompress as PNG (lossless); Bitmap encode strips metadata
 *   WebP → recompress as WEBP_LOSSY (API 30+) at tier quality
 *   GIF  → passthrough (no Android encoder for animated GIF; Phase 2: libgif)
 *
 * Quality per tier:
 *   TIER_LOSSLESS          → JPEG 95, WebP 95 (quasi-lossless)
 *   TIER_VISUALLY_LOSSLESS → JPEG 85, WebP 82 (spec default)
 *   TIER_AGGRESSIVE        → JPEG 65, WebP 60
 *
 * Skip threshold: if compressed ≥ 95% of original, return original unchanged.
 */
public class ImageCompressor {

    private static final String TAG = "CircleImageComp";

    private static final float SKIP_THRESHOLD = 0.95f;  // skip if < 5% savings

    public CompressionResult compress(File inputFile, File outputFile,
                                      String mimeType, int tier, boolean stripMeta) {
        CompressionResult result = new CompressionResult();
        result.originalBytes = inputFile.length();
        long start = System.currentTimeMillis();

        try {
            if (mimeType != null && mimeType.equals("image/gif")) {
                // GIF passthrough — animated GIF requires native encoder
                result.status         = CompressionResult.STATUS_SKIPPED;
                result.compressedBytes = result.originalBytes;
                result.method         = "gif-passthrough";
                return result;
            }

            BitmapFactory.Options opts = new BitmapFactory.Options();
            opts.inPreferredConfig = Bitmap.Config.ARGB_8888;
            Bitmap bmp = BitmapFactory.decodeFile(inputFile.getAbsolutePath(), opts);
            if (bmp == null) {
                result.status = CompressionResult.STATUS_ERROR;
                return result;
            }

            Bitmap.CompressFormat fmt;
            String method;
            int quality;

            if ("image/png".equals(mimeType)) {
                fmt    = Bitmap.CompressFormat.PNG;
                quality = 0;  // PNG is lossless; quality param ignored
                method  = "png-lossless";
            } else if ("image/webp".equals(mimeType)) {
                // WEBP_LOSSY available API 30+ (Android 14 = API 34 ✓)
                fmt     = Bitmap.CompressFormat.WEBP_LOSSY;
                quality = qualityFor(tier, 95, 82, 60);
                method  = "webp" + quality;
            } else {
                // Default: JPEG (also handles unknown image/* types)
                fmt     = Bitmap.CompressFormat.JPEG;
                quality = qualityFor(tier, 95, 85, 65);
                method  = "jpeg" + quality;
            }

            // Compress to byte array first to check savings
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bmp.compress(fmt, quality, bos);
            bmp.recycle();
            byte[] compressed = bos.toByteArray();

            if (compressed.length >= result.originalBytes * SKIP_THRESHOLD) {
                result.status         = CompressionResult.STATUS_SKIPPED;
                result.compressedBytes = result.originalBytes;
                result.method         = method + "-skipped";
                Log.d(TAG, "Skip " + inputFile.getName() + " — savings < 5%");
                return result;
            }

            // Write compressed bytes
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(compressed);
            }

            // Strip metadata from JPEG output via ExifInterface
            if (stripMeta && fmt == Bitmap.CompressFormat.JPEG) {
                stripExif(outputFile);
                result.metadataStripped = true;
            }

            result.status          = CompressionResult.STATUS_OK;
            result.compressedBytes = outputFile.length();
            result.method          = method;

        } catch (Exception e) {
            Log.e(TAG, "Image compression failed: " + inputFile.getName(), e);
            result.status = CompressionResult.STATUS_ERROR;
        } finally {
            result.savingsPercent = savingsPercent(result.originalBytes, result.compressedBytes);
            result.processingMs   = System.currentTimeMillis() - start;
        }
        return result;
    }

    private void stripExif(File jpegFile) throws IOException {
        ExifInterface exif = new ExifInterface(jpegFile.getAbsolutePath());
        // Zero out privacy-sensitive tags
        exif.setAttribute(ExifInterface.TAG_GPS_LATITUDE,        null);
        exif.setAttribute(ExifInterface.TAG_GPS_LONGITUDE,       null);
        exif.setAttribute(ExifInterface.TAG_GPS_ALTITUDE,        null);
        exif.setAttribute(ExifInterface.TAG_GPS_TIMESTAMP,       null);
        exif.setAttribute(ExifInterface.TAG_GPS_DATESTAMP,       null);
        exif.setAttribute(ExifInterface.TAG_MAKE,                null);
        exif.setAttribute(ExifInterface.TAG_MODEL,               null);
        exif.setAttribute(ExifInterface.TAG_SOFTWARE,            null);
        exif.setAttribute(ExifInterface.TAG_ARTIST,              null);
        exif.setAttribute(ExifInterface.TAG_IMAGE_DESCRIPTION,   null);
        exif.setAttribute(ExifInterface.TAG_COPYRIGHT,           null);
        exif.setAttribute(ExifInterface.TAG_DATETIME,            null);
        exif.setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL,   null);
        exif.setAttribute(ExifInterface.TAG_DATETIME_DIGITIZED,  null);
        exif.setAttribute(ExifInterface.TAG_USER_COMMENT,        null);
        exif.setAttribute(ExifInterface.TAG_CAMERA_OWNER_NAME,   null);
        exif.setAttribute(ExifInterface.TAG_BODY_SERIAL_NUMBER,  null);
        exif.setAttribute(ExifInterface.TAG_LENS_SERIAL_NUMBER,  null);
        exif.saveAttributes();
        Log.d(TAG, "EXIF stripped: " + jpegFile.getName());
    }

    private int qualityFor(int tier, int lossless, int visual, int aggressive) {
        switch (tier) {
            case CompressionRequest.TIER_LOSSLESS:          return lossless;
            case CompressionRequest.TIER_AGGRESSIVE:        return aggressive;
            default: /* TIER_VISUALLY_LOSSLESS */           return visual;
        }
    }

    private int savingsPercent(long original, long compressed) {
        if (original == 0) return 0;
        return (int) ((original - compressed) * 100L / original);
    }
}
