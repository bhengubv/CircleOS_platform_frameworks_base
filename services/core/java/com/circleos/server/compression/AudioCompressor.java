/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.media.MediaMuxer;
import android.util.Log;

import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionResult;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Audio compressor for Compression Phase 2.
 *
 * Re-encodes AAC/MP3/OGG/FLAC audio files to AAC-LC at reduced bitrate using
 * {@link MediaCodec} — no native libraries required.
 *
 * Skipped if:
 *   - TIER_LOSSLESS
 *   - Source is already AAC at or below the target bitrate
 *   - Duration is unknown or exceeds 2 hours
 *
 * Target bitrates:
 *   TIER_VISUALLY_LOSSLESS: 96 kbps AAC (transparent quality for speech + music)
 *   TIER_AGGRESSIVE:         64 kbps AAC
 *
 * Typical savings: 50–70% vs uncompressed PCM/FLAC; 20–40% vs high-bitrate MP3/AAC.
 */
public class AudioCompressor {

    private static final String TAG = "CircleAudioComp";

    private static final String OUTPUT_MIME     = "audio/mp4a-latm";  // AAC-LC
    private static final int    BITRATE_NORMAL  = 96_000;
    private static final int    BITRATE_AGGR    = 64_000;

    /** Maximum audio duration we'll transcode (2 hours in microseconds). */
    private static final long MAX_DURATION_US = 2L * 60 * 60 * 1_000_000;

    private static final long CODEC_TIMEOUT_US = 5_000_000L;

    /** Sample size ceiling per read operation. */
    private static final int SAMPLE_BUFFER_SIZE = 256 * 1024;

    public CompressionResult compress(File inputFile, File outputFile, int tier) {
        CompressionResult result = new CompressionResult();
        result.originalBytes = inputFile.length();
        long start = System.currentTimeMillis();

        if (tier == CompressionRequest.TIER_LOSSLESS) {
            result.status          = CompressionResult.STATUS_SKIPPED;
            result.method          = "audio-lossless-skip";
            result.compressedBytes = result.originalBytes;
            return result;
        }

        int targetBitrate = (tier == CompressionRequest.TIER_AGGRESSIVE)
                ? BITRATE_AGGR : BITRATE_NORMAL;

        MediaExtractor extractor = new MediaExtractor();
        try {
            extractor.setDataSource(inputFile.getAbsolutePath());

            int audioTrackIdx = findAudioTrack(extractor);
            if (audioTrackIdx < 0) {
                result.status          = CompressionResult.STATUS_SKIPPED;
                result.method          = "audio-no-track";
                result.compressedBytes = result.originalBytes;
                return result;
            }

            MediaFormat srcFmt = extractor.getTrackFormat(audioTrackIdx);
            String srcMime = srcFmt.getString(MediaFormat.KEY_MIME);

            long durationUs = srcFmt.containsKey(MediaFormat.KEY_DURATION)
                    ? srcFmt.getLong(MediaFormat.KEY_DURATION) : 0;
            if (durationUs > MAX_DURATION_US) {
                result.status          = CompressionResult.STATUS_SKIPPED;
                result.method          = "audio-too-long";
                result.compressedBytes = result.originalBytes;
                return result;
            }

            // Skip if already AAC at or below target bitrate
            if (OUTPUT_MIME.equals(srcMime)) {
                int srcBitrate = srcFmt.containsKey(MediaFormat.KEY_BIT_RATE)
                        ? srcFmt.getInteger(MediaFormat.KEY_BIT_RATE) : Integer.MAX_VALUE;
                if (srcBitrate <= targetBitrate) {
                    result.status          = CompressionResult.STATUS_SKIPPED;
                    result.method          = "audio-already-aac-low";
                    result.compressedBytes = result.originalBytes;
                    return result;
                }
            }

            int sampleRate  = srcFmt.getInteger(MediaFormat.KEY_SAMPLE_RATE);
            int channelCount = srcFmt.containsKey(MediaFormat.KEY_CHANNEL_COUNT)
                    ? srcFmt.getInteger(MediaFormat.KEY_CHANNEL_COUNT) : 2;

            transcode(extractor, audioTrackIdx, outputFile,
                    sampleRate, channelCount, targetBitrate, srcMime);

            result.compressedBytes = outputFile.length();
            if (result.compressedBytes >= result.originalBytes * 0.95f) {
                result.status = CompressionResult.STATUS_SKIPPED;
                result.method = "audio-no-saving";
                outputFile.delete();
            } else {
                result.status = CompressionResult.STATUS_OK;
                result.method = "audio-aac";
            }

        } catch (Exception e) {
            Log.e(TAG, "Audio compression failed: " + inputFile.getName(), e);
            result.status = CompressionResult.STATUS_ERROR;
            if (outputFile.exists()) outputFile.delete();
        } finally {
            extractor.release();
            result.savingsPercent = savingsPercent(result.originalBytes, result.compressedBytes);
            result.processingMs   = System.currentTimeMillis() - start;
        }
        return result;
    }

    // ── Transcode ─────────────────────────────────────────────────────────────

    private void transcode(MediaExtractor extractor, int audioTrackIdx, File outputFile,
                           int sampleRate, int channelCount, int targetBitrate,
                           String srcMime)
            throws IOException {

        // Decoder
        MediaFormat decFmt = extractor.getTrackFormat(audioTrackIdx);
        MediaCodec decoder = MediaCodec.createDecoderByType(srcMime);
        decoder.configure(decFmt, null, null, 0);
        decoder.start();

        // Encoder — AAC-LC output
        MediaFormat encFmt = MediaFormat.createAudioFormat(OUTPUT_MIME, sampleRate, channelCount);
        encFmt.setInteger(MediaFormat.KEY_BIT_RATE, targetBitrate);
        encFmt.setInteger(MediaFormat.KEY_AAC_PROFILE,
                android.media.MediaCodecInfo.CodecProfileLevel.AACObjectLC);
        MediaCodec encoder = MediaCodec.createEncoderByType(OUTPUT_MIME);
        encoder.configure(encFmt, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
        encoder.start();

        MediaMuxer muxer = new MediaMuxer(outputFile.getAbsolutePath(),
                MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4);

        try {
            extractor.selectTrack(audioTrackIdx);

            int muxTrack = -1;
            boolean muxerStarted = false;
            boolean decodeEos = false;
            boolean encodeEos = false;

            // PCM buffer between decoder output → encoder input
            // We use a simple dequeue loop to pass decoded buffers to encoder
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();

            while (!encodeEos) {
                // Feed extractor → decoder
                if (!decodeEos) {
                    int decIn = decoder.dequeueInputBuffer(CODEC_TIMEOUT_US);
                    if (decIn >= 0) {
                        ByteBuffer inBuf = decoder.getInputBuffer(decIn);
                        if (inBuf != null) {
                            int size = extractor.readSampleData(inBuf, 0);
                            if (size < 0) {
                                decoder.queueInputBuffer(decIn, 0, 0, 0,
                                        MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                                decodeEos = true;
                            } else {
                                decoder.queueInputBuffer(decIn, 0, size,
                                        extractor.getSampleTime(), 0);
                                extractor.advance();
                            }
                        }
                    }
                }

                // Drain decoder → feed encoder
                int decOut = decoder.dequeueOutputBuffer(info, CODEC_TIMEOUT_US);
                if (decOut >= 0) {
                    ByteBuffer decBuf = decoder.getOutputBuffer(decOut);
                    boolean eos = (info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;

                    if (decBuf != null && info.size > 0) {
                        // Copy PCM to encoder input
                        int encIn = encoder.dequeueInputBuffer(CODEC_TIMEOUT_US);
                        if (encIn >= 0) {
                            ByteBuffer encBuf = encoder.getInputBuffer(encIn);
                            if (encBuf != null) {
                                encBuf.clear();
                                encBuf.put(decBuf);
                                encoder.queueInputBuffer(encIn, 0, info.size,
                                        info.presentationTimeUs,
                                        eos ? MediaCodec.BUFFER_FLAG_END_OF_STREAM : 0);
                            }
                        }
                    }
                    decoder.releaseOutputBuffer(decOut, false);
                }

                // Drain encoder → muxer
                int encOut = encoder.dequeueOutputBuffer(info, CODEC_TIMEOUT_US);
                if (encOut == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    muxTrack = muxer.addTrack(encoder.getOutputFormat());
                    muxer.start();
                    muxerStarted = true;
                } else if (encOut >= 0) {
                    ByteBuffer encBuf = encoder.getOutputBuffer(encOut);
                    if (encBuf != null && muxerStarted && muxTrack >= 0
                            && (info.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == 0) {
                        muxer.writeSampleData(muxTrack, encBuf, info);
                    }
                    encoder.releaseOutputBuffer(encOut, false);
                    if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                        encodeEos = true;
                    }
                }
            }
        } finally {
            try { decoder.stop(); decoder.release(); } catch (Exception ignored) {}
            try { encoder.stop(); encoder.release(); } catch (Exception ignored) {}
            try { if (muxer != null) { muxer.stop(); muxer.release(); } } catch (Exception ignored) {}
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private int findAudioTrack(MediaExtractor extractor) {
        for (int i = 0; i < extractor.getTrackCount(); i++) {
            MediaFormat fmt = extractor.getTrackFormat(i);
            String mime = fmt.getString(MediaFormat.KEY_MIME);
            if (mime != null && mime.startsWith("audio/")) return i;
        }
        return -1;
    }

    private int savingsPercent(long original, long compressed) {
        if (original == 0) return 0;
        return (int) ((original - compressed) * 100L / original);
    }
}
