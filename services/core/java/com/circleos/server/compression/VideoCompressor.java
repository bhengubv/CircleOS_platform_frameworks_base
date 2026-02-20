/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.compression;

import android.media.MediaCodec;
import android.media.MediaCodecInfo;
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
 * Video transcoder for Compression Phase 2.
 *
 * Re-encodes MP4/WebM/MKV video streams to H.265/HEVC at a reduced bitrate.
 * Audio tracks are copied without re-encoding to avoid compounding quality loss.
 *
 * Skipped if:
 *   - TIER_LOSSLESS (no lossy transforms allowed)
 *   - Source codec is already HEVC and measured bitrate is at or below target
 *   - Source duration is zero or unreadable
 *
 * Target bitrates:
 *   TIER_VISUALLY_LOSSLESS: 2 Mbps video (imperceptible loss at ≤1080p)
 *   TIER_AGGRESSIVE:         1 Mbps video
 *
 * Typical savings: 40–60% vs H.264 sources; 20–30% vs HEVC sources at high bitrate.
 */
public class VideoCompressor {

    private static final String TAG = "CircleVideoComp";

    /** Target video bitrate for TIER_VISUALLY_LOSSLESS (2 Mbit/s). */
    private static final int BITRATE_NORMAL = 2_000_000;
    /** Target video bitrate for TIER_AGGRESSIVE (1 Mbit/s). */
    private static final int BITRATE_AGGRESSIVE = 1_000_000;

    /** Codec used for output. HEVC is hardware-accelerated on all modern SoCs. */
    private static final String OUTPUT_CODEC = "video/hevc";

    /** Maximum video duration to transcode (10 minutes). Longer files are skipped. */
    private static final long MAX_DURATION_US = 10L * 60 * 1_000_000;

    /** Timeout for codec operations (5 s). */
    private static final long CODEC_TIMEOUT_US = 5_000_000L;

    public CompressionResult compress(File inputFile, File outputFile, int tier) {
        CompressionResult result = new CompressionResult();
        result.originalBytes = inputFile.length();
        long start = System.currentTimeMillis();

        if (tier == CompressionRequest.TIER_LOSSLESS) {
            result.status = CompressionResult.STATUS_SKIPPED;
            result.method = "video-lossless-skip";
            result.compressedBytes = result.originalBytes;
            return result;
        }

        int targetBitrate = (tier == CompressionRequest.TIER_AGGRESSIVE)
                ? BITRATE_AGGRESSIVE : BITRATE_NORMAL;

        MediaExtractor extractor = new MediaExtractor();
        try {
            extractor.setDataSource(inputFile.getAbsolutePath());

            int videoTrackIdx = findTrack(extractor, "video/");
            int audioTrackIdx = findTrack(extractor, "audio/");

            if (videoTrackIdx < 0) {
                result.status          = CompressionResult.STATUS_SKIPPED;
                result.method          = "video-no-track";
                result.compressedBytes = result.originalBytes;
                return result;
            }

            MediaFormat videoFormat = extractor.getTrackFormat(videoTrackIdx);
            long durationUs = videoFormat.containsKey(MediaFormat.KEY_DURATION)
                    ? videoFormat.getLong(MediaFormat.KEY_DURATION) : 0;

            if (durationUs > MAX_DURATION_US || durationUs <= 0) {
                result.status          = CompressionResult.STATUS_SKIPPED;
                result.method          = "video-too-long-or-unknown";
                result.compressedBytes = result.originalBytes;
                return result;
            }

            // Skip if already HEVC and bitrate is at/below target
            String srcMime = videoFormat.getString(MediaFormat.KEY_MIME);
            if (OUTPUT_CODEC.equals(srcMime)) {
                int srcBitrate = videoFormat.containsKey(MediaFormat.KEY_BIT_RATE)
                        ? videoFormat.getInteger(MediaFormat.KEY_BIT_RATE) : Integer.MAX_VALUE;
                if (srcBitrate <= targetBitrate) {
                    result.status          = CompressionResult.STATUS_SKIPPED;
                    result.method          = "video-already-hevc-low";
                    result.compressedBytes = result.originalBytes;
                    return result;
                }
            }

            int width  = videoFormat.getInteger(MediaFormat.KEY_WIDTH);
            int height = videoFormat.getInteger(MediaFormat.KEY_HEIGHT);
            int frameRate = videoFormat.containsKey(MediaFormat.KEY_FRAME_RATE)
                    ? videoFormat.getInteger(MediaFormat.KEY_FRAME_RATE) : 30;

            transcode(extractor, inputFile, outputFile,
                    videoTrackIdx, audioTrackIdx,
                    width, height, frameRate, targetBitrate);

            result.compressedBytes = outputFile.length();
            if (result.compressedBytes >= result.originalBytes * 0.95f) {
                result.status = CompressionResult.STATUS_SKIPPED;
                result.method = "video-no-saving";
                outputFile.delete();
            } else {
                result.status = CompressionResult.STATUS_OK;
                result.method = "video-hevc";
            }

        } catch (Exception e) {
            Log.e(TAG, "Video compression failed: " + inputFile.getName(), e);
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

    private void transcode(MediaExtractor extractor, File inputFile, File outputFile,
                           int videoTrackIdx, int audioTrackIdx,
                           int width, int height, int frameRate, int targetBitrate)
            throws IOException {

        // Encoder output format
        MediaFormat encFormat = MediaFormat.createVideoFormat(OUTPUT_CODEC, width, height);
        encFormat.setInteger(MediaFormat.KEY_BIT_RATE,        targetBitrate);
        encFormat.setInteger(MediaFormat.KEY_FRAME_RATE,      frameRate);
        encFormat.setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 2);
        encFormat.setInteger(MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible);

        // Decoder
        MediaFormat decFormat = extractor.getTrackFormat(videoTrackIdx);
        String srcMime = decFormat.getString(MediaFormat.KEY_MIME);

        MediaCodec decoder = MediaCodec.createDecoderByType(srcMime);
        MediaCodec encoder = MediaCodec.createEncoderByType(OUTPUT_CODEC);

        MediaMuxer muxer = new MediaMuxer(outputFile.getAbsolutePath(),
                MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4);

        try {
            encoder.configure(encFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
            decoder.configure(decFormat, encoder.createInputSurface(), null, 0);

            encoder.start();
            decoder.start();

            // Pass-through audio track
            int muxAudioTrack = -1;
            if (audioTrackIdx >= 0) {
                MediaFormat audioFmt = extractor.getTrackFormat(audioTrackIdx);
                muxAudioTrack = muxer.addTrack(audioFmt);
            }

            // Add video track index (filled once encoder sends CSD)
            int muxVideoTrack = -1;
            boolean muxerStarted = false;

            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            boolean decoderDone = false;
            boolean encoderDone = false;

            extractor.selectTrack(videoTrackIdx);
            if (audioTrackIdx >= 0) extractor.selectTrack(audioTrackIdx);

            while (!encoderDone) {
                // Feed decoder
                if (!decoderDone) {
                    int inIdx = decoder.dequeueInputBuffer(CODEC_TIMEOUT_US);
                    if (inIdx >= 0) {
                        ByteBuffer inBuf = decoder.getInputBuffer(inIdx);
                        if (inBuf != null) {
                            int sampleSize = extractor.readSampleData(inBuf, 0);
                            if (sampleSize < 0) {
                                decoder.queueInputBuffer(inIdx, 0, 0, 0,
                                        MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                                decoderDone = true;
                            } else {
                                long pts = extractor.getSampleTime();
                                decoder.queueInputBuffer(inIdx, 0, sampleSize, pts, 0);
                                extractor.advance();
                            }
                        }
                    }
                }

                // Poll encoder output
                int outIdx = encoder.dequeueOutputBuffer(info, CODEC_TIMEOUT_US);
                if (outIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    muxVideoTrack = muxer.addTrack(encoder.getOutputFormat());
                    if (muxAudioTrack >= 0 || muxVideoTrack >= 0) {
                        muxer.start();
                        muxerStarted = true;
                    }
                } else if (outIdx >= 0) {
                    if (!muxerStarted) {
                        // Start muxer if it wasn't started yet (no audio track)
                        muxer.start();
                        muxerStarted = true;
                    }
                    ByteBuffer outBuf = encoder.getOutputBuffer(outIdx);
                    if (outBuf != null && muxVideoTrack >= 0
                            && (info.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == 0) {
                        muxer.writeSampleData(muxVideoTrack, outBuf, info);
                    }
                    encoder.releaseOutputBuffer(outIdx, false);
                    if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                        encoderDone = true;
                    }
                }
            }

            // Write audio passthrough
            if (audioTrackIdx >= 0 && muxerStarted) {
                writeAudioPassthrough(inputFile, muxer, muxAudioTrack, audioTrackIdx);
            }

        } finally {
            try { decoder.stop(); decoder.release(); } catch (Exception ignored) {}
            try { encoder.stop(); encoder.release(); } catch (Exception ignored) {}
            try { muxer.stop();  muxer.release();  } catch (Exception ignored) {}
        }
    }

    /** Re-mux the audio track from the source file without re-encoding. */
    private void writeAudioPassthrough(File inputFile, MediaMuxer muxer,
                                       int muxAudioTrack, int audioTrackIdx)
            throws IOException {
        MediaExtractor audioExtractor = new MediaExtractor();
        try {
            audioExtractor.setDataSource(inputFile.getAbsolutePath());
            audioExtractor.selectTrack(audioTrackIdx);
            ByteBuffer buf = ByteBuffer.allocate(1024 * 1024);
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            while (true) {
                int size = audioExtractor.readSampleData(buf, 0);
                if (size < 0) break;
                info.offset = 0;
                info.size = size;
                info.presentationTimeUs = audioExtractor.getSampleTime();
                info.flags = audioExtractor.getSampleFlags();
                muxer.writeSampleData(muxAudioTrack, buf, info);
                audioExtractor.advance();
            }
        } finally {
            audioExtractor.release();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private int findTrack(MediaExtractor extractor, String mimePrefix) {
        for (int i = 0; i < extractor.getTrackCount(); i++) {
            MediaFormat fmt = extractor.getTrackFormat(i);
            String mime = fmt.getString(MediaFormat.KEY_MIME);
            if (mime != null && mime.startsWith(mimePrefix)) return i;
        }
        return -1;
    }

    private int savingsPercent(long original, long compressed) {
        if (original == 0) return 0;
        return (int) ((original - compressed) * 100L / original);
    }
}
