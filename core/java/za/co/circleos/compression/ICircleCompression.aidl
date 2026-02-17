/*
 * Copyright (C) 2024 CircleOS
 * SPDX-License-Identifier: Apache-2.0
 */
package za.co.circleos.compression;

import android.os.ParcelFileDescriptor;
import za.co.circleos.compression.CompressionRequest;
import za.co.circleos.compression.CompressionResult;
import za.co.circleos.compression.CompressionStats;
import za.co.circleos.compression.ICompressionCallback;

/**
 * Circle Compression Service binder interface.
 *
 * Callers submit a file (via PFD) with a CompressionRequest and receive a
 * sessionId for async polling. Compressed output is retrieved via
 * getCompressedFile(). Sessions must be released when done.
 *
 * Requires: com.circleos.permission.ACCESS_COMPRESSION (normal)
 *
 * Integrated into the DMZ pipeline — apps do not typically call this directly;
 * they receive already-compressed+clean files from CircleFileDmzService.
 */
interface ICircleCompression {

    /**
     * Submit a file for compression. Returns a session ID for polling.
     * Processing is asynchronous on the compression worker thread.
     */
    String compress(in ParcelFileDescriptor fileFd, in CompressionRequest request);

    /**
     * Poll for the result of a compression session.
     * Returns null while in progress; CompressionResult when complete.
     */
    CompressionResult getResult(String sessionId);

    /**
     * Retrieve the compressed file. Returns null if not ready or if
     * STATUS_SKIPPED (file was already optimal — original is unchanged).
     */
    ParcelFileDescriptor getCompressedFile(String sessionId);

    /** Release session resources. Must be called after file is consumed. */
    void releaseSession(String sessionId);

    /** Get cumulative compression statistics for the current month. */
    CompressionStats getMonthlyStats();

    /** Reset monthly statistics (e.g. on month rollover). */
    void resetMonthlyStats();

    /** Returns current service version. */
    int getServiceVersion();
}
