/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

import android.app.DownloadManager;
import android.content.Context;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.IOException;

/**
 * Downloads an OTA update package using {@link DownloadManager}, restricted to WiFi only.
 *
 * Downloads are stored in /data/system/circleos_update/ and named
 * circleos_update_{version}.zip. Any existing files in that directory are removed
 * before the new download begins.
 */
public class UpdateDownloader {

    private static final String TAG = "CircleUpdateDownloader";

    private static final String UPDATE_DIR  = "/data/system/circleos_update";
    private static final long   POLL_INTERVAL_MS = 1_000L;

    /** Callback to receive download progress updates (0–100). */
    public interface ProgressCallback {
        void onProgress(int percent);
    }

    private final Context mContext;

    public UpdateDownloader(Context context) {
        mContext = context;
    }

    /**
     * Downloads the OTA package from {@code url} for the given {@code version}.
     * Blocks the calling thread until the download completes or fails.
     *
     * @param url      The HTTPS URL of the OTA zip to download.
     * @param version  The version string used to name the local file.
     * @param callback Progress callback, invoked on the calling thread approximately once per second.
     * @return The downloaded {@link File} on success.
     * @throws IOException if WiFi is unavailable, the download fails, or the file is not found.
     */
    public File download(String url, String version, ProgressCallback callback)
            throws IOException {

        if (!isWifiConnected()) {
            throw new IOException("WiFi not available — refusing to download update");
        }

        // Prepare target directory
        File updateDir = new File(UPDATE_DIR);
        if (!updateDir.exists() && !updateDir.mkdirs()) {
            throw new IOException("Failed to create update directory: " + UPDATE_DIR);
        }

        // Clean up any previous downloads
        cleanOldDownloads(updateDir);

        String filename = "circleos_update_" + sanitizeVersion(version) + ".zip";
        File destFile = new File(updateDir, filename);

        Log.i(TAG, "Starting download of " + url + " -> " + destFile.getAbsolutePath());

        DownloadManager dm = (DownloadManager) mContext.getSystemService(Context.DOWNLOAD_SERVICE);
        if (dm == null) {
            throw new IOException("DownloadManager not available");
        }

        DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
        request.setAllowedNetworkTypes(DownloadManager.Request.NETWORK_WIFI);
        request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_HIDDEN);
        request.setDestinationUri(Uri.fromFile(destFile));
        request.setTitle("CircleOS Update");
        request.setDescription("Downloading " + version);
        request.setRequiresCharging(false);

        long downloadId = dm.enqueue(request);
        Log.d(TAG, "Enqueued download ID: " + downloadId);

        // Poll until complete or failed
        return pollDownload(dm, downloadId, destFile, callback);
    }

    private File pollDownload(DownloadManager dm, long downloadId, File destFile,
            ProgressCallback callback) throws IOException {

        DownloadManager.Query query = new DownloadManager.Query();
        query.setFilterById(downloadId);

        while (true) {
            Cursor cursor = dm.query(query);
            if (cursor == null) {
                throw new IOException("DownloadManager query returned null cursor");
            }

            try {
                if (!cursor.moveToFirst()) {
                    throw new IOException("Download ID " + downloadId + " not found in DownloadManager");
                }

                int statusCol    = cursor.getColumnIndex(DownloadManager.COLUMN_STATUS);
                int bytesCol     = cursor.getColumnIndex(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR);
                int totalCol     = cursor.getColumnIndex(DownloadManager.COLUMN_TOTAL_SIZE_BYTES);
                int reasonCol    = cursor.getColumnIndex(DownloadManager.COLUMN_REASON);

                int    status    = cursor.getInt(statusCol);
                long   received  = cursor.getLong(bytesCol);
                long   total     = cursor.getLong(totalCol);
                int    reason    = cursor.getInt(reasonCol);

                switch (status) {
                    case DownloadManager.STATUS_SUCCESSFUL:
                        Log.i(TAG, "Download complete: " + destFile.getAbsolutePath());
                        if (callback != null) callback.onProgress(100);
                        if (!destFile.exists()) {
                            throw new IOException("Downloaded file not found: " + destFile);
                        }
                        return destFile;

                    case DownloadManager.STATUS_FAILED:
                        dm.remove(downloadId);
                        throw new IOException("Download failed with reason code: " + reason);

                    case DownloadManager.STATUS_RUNNING:
                    case DownloadManager.STATUS_PENDING:
                    case DownloadManager.STATUS_PAUSED:
                        if (callback != null && total > 0) {
                            int percent = (int) ((received * 100L) / total);
                            callback.onProgress(percent);
                            Log.v(TAG, "Download progress: " + percent + "% ("
                                    + received + "/" + total + " bytes)");
                        }
                        break;

                    default:
                        Log.w(TAG, "Unexpected download status: " + status);
                        break;
                }
            } finally {
                cursor.close();
            }

            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                dm.remove(downloadId);
                throw new IOException("Download interrupted");
            }
        }
    }

    /** Removes all files from the update directory. */
    private void cleanOldDownloads(File dir) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isFile()) {
                boolean deleted = f.delete();
                Log.d(TAG, (deleted ? "Deleted" : "Failed to delete") + " old file: " + f.getName());
            }
        }
    }

    private boolean isWifiConnected() {
        ConnectivityManager cm = (ConnectivityManager)
                mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        Network activeNetwork = cm.getActiveNetwork();
        if (activeNetwork == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }

    /** Strips characters that are not safe for use in a filename. */
    private static String sanitizeVersion(String version) {
        if (version == null) return "unknown";
        return version.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
