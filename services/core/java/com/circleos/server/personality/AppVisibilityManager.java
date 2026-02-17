/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.content.Context;
import android.content.Intent;
import android.util.ArrayMap;
import android.util.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Manages per-mode app visibility rules.
 *
 * <p>When a mode is activated, broadcasts
 * {@code za.co.circleos.personality.APP_VISIBILITY_CHANGED} so that
 * CircleOS-aware launchers can hide the specified packages.</p>
 */
class AppVisibilityManager {

    private static final String TAG = "CirclePersonality";

    static final String ACTION_APP_VISIBILITY_CHANGED =
            "za.co.circleos.personality.APP_VISIBILITY_CHANGED";
    static final String EXTRA_MODE_ID       = "mode_id";
    static final String EXTRA_HIDDEN_PKGS   = "hidden_packages";

    private final Context           mContext;
    private final CustomModeStore   mStore;

    /** modeId → list of hidden package names */
    private final Map<String, List<String>> mRules = new ArrayMap<>();

    AppVisibilityManager(Context context, CustomModeStore store) {
        mContext = context;
        mStore   = store;
    }

    void init() {
        Map<String, List<String>> saved = mStore.loadAppRules();
        mRules.putAll(saved);
        Log.d(TAG, "AppVisibilityManager: loaded rules for " + mRules.size() + " modes");
    }

    void setHiddenApps(String modeId, List<String> packageNames) {
        if (packageNames == null || packageNames.isEmpty()) {
            mRules.remove(modeId);
        } else {
            mRules.put(modeId, new ArrayList<>(packageNames));
        }
        mStore.saveAppRules(mRules);
        Log.d(TAG, "AppVisibilityManager: set " + (packageNames == null ? 0 : packageNames.size())
                + " hidden apps for mode " + modeId);
    }

    List<String> getHiddenApps(String modeId) {
        List<String> list = mRules.get(modeId);
        return list != null ? new ArrayList<>(list) : Collections.emptyList();
    }

    /**
     * Broadcasts the visibility rules for the activated mode so launchers
     * can apply hide/show logic.
     */
    void applyForMode(String modeId) {
        List<String> hidden = getHiddenApps(modeId);
        Intent intent = new Intent(ACTION_APP_VISIBILITY_CHANGED);
        intent.putExtra(EXTRA_MODE_ID, modeId);
        intent.putStringArrayListExtra(EXTRA_HIDDEN_PKGS,
                new ArrayList<>(hidden));
        mContext.sendBroadcast(intent);
        Log.d(TAG, "AppVisibilityManager: broadcast for mode " + modeId
                + " (" + hidden.size() + " hidden)");
    }
}
