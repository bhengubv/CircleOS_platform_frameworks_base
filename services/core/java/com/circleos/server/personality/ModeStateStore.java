/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.personality;

import android.content.Context;
import android.provider.Settings;
import android.util.Log;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

/**
 * Persists the active personality mode and mode stack to Settings.Secure so that
 * it survives service restarts and reboots.
 */
class ModeStateStore {

    private static final String TAG = "CirclePersonality";

    /** Settings.Secure key for the currently active mode id. */
    private static final String KEY_ACTIVE_MODE = "circle_personality_mode";

    /** Settings.Secure key for the serialized mode stack (pipe-separated). */
    private static final String KEY_MODE_STACK = "circle_personality_mode_stack";

    /** Default mode applied when no saved state exists. */
    static final String DEFAULT_MODE = "daily";

    private final Context mContext;

    ModeStateStore(Context context) {
        mContext = context;
    }

    String loadActiveMode() {
        String saved = Settings.Secure.getString(
                mContext.getContentResolver(), KEY_ACTIVE_MODE);
        return (saved != null && !saved.isEmpty()) ? saved : DEFAULT_MODE;
    }

    void saveActiveMode(String modeId) {
        Settings.Secure.putString(
                mContext.getContentResolver(), KEY_ACTIVE_MODE, modeId);
    }

    Deque<String> loadModeStack() {
        String raw = Settings.Secure.getString(
                mContext.getContentResolver(), KEY_MODE_STACK);
        ArrayDeque<String> stack = new ArrayDeque<>();
        if (raw != null && !raw.isEmpty()) {
            for (String id : raw.split("\\|")) {
                if (!id.isEmpty()) stack.addLast(id);
            }
        }
        return stack;
    }

    void saveModeStack(Deque<String> stack) {
        StringBuilder sb = new StringBuilder();
        for (String id : stack) {
            if (sb.length() > 0) sb.append('|');
            sb.append(id);
        }
        Settings.Secure.putString(
                mContext.getContentResolver(), KEY_MODE_STACK, sb.toString());
    }
}
