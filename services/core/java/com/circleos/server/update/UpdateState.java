/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.circleos.server.update;

/** Possible states for the CircleOS update pipeline. */
public final class UpdateState {
    public static final int IDLE             = 0;
    public static final int CHECKING         = 1;
    public static final int DOWNLOADING      = 2;
    public static final int READY_TO_INSTALL = 3;
    public static final int INSTALLING       = 4;
    public static final int FAILED           = 5;

    private UpdateState() {}

    public static String name(int state) {
        switch (state) {
            case IDLE:             return "IDLE";
            case CHECKING:        return "CHECKING";
            case DOWNLOADING:     return "DOWNLOADING";
            case READY_TO_INSTALL:return "READY_TO_INSTALL";
            case INSTALLING:      return "INSTALLING";
            case FAILED:          return "FAILED";
            default:              return "UNKNOWN(" + state + ")";
        }
    }
}
