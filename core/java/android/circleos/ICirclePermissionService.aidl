/*
 * Copyright (C) 2024 CircleOS
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * AIDL interface for Circle OS custom permission management.
 * Service name: "circle.permission"
 */
package android.circleos;

/**
 * Binder interface for CirclePermissionService.
 *
 * Manages Circle-specific permissions not present in AOSP:
 *   com.circleos.permission.NETWORK
 *   com.circleos.permission.ACCELEROMETER
 *   com.circleos.permission.GYROSCOPE
 *   com.circleos.permission.BAROMETER
 *   com.circleos.permission.MAGNETOMETER
 */
interface ICirclePermissionService {

    /** Returns true if the package holds NETWORK permission. */
    boolean checkNetworkPermission(String packageName);

    /** Grants NETWORK permission to the package and adds UID to netd ACCEPT chain. */
    void grantNetworkPermission(String packageName);

    /** Revokes NETWORK permission and removes UID from netd ACCEPT chain. */
    void revokeNetworkPermission(String packageName);

    /**
     * Returns true if the package holds the given sensor permission.
     * {@code sensorType} is one of: ACCELEROMETER, GYROSCOPE, BAROMETER, MAGNETOMETER.
     */
    boolean checkSensorPermission(String packageName, String sensorType);

    /** Returns all packages currently holding NETWORK permission. */
    List<String> getPackagesWithNetworkPermission();
}
