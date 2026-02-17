# CircleOS — frameworks/base patches

These files are applied on top of **AOSP android-14.0.0_r50**
(`platform/frameworks/base` tag `android-14.0.0_r50`).

## What's here

| Path | Purpose |
|------|---------|
| `core/java/android/circleos/` | AIDL interfaces + Parcelables for the privacy framework |
| `core/res/AndroidManifest.xml` | Circle OS permission declarations |
| `services/core/java/com/circleos/server/privacy/` | Privacy service implementations |
| `services/java/com/android/server/SystemServer.java` | Service registration hooks |

## Applying to your AOSP tree

```bash
repo init -u https://android.googlesource.com/platform/manifest -b android-14.0.0_r50
repo sync -j$(nproc)
# Copy Circle files into your tree, then build
```

## Do not open issues or PRs on this repo.
Changes are made internally. This repository is read-only for external viewers.
