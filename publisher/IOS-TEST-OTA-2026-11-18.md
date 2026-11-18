# OTA-enabled ad-hoc test iPhone

The owner explicitly requested a test iPhone version able to receive subsequent OTA updates, preserving Google sign-in and the existing carnet. The signed native app is DRASC Test 0.1.74 (18), `app.drasc.mobile.test71`, with its distinct Google callback. It uses the same existing OTA verification key and rollback controls. See `ios-test-native-validation.json` for exact native compile, signature, source and artifact evidence. Installation and real OTA activation remain to be confirmed on the physical iPhone.

The existing Android Play and personal iPhone runtimes remain unchanged. The additional iPhone runtime `f061262a434936aa0ba1e059e55c0799a15955e39cfdaa09ca337bf6ebd94d2c` is explicitly allowed alongside the original iPhone runtime. Unknown, malformed and wildcard profiles remain rejected. Bootstrap is allowed only for that exact absent iPhone channel with the explicitly approved zero previous checksum. Existing-channel signature, checksum and version checks are retained.

No key, credentials, hardware identifier, provisioning profile or user data is added. The ad-hoc IPA stays outside this public repository. Signing remains exclusively on the protected `release-control` branch and `production-signing` environment. The first web OTA is a separately reviewed 0.1.75 candidate; this native validation does not itself publish any web bundle.
