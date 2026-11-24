#!/usr/bin/env bash
# GigaMesh Production Android Release Builder (Capacitor + Kotlin VPN Shield + StrongBox Biometrics)
# Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/frontend"

echo "[1/4] Building production PWA web bundle..."
npm ci
npm run build

echo "[2/4] Syncing Capacitor Android project..."
if [ ! -d "android" ]; then
  npx cap add android
fi
npx cap sync android

echo "[3/4] Copying GigaMesh native Kotlin VPN Shield, Biometric Quorum & hardened Manifest..."
KOTLIN_DIR="android/app/src/main/java/com/quanumis/gigamesh"
mkdir -p "$KOTLIN_DIR"
cp android-native/GigaMeshVpnShieldService.kt "$KOTLIN_DIR/"
cp android-native/GigaMeshBiometricQuorumPlugin.kt "$KOTLIN_DIR/"
cp android-native/AndroidManifest.xml android/app/src/main/AndroidManifest.xml

echo "[4/4] Building signed Android App Bundle (.aab)..."
cd android
./gradlew bundleRelease
echo "SUCCESS: Release bundle at frontend/android/app/build/outputs/bundle/release/app-release.aab"
