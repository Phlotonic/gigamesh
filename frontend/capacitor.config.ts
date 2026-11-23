// Capacitor Configuration for Native Android (Google Play .aab) & iOS Builds
// Copyright (C) 2026 Adam Dryden and Quanumis Systems.
// Setup: npm install @capacitor/core @capacitor/cli @capacitor/android && npx cap add android && npx cap sync

const config = {
  appId: 'io.quanumis.gigamesh',
  appName: 'GigaMesh',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
    cleartext: false,
  },
  android: {
    allowMixedContent: false,
    captureInput: true,
    webContentsDebuggingEnabled: false,
  },
  plugins: {
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert'],
    },
  },
};

export default config;
