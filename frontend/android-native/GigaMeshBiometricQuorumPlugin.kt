// GigaMesh Hardware-Backed Biometric Quorum Signing Plugin for Android (Capacitor)
// Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
//
// Signs high-impact factory Sparkplug B DCMD & cloud HITL Quorum approvals using an Android
// Keystore / StrongBox hardware-backed ECDSA key gated by fingerprint / face BiometricPrompt.

package io.quanumis.gigamesh.biometric

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

class GigaMeshBiometricQuorumSigner(
    private val keyAlias: String = "gigamesh_quorum_hw_key_v1"
) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun ensureHardwareKey(requireStrongBox: Boolean = false) {
        if (keyStore.containsAlias(keyAlias)) return
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        if (requireStrongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    /** Creates an initialized Signature object to pass into BiometricPrompt.CryptoObject. */
    fun prepareBiometricSignature(): Signature {
        ensureHardwareKey()
        val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        return Signature.getInstance("SHA256withECDSA").apply {
            initSign(entry.privateKey)
        }
    }

    /** Completes hardware signature after BiometricPrompt succeeds; returns Base64 DER signature. */
    fun finalizeSignedApproval(unlockedSig: Signature, canonicalQuorumPayload: String): String {
        unlockedSig.update(canonicalQuorumPayload.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(unlockedSig.sign(), Base64.NO_WRAP)
    }

    fun exportPublicKeyPem(): String {
        ensureHardwareKey()
        val cert = keyStore.getCertificate(keyAlias)
        val b64 = Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
        return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----"
    }
}
