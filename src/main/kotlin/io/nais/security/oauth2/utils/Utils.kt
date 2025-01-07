package io.nais.security.oauth2.utils

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.metrics.Metrics
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

typealias KeyId = String
typealias KeySize = Int

fun generateRsaKey(
    keyId: KeyId = UUID.randomUUID().toString(),
    keySize: KeySize = 2048,
): RSAKey =
    KeyPairGenerator
        .getInstance("RSA")
        .apply { initialize(keySize) }
        .generateKeyPair()
        .let {
            RSAKey
                .Builder(it.public as RSAPublicKey)
                .privateKey(it.private as RSAPrivateKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .build()
        }

inline fun <reified R : Any?> withTimer(
    timerLabel: String,
    block: () -> R,
): R {
    val timer = Metrics.dbTimer.labels(timerLabel).startTimer()
    try {
        return block()
    } finally {
        timer.observeDuration()
    }
}
