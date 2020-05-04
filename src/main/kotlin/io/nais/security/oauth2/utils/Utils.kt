package io.nais.security.oauth2.utils

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.prometheus.client.Histogram
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

typealias KeyId = String
typealias KeySize = Int

fun generateRsaKey(keyId: KeyId = UUID.randomUUID().toString(), keySize: KeySize = 2048): RSAKey =
    KeyPairGenerator.getInstance("RSA").apply { initialize(keySize) }.generateKeyPair()
        .let {
            RSAKey.Builder(it.public as RSAPublicKey)
                .privateKey(it.private as RSAPrivateKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .build()
        }

fun generateAESKey(): SecretKey =
    KeyGenerator.getInstance("AES")
        .apply {
            this.init(128)
        }.generateKey()

fun String.encrypt(key: SecretKey): String =
    JWEObject(
        JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM),
        Payload(this)
    ).also {
        it.encrypt(DirectEncrypter(key))
    }.serialize()

fun String.decrypt(key: SecretKey): String =
    JWEObject.parse(this).also {
        it.decrypt(DirectDecrypter(key))
    }.payload.toString()

inline fun <reified R : Any?> withTimer(timer: Histogram.Child, block: () -> R): R {
    val t = timer.startTimer()
    try {
        return block()
    } finally {
        t.observeDuration()
    }
}
