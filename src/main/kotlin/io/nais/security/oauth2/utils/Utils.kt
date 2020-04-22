package io.nais.security.oauth2.utils

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import io.prometheus.client.Histogram
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

inline fun <reified R : Any?> withTimer(timer: Histogram.Child, block: () -> R): R {
    val t = timer.startTimer()
    try {
        return block()
    } finally {
        t.observeDuration()
    }
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
