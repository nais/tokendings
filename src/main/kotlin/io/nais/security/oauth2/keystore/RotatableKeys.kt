package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.utils.generateRsaKey
import java.time.Duration
import java.time.LocalDateTime

data class RotatableKeys(
    val currentKey: RSAKey,
    val previousKey: RSAKey,
    val nextKey: RSAKey,
    val expiry: LocalDateTime
) {
    fun rotate(expiresIn: Duration): RotatableKeys {
        val newKey = generateRsaKey()
        return RotatableKeys(
            previousKey = this.currentKey,
            currentKey = this.nextKey,
            nextKey = newKey,
            expiry = LocalDateTime.now().plus(expiresIn)
        )
    }

    fun expired(now: LocalDateTime = LocalDateTime.now()) = now.isAfter(this.expiry)

    fun notExpired(now: LocalDateTime = LocalDateTime.now()) = !expired(now)

    companion object {
        fun generate(expiresIn: Duration): RotatableKeys = RotatableKeys(
            currentKey = generateRsaKey(),
            previousKey = generateRsaKey(),
            nextKey = generateRsaKey(),
            expiry = LocalDateTime.now().plus(expiresIn)
        )
    }
}
