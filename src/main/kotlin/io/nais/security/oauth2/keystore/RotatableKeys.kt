package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.utils.generateRsaKey
import java.time.LocalDateTime

data class RotatableKeys(
    val currentKey: RSAKey,
    val previousKey: RSAKey,
    val nextKey: RSAKey,
    val expiry: LocalDateTime
) {
    fun rotate(expiry: LocalDateTime): RotatableKeys {
        val newKey = generateRsaKey()
        return RotatableKeys(
            previousKey = this.currentKey,
            currentKey = this.nextKey,
            nextKey = newKey,
            expiry = expiry
        )
    }

    fun expired(now: LocalDateTime = LocalDateTime.now()) = now.isAfter(this.expiry)
}
