package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import java.time.LocalDateTime

data class RsaKeys(
    var currentKey: RSAKey,
    var previousKey: RSAKey,
    var nextKey: RSAKey,
    var expiry: LocalDateTime
) {

    companion object {

        fun toKey(rsaKeys: RsaKeys) = rsaKeys

        private fun rotateKeys(rsaKeys: RsaKeys, newKey: RSAKey, expiry: LocalDateTime) = rsaKeys.apply {
            previousKey = currentKey
            currentKey = this.nextKey
            this.nextKey = newKey
            this.expiry = expiry
        }
    }

    fun rotate(newKey: RSAKey, expiry: LocalDateTime) = rotateKeys(this, newKey, expiry)

    fun toKey() = toKey(this)

    fun expired(now: LocalDateTime) = now.isAfter(this.expiry)
}
