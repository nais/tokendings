package io.nais.security.oauth2.rsakeystore

import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.utils.generateRsaKey
import java.time.LocalDateTime

class RSAKeys(
    var currentKey: RSAKey? = null,
    var previousKey: RSAKey? = null,
    var nextKey: RSAKey? = null,
    var expiry: LocalDateTime? = null
) {

    companion object {

        fun toKey(rsaKeys: RSAKeys) = rsaKeys

        fun initKey(rsaKeys: RSAKeys, ttl: Long) = rsaKeys.apply {
            this.currentKey = generateRsaKey()
            this.previousKey = generateRsaKey()
            this.nextKey = generateRsaKey()
            this.expiry = LocalDateTime.now().plusSeconds(ttl)
        }

        private fun rotateKeys(rsaKeys: RSAKeys, newKey: RSAKey, expiry: LocalDateTime) = rsaKeys.apply {
            previousKey = currentKey
            currentKey = this.nextKey
            this.nextKey = newKey
            this.expiry = expiry
        }
    }

    fun rotate(newKey: RSAKey, expiry: LocalDateTime) = rotateKeys(this, newKey, expiry)

    fun initKeys(ttl: Long) = initKey(this, ttl)

    fun toKey() = toKey(this)

    fun expired(now: LocalDateTime) = now.isAfter(this.expiry)
}
