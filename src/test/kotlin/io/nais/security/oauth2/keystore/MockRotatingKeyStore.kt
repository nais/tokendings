package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.SecurityContext
import java.time.Duration

class MockRotatingKeyStore(private val rotationInterval: Duration = Duration.ofDays(1)): RotatingKeyStore {
    private var keys = RotatableKeys.generate(expiresIn = rotationInterval)

    override fun currentSigningKey() = getAndRotateKeysIfExpired().currentKey

    override fun publicJWKSet() = JWKSet(listOf(keys.currentKey, keys.previousKey)).toPublicJWKSet()

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?) = publicJWKSet().keys

    private fun getAndRotateKeysIfExpired(): RotatableKeys {
        if (keys.expired()) keys = RotatableKeys.generate(expiresIn = rotationInterval)
        return keys
    }
}
