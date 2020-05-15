package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey

interface KeyStore {
    fun publicJwks(): JWKSet
    fun signingKey(): RSAKey
}

class DefaultKeyStore(
    val jwkSet: JWKSet
) : KeyStore {
    override fun publicJwks(): JWKSet = jwkSet.toPublicJWKSet()
    override fun signingKey(): RSAKey = jwkSet.keys.first() as RSAKey
}
