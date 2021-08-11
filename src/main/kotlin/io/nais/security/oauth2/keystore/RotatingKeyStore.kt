package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext

interface RotatingKeyStore : JWKSource<SecurityContext?> {

    fun currentSigningKey(): RSAKey

    fun publicJWKSet(): JWKSet
}
