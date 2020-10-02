package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.net.URL

class TokenValidator(private val issuer: String, jwkSource: JWKSource<SecurityContext?>) {

    constructor(issuer: String, jwkSetUri: URL) : this(issuer, RemoteJWKSet(jwkSetUri))

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    fun validate(token: SignedJWT): JWTClaimsSet {
        return token.verify(issuer, keySelector)
    }
}
