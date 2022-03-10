package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.model.CacheProperties
import java.net.URL

class TokenValidator(private val issuer: String, jwkSource: JWKSource<SecurityContext?>) {

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    constructor(issuer: String, cacheProperties: CacheProperties) : this(
        issuer,
        RemoteJWKSet(
            URL(cacheProperties.jwksUrl),
            cacheProperties.configurableFailOver,
            cacheProperties.configurableResourceRetriever,
            cacheProperties.configurableJWKSetCache
        )
    )

    fun validate(token: SignedJWT): JWTClaimsSet {
        return token.verify(issuer, keySelector)
    }
}
