package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.model.CacheProperties
import io.opentelemetry.instrumentation.annotations.WithSpan

class TokenValidator(
    private val issuer: String,
    jwkSource: JWKSource<SecurityContext>,
) {
    constructor(issuer: String, cacheProperties: CacheProperties) : this(
        issuer,
        cacheProperties.jwkSource,
    )

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    @WithSpan
    fun validate(token: SignedJWT): JWTClaimsSet = token.verify(issuer, keySelector)
}
