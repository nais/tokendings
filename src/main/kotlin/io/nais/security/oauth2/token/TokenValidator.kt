package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.model.JwkSetCacheProperties
import java.net.URL

// TODO remove blocking calls from i.e. RemoteJWKSet
class TokenValidator(
    private val issuer: String,
    jwkSource: JWKSource<SecurityContext?>
) {

    constructor(issuer: String, jwkSetUri: URL, configCacheProperties: JwkSetCacheProperties) : this(
        issuer,
        RemoteJWKSet(
            jwkSetUri,
            configCacheProperties.getConfigurableResourceRetriever,
            configCacheProperties.getConfigurableJWKSetCache
        )
    )

    constructor(issuer: String, jwkSet: JWKSet) : this(issuer, ImmutableJWKSet(jwkSet))

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    fun validate(token: SignedJWT): JWTClaimsSet {
        return token.verify(issuer, keySelector)
    }
}
