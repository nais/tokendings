package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.model.ConfigurableJWKSetCache
import java.net.URL
import java.util.concurrent.TimeUnit

// TODO remove blocking calls from i.e. RemoteJWKSet
class TokenValidator(
    private val issuer: String,
    jwkSource: JWKSource<SecurityContext?>
) {

    constructor(issuer: String, jwkSetUri: URL, configCache: ConfigurableJWKSetCache) : this(
        issuer, RemoteJWKSet(
            jwkSetUri,
            DefaultResourceRetriever(),
            DefaultJWKSetCache(
                configCache.lifeSpan,
                configCache.refreshTime,
                TimeUnit.SECONDS
            )
        )
    )

    constructor(issuer: String, jwkSet: JWKSet) : this(issuer, ImmutableJWKSet(jwkSet))

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    fun validate(token: SignedJWT): JWTClaimsSet {
        return token.verify(issuer, keySelector)
    }
}
