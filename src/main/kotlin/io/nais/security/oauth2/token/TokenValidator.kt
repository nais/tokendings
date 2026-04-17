package io.nais.security.oauth2.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import io.nais.security.oauth2.model.CacheProperties
import io.opentelemetry.instrumentation.annotations.WithSpan

/**
 * Validates [SignedJWT]s against a (possibly cached and stale-tolerant) [JWKSource].
 *
 * By default enforces the baseline shared by all tokendings-validated tokens:
 * signature via RS256, `iss` equals [issuer], and required claims `sub, iss, iat, exp`.
 *
 * [extraClaimsVerifier] layers additional claim policy on top (e.g. audience check
 * for federated client assertions). Its verification runs *after* the baseline in
 * the same JWT-processor pass — both must pass.
 */
class TokenValidator(
    issuer: String,
    jwkSource: JWKSource<SecurityContext>,
    extraClaimsVerifier: JWTClaimsSetVerifier<SecurityContext?>? = null,
) {
    constructor(
        issuer: String,
        cacheProperties: CacheProperties,
        extraClaimsVerifier: JWTClaimsSetVerifier<SecurityContext?>? = null,
    ) : this(
        issuer,
        cacheProperties.jwkSource,
        extraClaimsVerifier,
    )

    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)
    private val claimsVerifier: JWTClaimsSetVerifier<SecurityContext?> = buildClaimsVerifier(issuer, extraClaimsVerifier)

    @WithSpan
    fun validate(token: SignedJWT): JWTClaimsSet = token.verify(claimsVerifier, keySelector)

    private companion object {
        private fun buildClaimsVerifier(
            issuer: String,
            extra: JWTClaimsSetVerifier<SecurityContext?>?,
        ): JWTClaimsSetVerifier<SecurityContext?> {
            val baseline =
                DefaultJWTClaimsVerifier<SecurityContext?>(
                    JWTClaimsSet
                        .Builder()
                        .issuer(issuer)
                        .build(),
                    setOf("sub", "iss", "iat", "exp"),
                )
            return if (extra == null) {
                baseline
            } else {
                JWTClaimsSetVerifier { claims, ctx ->
                    baseline.verify(claims, ctx)
                    extra.verify(claims, ctx)
                }
            }
        }
    }
}
