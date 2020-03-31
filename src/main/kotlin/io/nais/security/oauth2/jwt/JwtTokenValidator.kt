package io.nais.security.oauth2.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.oauth2.sdk.id.Issuer
import java.util.HashSet

class JwtTokenValidator {
    // TODO validate against trusted issuers
    fun validate(token: String): JWTClaimsSet {
        return SignedJWT.parse(token).jwtClaimsSet
    }
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun verifyJwt(jwt: String, issuer: Issuer, audience: String, jwkSet: JWKSet): JWTClaimsSet {
    return verifyJwt(
        SignedJWT.parse(jwt),
        DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder()
                .issuer(issuer.toString())
                .audience(audience)
                .build(),
            HashSet(listOf("sub", "iss", "iat", "exp", "aud")
            )
        ),
        jwkSet
    )
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun verifyJwt(signedJwt: SignedJWT, jwtClaimsSetVerifier: JWTClaimsSetVerifier<SecurityContext?>, jwkSet: JWKSet): JWTClaimsSet {
    val jwtProcessor: ConfigurableJWTProcessor<SecurityContext?> = DefaultJWTProcessor()
    val keySelector: JWSKeySelector<SecurityContext?> = JWSVerificationKeySelector(
        JWSAlgorithm.RS256,
        ImmutableJWKSet(jwkSet)
    )
    jwtProcessor.jwsKeySelector = keySelector
    jwtProcessor.jwtClaimsSetVerifier = jwtClaimsSetVerifier
    return jwtProcessor.process(signedJwt, null)
}
