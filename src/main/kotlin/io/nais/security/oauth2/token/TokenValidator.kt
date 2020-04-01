package io.nais.security.oauth2.token

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import java.net.URL
import java.util.HashSet

class TokenValidator(private val issuer: String, jwkSource: JWKSource<SecurityContext?>) {

    constructor(issuer: String, jwkSetUri: URL) : this(issuer, RemoteJWKSet(jwkSetUri))
    constructor(issuer: String, jwkSet: JWKSet) : this(issuer, ImmutableJWKSet(jwkSet))
    private val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

    fun validate(token: SignedJWT): JWTClaimsSet {
        return verifyJwt(token, issuer, keySelector)
    }
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun verifyJwt(signedJwt: SignedJWT, issuer: String, keySelector: JWSVerificationKeySelector<SecurityContext?>): JWTClaimsSet {
    return verifyJwt(
        signedJwt,
        DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder()
                .issuer(issuer)
                .build(),
            HashSet(
                listOf("sub", "iss", "iat", "exp", "aud")
            )
        ),
        keySelector
    )
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun verifyJwt(signedJwt: SignedJWT, jwtClaimsSetVerifier: JWTClaimsSetVerifier<SecurityContext?>, jwkSet: JWKSet): JWTClaimsSet {
    return verifyJwt(
        signedJwt,
        jwtClaimsSetVerifier,
        JWSVerificationKeySelector(
            JWSAlgorithm.RS256,
            ImmutableJWKSet(jwkSet)
        )
    )
}

@Throws(BadJOSEException::class, JOSEException::class, BadJWTException::class)
fun verifyJwt(signedJwt: SignedJWT, jwtClaimsSetVerifier: JWTClaimsSetVerifier<SecurityContext?>, keySelector: JWSVerificationKeySelector<SecurityContext?>):
    JWTClaimsSet {
    val jwtProcessor: ConfigurableJWTProcessor<SecurityContext?> = DefaultJWTProcessor()
    jwtProcessor.jwsKeySelector = keySelector
    jwtProcessor.jwtClaimsSetVerifier = jwtClaimsSetVerifier
    return jwtProcessor.process(signedJwt, null)
}
