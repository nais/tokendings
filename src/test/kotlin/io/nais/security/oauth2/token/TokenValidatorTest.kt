package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.utils.jwkSet
import org.junit.jupiter.api.Test
import java.util.Date
import java.util.concurrent.TimeUnit

internal class TokenValidatorTest {
    private val jwkSet = jwkSet()
    private val rsaKey = jwkSet.keys.first() as RSAKey
    private val validator = TokenValidator(ISSUER, ImmutableJWKSet(jwkSet))
    private val beyondLeeway = TimeUnit.SECONDS.toMillis(validator.maxClockSkew().toLong()) + 1_000

    @Test
    fun `validate should succeed for valid token`() {
        val claims = validClaims().build().sign(rsaKey)
        val result = validator.validate(claims)
        result.issuer shouldBe ISSUER
        result.subject shouldBe null
    }

    @Test
    fun `validate should reject token with wrong issuer`() {
        val claims = validClaims().issuer("https://wrong.issuer").build().sign(rsaKey)
        val exception = shouldThrow<OAuth2Exception> { validator.validate(claims) }
        exception.errorObject?.code shouldBe OAuth2Error.INVALID_REQUEST.code
        exception.errorObject?.description shouldContain "iss"
    }

    @Test
    fun `validate should reject token with missing exp claim`() {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(ISSUER)
                .issueTime(Date())
                .build()
                .sign(rsaKey)
        val exception = shouldThrow<OAuth2Exception> { validator.validate(claims) }
        exception.errorObject?.code shouldBe OAuth2Error.INVALID_REQUEST.code
        exception.errorObject?.description shouldContain "exp"
    }

    @Test
    fun `validate should reject token with missing iat claim`() {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(ISSUER)
                .expirationTime(Date(System.currentTimeMillis() + beyondLeeway))
                .build()
                .sign(rsaKey)
        val exception = shouldThrow<OAuth2Exception> { validator.validate(claims) }
        exception.errorObject?.code shouldBe OAuth2Error.INVALID_REQUEST.code
        exception.errorObject?.description shouldContain "iat"
    }

    @Test
    fun `validate should reject expired token`() {
        val past = Date(System.currentTimeMillis() - beyondLeeway)
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(ISSUER)
                .issueTime(past)
                .expirationTime(past)
                .build()
                .sign(rsaKey)
        val exception = shouldThrow<OAuth2Exception> { validator.validate(claims) }
        exception.errorObject?.code shouldBe OAuth2Error.INVALID_REQUEST.code
        exception.errorObject?.description shouldContain "Expired+JWT"
    }

    private fun validClaims(): JWTClaimsSet.Builder =
        JWTClaimsSet
            .Builder()
            .issuer(ISSUER)
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + beyondLeeway))

    companion object {
        private const val ISSUER = "https://test.issuer"
    }
}
