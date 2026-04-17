package io.nais.security.oauth2.authentication

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.Date

internal class FederatedClientAssertionJwtClaimsVerifierTest {
    private val expectedAudience = "tokendings"
    private val maxLifetimeSeconds = 600L
    private val verifier =
        FederatedClientAssertionJwtClaimsVerifier<com.nimbusds.jose.proc.SecurityContext?>(
            expectedAudience = expectedAudience,
            maxLifetimeSeconds = maxLifetimeSeconds,
        )

    private fun validClaims(mutate: JWTClaimsSet.Builder.() -> Unit = {}): JWTClaimsSet {
        val now = Date()
        return JWTClaimsSet
            .Builder()
            .issuer("https://kubernetes.default.svc")
            .subject("system:serviceaccount:team:app")
            .audience(listOf(expectedAudience, "https://kubernetes.default.svc"))
            .issueTime(now)
            .expirationTime(Date(now.time + 60_000))
            .also(mutate)
            .build()
    }

    @Test
    fun `accepts assertion with required claims and matching audience contained in aud`() {
        verifier.verify(validClaims(), null)
    }

    @Test
    fun `does not require jti or nbf`() {
        val claims = validClaims()
        assertThat(claims.jwtid).isNull()
        assertThat(claims.notBeforeTime).isNull()
        verifier.verify(claims, null)
    }

    @Test
    fun `rejects when expected audience is not contained in aud`() {
        val claims = validClaims { audience(listOf("someone-else")) }
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
            .hasMessageContaining("does not contain expected value")
    }

    @Test
    fun `rejects when sub is blank`() {
        val claims = validClaims { subject("") }
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
    }

    @Test
    fun `rejects when iss is missing`() {
        val now = Date()
        val claims =
            JWTClaimsSet
                .Builder()
                .subject("system:serviceaccount:team:app")
                .audience(listOf(expectedAudience))
                .issueTime(now)
                .expirationTime(Date(now.time + 60_000))
                .build()
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
    }

    @Test
    fun `rejects when iat is missing`() {
        val now = Date()
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer("https://kubernetes.default.svc")
                .subject("system:serviceaccount:team:app")
                .audience(listOf(expectedAudience))
                .expirationTime(Date(now.time + 60_000))
                .build()
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
    }

    @Test
    fun `rejects when exp is missing`() {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer("https://kubernetes.default.svc")
                .subject("system:serviceaccount:team:app")
                .audience(listOf(expectedAudience))
                .issueTime(Date())
                .build()
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
    }

    @Test
    fun `rejects when remaining lifetime exceeds max`() {
        val now = Date()
        val claims =
            validClaims {
                issueTime(now)
                expirationTime(Date(now.time + (maxLifetimeSeconds + 60) * 1000))
            }
        assertThatThrownBy { verifier.verify(claims, null) }
            .isInstanceOf(BadJWTException::class.java)
            .hasMessageContaining("exceeded max lifetime")
    }

    @Test
    fun `accepts when remaining lifetime equals max`() {
        val now = Date()
        val claims =
            validClaims {
                issueTime(now)
                expirationTime(Date(now.time + maxLifetimeSeconds * 1000))
            }
        verifier.verify(claims, null)
    }
}
