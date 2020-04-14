package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.config.ServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.config.TokenIssuerProperties
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.token.JwtTokenProvider
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import no.nav.security.mock.oauth2.MockOAuth2Server
import java.time.Instant
import java.util.Date
import java.util.UUID

class MockClientRegistry(private val acceptedAudience: String) : ClientRegistry(
    ClientRegistryProperties(acceptedAudience)
) {
    fun registerClientAndGenerateKeys(clientId: String, accessPolicy: AccessPolicy): OAuth2Client =
        registerClient(
            OAuth2Client(
                clientId,
                generateJWKSet(clientId, 2048),
                accessPolicy
            )
        )

    fun generateClientAssertionFor(clientId: String): SignedJWT =
        findClient(clientId)?.let {
            JwtTokenProvider.createSignedJWT(
                JWTClaimsSet.Builder()
                    .issuer(it.clientId)
                    .subject(it.clientId)
                    .audience(acceptedAudience)
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtID(UUID.randomUUID().toString())
                    .build(),
                it.jwkSet.keys.first() as RSAKey
            )
        } ?: throw IllegalArgumentException("cannot generate assertion for unknown clientId=$clientId")
}

fun mockConfig(mockOAuth2Server: MockOAuth2Server): AppConfiguration {
    val tokenIssuerProperties = TokenIssuerProperties(
        issuerUrl = "http://localhost:8080",
        subjectTokenIssuers = listOf(
            SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("mock1").toString()),
            SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("mock2").toString())
        )
    )
    val clientRegistry = MockClientRegistry(tokenIssuerProperties.tokenEndpointUrl())
    return AppConfiguration(ServerProperties(8080), clientRegistry, tokenIssuerProperties)
}

fun <R> withMockOAuth2Server(
    test: MockOAuth2Server.() -> R
): R {
    val server = MockOAuth2Server()
    server.start()
    try {
        return server.test()
    } finally {
        server.shutdown()
    }
}
