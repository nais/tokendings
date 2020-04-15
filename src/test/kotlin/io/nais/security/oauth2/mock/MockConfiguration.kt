package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.config.ServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.config.AuthorizationServerProperties
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
    fun registerClientAndGenerateKeys(
        clientId: String,
        accessPolicy: AccessPolicy = AccessPolicy(),
        allowedScopes: List<String> = emptyList()
    ): OAuth2Client =
        registerClient(
            OAuth2Client(
                clientId,
                generateJWKSet(clientId, 2048),
                accessPolicy,
                allowedScopes
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

fun generateClientAssertion(clientId: String, audience: String, jwkSet: JWKSet) =
    JwtTokenProvider.createSignedJWT(
        JWTClaimsSet.Builder()
            .issuer(clientId)
            .subject(clientId)
            .audience(audience)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
            .jwtID(UUID.randomUUID().toString())
            .build(),
        jwkSet.keys.first() as RSAKey
    )

fun mockConfig(mockOAuth2Server: MockOAuth2Server? = null): AppConfiguration {
    val tokenIssuerProperties = AuthorizationServerProperties(
        issuerUrl = "http://localhost:8080",
        subjectTokenIssuers = mockOAuth2Server?.let {
            listOf(SubjectTokenIssuer(it.wellKnownUrl("mock1").toString()))
        } ?: emptyList()
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
