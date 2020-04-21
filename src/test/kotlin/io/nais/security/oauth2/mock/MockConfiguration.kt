package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.zaxxer.hikari.HikariDataSource
import io.ktor.application.Application
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.config.ServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.config.clean
import io.nais.security.oauth2.config.migrate
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.token.JwtTokenProvider
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import io.nais.security.oauth2.tokenExchangeApp
import no.nav.security.mock.oauth2.MockOAuth2Server
import org.testcontainers.containers.PostgreSQLContainer
import java.net.URL
import java.time.Instant
import java.util.Date
import java.util.UUID

// TODO do not init database for every test
fun mockConfig(mockOAuth2Server: MockOAuth2Server? = null): AppConfiguration {
    val issuerUrl = "http://localhost:8080"
    val tokenIssuerProperties = AuthorizationServerProperties(
        issuerUrl = issuerUrl,
        subjectTokenIssuers = mockOAuth2Server?.let {
            listOf(SubjectTokenIssuer(it.wellKnownUrl("mock1").toString()))
        } ?: emptyList()
    )
    val clientRegistry = MockClientRegistry(tokenIssuerProperties.tokenEndpointUrl())
    return AppConfiguration(ServerProperties(8080), clientRegistry, tokenIssuerProperties)
}

fun MockApp(
    config: AppConfiguration = mockConfig()
): Application.() -> Unit {
    return fun Application.() {
        tokenExchangeApp(config, DefaultRouting(config))
    }
}

data class AdminOAuth2Client(
    val clientId: ClientId,
    val jwkSet: JWKSet,
    val allowedScopes: List<String>
) {
    constructor(clientId: ClientId, jwksUrl: URL, allowedScopes: List<String>) :
        this(clientId, RemoteJWKSet<SecurityContext?>(jwksUrl).cachedJWKSet, allowedScopes)

    val allowedGrantTypes: List<String> = listOf(GrantType.CLIENT_CREDENTIALS_GRANT)
}

class MockClientRegistry(private val acceptedAudience: String) : ClientRegistry(
    ClientRegistryProperties(DataSource.instance.apply { clean(this) }.apply { migrate(this) })
) {

    fun registerClientAndGenerateKeys(
        clientId: String,
        accessPolicy: AccessPolicy = AccessPolicy(),
        allowedScopes: List<String> = emptyList(),
        allowedGrantTypes: List<String> = emptyList()
    ): OAuth2Client =
        registerClient(
            OAuth2Client(
                clientId,
                JsonWebKeys(generateJWKSet(clientId, 2048)),
                accessPolicy,
                accessPolicy,
                allowedScopes,
                allowedGrantTypes
            )
        )

    fun generateClientAssertionFor(clientId: String): SignedJWT =
        findClient(clientId)?.let {
            generateClientAssertion(
                clientId,
                acceptedAudience,
                it.jwkSet
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

// TODO bump version
internal object PostgresContainer {
    val instance by lazy {
        PostgreSQLContainer<Nothing>("postgres:11.2").apply {
            start()
        }
    }
}

internal object DataSource {
    val instance: HikariDataSource by lazy {
        HikariDataSource().apply {
            username = PostgresContainer.instance.username
            password = PostgresContainer.instance.password
            jdbcUrl = PostgresContainer.instance.jdbcUrl
            connectionTimeout = 1000L
        }
    }
}

internal fun withCleanDb(test: () -> Unit) = DataSource.instance.also { clean(it) }.run { test() }

internal fun withMigratedDb(test: () -> Unit) =
    DataSource.instance.also { clean(it) }.also { migrate(it) }.run { test() }
