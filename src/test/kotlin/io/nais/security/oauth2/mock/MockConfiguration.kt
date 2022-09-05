package io.nais.security.oauth2.mock

import com.auth0.jwk.JwkProvider
import com.zaxxer.hikari.HikariDataSource
import io.ktor.server.application.Application
import io.mockk.every
import io.mockk.mockk
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.config.ServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.config.clean
import io.nais.security.oauth2.config.migrate
import io.nais.security.oauth2.health.HealthCheck
import io.nais.security.oauth2.keystore.MockRotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.tokenExchangeApp
import io.nais.security.oauth2.utils.jwkSet
import no.nav.security.mock.oauth2.MockOAuth2Server
import org.testcontainers.containers.PostgreSQLContainer
import java.time.Duration

fun mockConfig(
    mockOAuth2Server: MockOAuth2Server? = null,
    clientRegistrationAuthProperties: ClientRegistrationAuthProperties? = null,
    failHealthCheck: Boolean = false
): AppConfiguration {
    val issuerUrl = "http://localhost:8080"
    val authorizationServerProperties = AuthorizationServerProperties(
        issuerUrl = issuerUrl,
        subjectTokenIssuers = mockOAuth2Server?.let {
            listOf(SubjectTokenIssuer(it.wellKnownUrl("mock1").toString()))
        } ?: emptyList(),
        rotatingKeyStore = rotatingKeyStore()
    )
    val clientRegAuthProperties = when {
        clientRegistrationAuthProperties != null -> clientRegistrationAuthProperties
        mockOAuth2Server != null -> ClientRegistrationAuthProperties(
            identityProviderWellKnownUrl = mockOAuth2Server.wellKnownUrl("aadmock").toString(),
            acceptedAudience = listOf("tokendings"),
            acceptedRoles = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
            softwareStatementJwks = jwkSet()
        )
        else -> mockBearerTokenAuthenticationProperties()
    }

    val clientRegistry = MockClientRegistry()
    val mockDatabaseHealthCheck = object : HealthCheck {
        override fun ping() = if (failHealthCheck) throw RuntimeException("oh noes") else "pong"
    }
    return AppConfiguration(
        ServerProperties(8080),
        clientRegistry,
        authorizationServerProperties,
        clientRegAuthProperties,
        mockDatabaseHealthCheck
    )
}

fun mockBearerTokenAuthenticationProperties(): ClientRegistrationAuthProperties =
    mockBearerTokenAuthenticationProperties(
        mockk<WellKnown>().also {
            every { it.jwksUri } returns "http://na"
            every { it.issuer } returns "http://na"
        },
        mockk()
    )

fun mockBearerTokenAuthenticationProperties(wellKnown: WellKnown, jwkProvider: JwkProvider): ClientRegistrationAuthProperties =
    mockk<ClientRegistrationAuthProperties>().also {
        every { it.issuer } returns wellKnown.issuer
        every { it.jwkProvider } returns jwkProvider
    }

fun rotatingKeyStore(): RotatingKeyStore = MockRotatingKeyStore()

fun rotatingKeyStore(rotationInterval: Duration): RotatingKeyStore = MockRotatingKeyStore(rotationInterval)

fun MockApp(
    config: AppConfiguration = mockConfig()
): Application.() -> Unit {
    return fun Application.() {
        tokenExchangeApp(config, DefaultRouting(config))
    }
}

class MockClientRegistry : ClientRegistry {
    private val clients: MutableMap<ClientId, OAuth2Client> = mutableMapOf()

    override fun findClient(clientId: ClientId): OAuth2Client? = clients[clientId]

    override fun registerClient(client: OAuth2Client) = client.apply { clients[clientId] = this }

    override fun findAll(): List<OAuth2Client> = clients.values.toList()

    override fun deleteClient(clientId: ClientId) = clients.remove(clientId)?.let { 1 } ?: 0

    fun register(clientId: ClientId, accessPolicy: AccessPolicy = AccessPolicy()) =
        OAuth2Client(
            clientId,
            JsonWebKeys(jwkSet()),
            accessPolicy,
            accessPolicy,
            emptyList(),
            emptyList()
        ).let { registerClient(it) }
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
